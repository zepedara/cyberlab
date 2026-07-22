# 47 * Scenario: ransomware memory investigation -- LAB-LINUX

## Overview (plain language)
Imagine a workstation gets locked by ransomware and someone captures a snapshot of everything the computer was holding in its memory (RAM). This module teaches you how to open that snapshot and look inside it. RAM contains a treasure map: which programs were running, what web addresses they talked to, and even leftover text and keys. We use three tools together. Volatility 3 reads the raw memory file and lists processes, network connections, and injected code. YARA scans the same memory for known "signatures" of bad software. bulk_extractor sweeps through the memory blindly and pulls out useful bits like URLs, email addresses, and crypto artifacts. Together they help you reconstruct what the ransomware did, including how it evaded defenses and what recovery options were disabled.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | apt install volatility3 | Framework to extract processes, network, and injected code from a RAM capture |
| YARA | apt install yara | Pattern-matching engine to flag malware signatures inside memory or files |
| bulk_extractor | apt install bulk-extractor | Bulk scanner that carves URLs, emails, crypto artifacts, and other IOCs from raw data without a filesystem |

Notes on tool identity and provenance:
- Volatility 3 is the current Python 3 rewrite of the Volatility framework and uses the `vol` (or `vol.py`/`vol3`) entry point with a `plugins`-based invocation model (`vol -f <image> <os>.<plugin>`); see the official docs at https://volatility3.readthedocs.io/en/latest/ and the source at https://github.com/volatilityfoundation/volatility3.
- YARA is authored by VirusTotal; documentation and the rule language reference are at https://yara.readthedocs.io/ and source at https://github.com/VirusTotal/yara.
- bulk_extractor is Simson Garfinkel's stream-based feature/carving tool; source and manual are at https://github.com/simsong/bulk_extractor. Both Volatility and bulk_extractor ship on REMnux (https://docs.remnux.org/discover-the-tools/) and the SANS SIFT Workstation (https://www.sans.org/tools/sift-workstation/).

## Learning objectives
- Enumerate running processes and suspicious parent/child relationships in a memory image using Volatility 3, including detection of process hollowing and DKOM unlinking.
- Extract network connections and command-line arguments tied to a ransomware process, including residual socket structures and closed connections.
- Scan a memory image with a custom YARA rule and interpret hits, including per-process attribution using Volatility 3's `yarascan` plugin.
- Carve indicators of compromise (URLs, ransom-note strings, crypto keys, and registry artifacts) from RAM with bulk_extractor.
- Identify defense evasion techniques such as Volume Shadow Copy deletion, process injection, and log clearing by analyzing memory artifacts.

## Environment check
```bash
# Prove all three tools are installed on LAB-LINUX (SIFT/REMnux)
vol --info | head -n 3
yara --version
bulk_extractor -V
```
Expected output: Volatility 3 prints its plugin/OS-layer banner via `--info` (this flag lists available address spaces, plugins, and layers — see https://volatility3.readthedocs.io/en/latest/basics.html); `yara --version` prints a version like `4.x.x` (the `--version` flag is documented in the YARA command-line reference, https://yara.readthedocs.io/en/stable/commandline.html); and `bulk_extractor -V` prints a version string such as `bulk_extractor 2.0.x` (the `-V` capital-V flag prints version per the bulk_extractor usage/manual, https://github.com/simsong/bulk_extractor).

## Guided walkthrough
1. `vol -f memory.raw windows.info` — always run this first. It confirms the image is parseable and prints the OS build, kernel base (KDBG/DTB), and system time. WHY: Volatility 3 auto-detects the symbol/profile at runtime rather than requiring a manually chosen profile as in Volatility 2, so `windows.info` is your sanity check that the correct symbol table (PDB) was resolved before you trust any later plugin output. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.info
```bash
vol -f memory.raw windows.info
```
Expected: a key/value table showing `NTBuildLab` (e.g., `19041.1.amd64fre.vb_release.191206-1406`), kernel base address, DTB (Directory Table Base), and the capture's `SystemTime`. Nuance: if this fails or shows no symbols, the rest of the walkthrough will be unreliable — you likely need matching symbol files (https://volatility3.readthedocs.io/en/latest/symbol-tables.html). The `SystemTime` field is critical for correlating with network logs (e.g., Zeek `conn.log` timestamps).

2. `vol -f memory.raw windows.pslist` — walks the doubly-linked `EPROCESS` list to enumerate processes. WHY: it gives you PID/PPID, start time, and thread count so you can spot oddly-named binaries or unexpected parents. Nuance: `pslist` relies on the linked list and can be evaded by DKOM (Direct Kernel Object Manipulation) unlinking; cross-check with `windows.psscan` (pool-tag scanning) and `windows.pstree` (parent/child hierarchy) to catch hidden or terminated processes. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.pslist
```bash
vol -f memory.raw windows.pslist | grep -i -E "lock|crypt|ransom|encrypt|vssadmin|wmic|powershell|cmd"
```
Expected: one or more matching PIDs if a ransomware-like process is present. Nuance: absence of a match does NOT clear the host — legitimate names (e.g., `svchost.exe`) are common attacker cover, so also run `windows.pstree` to inspect lineage and `windows.psscan` to detect DKOM unlinking (https://attack.mitre.org/techniques/T1057/).

3. `vol -f memory.raw windows.cmdline` — reads each process's `PEB.ProcessParameters` to reveal the full command line. WHY: command-line arguments frequently expose the encryptor's target path, key material flags, or a launch from `%TEMP%`/`%APPDATA%`. Ransomware often uses `vssadmin delete shadows` or `wmic shadowcopy delete` to disable recovery (**T1490** Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/). Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.cmdline
```bash
vol -f memory.raw windows.cmdline | grep -i -E "vssadmin|wmic|shadowcopy|delete|/c|powershell.*-enc"
```
Expected: a table mapping PID to command line; ransomware often shows an executable launched from `%TEMP%` or `%APPDATA%`, or commands like `vssadmin delete shadows /all /quiet`. Nuance: a blank/`N/A` command line can itself be suspicious (process hollowing or a paged-out PEB). Attackers may also use **T1059.001 (PowerShell)** with encoded commands (`-enc` or `-e`), which are recoverable here (https://attack.mitre.org/techniques/T1059/001/).

4. `vol -f memory.raw windows.netscan` — pool-tag scans for `_TCP_ENDPOINT`/`_UDP_ENDPOINT` structures to recover current and recently-closed sockets. WHY: it links a foreign IP/port to the owning PID so you can attribute a C2 callback to a process. Nuance: `netscan` recovers residual (even closed) connection objects, so entries may outlive the live connection — correlate timestamps with the capture time from step 1. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.netscan
```bash
vol -f memory.raw windows.netscan | grep -E "ESTABLISHED|CLOSE_WAIT" | grep -v "127.0.0.1"
```
Expected: rows with foreign IPs such as 203.0.113.10 tied to a suspicious PID (203.0.113.0/24 is a RFC 5737 documentation range, safe to use as an example). Nuance: closed sockets may indicate **T1041 (Exfiltration Over C2 Channel)**, especially if the foreign IP is known-bad (https://attack.mitre.org/techniques/T1041/).

5. Scan the raw memory with a YARA rule for ransom-note strings and crypto artifacts. WHY: string/byte signatures confirm a family and pin the byte offsets where note templates or config live. The `-s` flag prints the matching strings and their offsets (see https://yara.readthedocs.io/en/stable/commandline.html). Nuance: scanning a flat memory dump matches physical offsets; to attribute a hit to a process, use Volatility 3's `windows.yarascan` plugin instead (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.yarascan). Example rule for crypto keys:
```bash
cat > crypto.yar <<'EOF'
rule ransom_crypto_key {
    meta:
        description = "Detects common ransomware symmetric key patterns"
    strings:
        $a = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 } // ABCDEFGHIJKLMNOP (example key)
        $b = "-----BEGIN PUBLIC KEY-----" wide ascii
    condition:
        any of them
}
EOF
yara -s crypto.yar memory.raw
```
Expected: rule name plus matched offsets/strings when the note text or key is found. Nuance: YARA rules can also detect **T1027 (Obfuscated Files or Information)** by matching encoded strings or packer signatures (https://attack.mitre.org/techniques/T1027/).

6. Carve indicators with bulk_extractor into an output directory. WHY: bulk_extractor runs feature-extraction scanners over the raw bytes without needing a filesystem or valid process structures, so it recovers IOCs even from unallocated/paged regions. It writes one feature file per scanner (e.g., `url.txt`, `email.txt`, `aes_keys.txt`) plus histograms — see the manual at https://github.com/simsong/bulk_extractor. Nuance: `-o` must name a directory that does not already exist, or bulk_extractor will refuse to overwrite it. Enable additional scanners for crypto artifacts:
```bash
bulk_extractor -E aes -E zip -o be_out memory.raw
cat be_out/url.txt | grep -i http | head
cat be_out/aes_keys.txt | head
```
Expected: a populated `be_out/` directory; `url.txt` and `email.txt` contain carved indicators (each line prefixed with the byte offset where the feature was found), and `aes_keys.txt` may contain symmetric keys used for encryption (**T1486** Data Encrypted for Impact, https://attack.mitre.org/techniques/T1486/).

7. Check for process injection artifacts using `windows.malfind`. WHY: ransomware often injects into legitimate processes (e.g., `svchost.exe`) to evade detection (**T1055** Process Injection, https://attack.mitre.org/techniques/T1055/). `malfind` detects private memory regions with `PAGE_EXECUTE_READWRITE` permissions, which are indicative of injected code. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind
```bash
vol -f memory.raw windows.malfind --dump
```
Expected: output showing processes with suspicious memory regions, including the start/end addresses and protection flags. Nuance: legitimate applications (e.g., JIT compilers) may also use RWX memory, so cross-check with `windows.dlllist` to confirm the absence of backing DLLs (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.dlllist).

8. Recover registry artifacts using `windows.registry.hivelist` and `windows.registry.printkey`. WHY: ransomware often modifies registry keys to disable recovery options or establish persistence (**T1112** Modify Registry, https://attack.mitre.org/techniques/T1112/). Plugin references: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.hivelist and https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.printkey
```bash
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "ControlSet001\Services\VSS"
```
Expected: `hivelist` shows the virtual addresses of registry hives; `printkey` reveals modifications to Volume Shadow Copy Service (VSS) settings, which may indicate **T1490** (Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/).

## Hands-on exercise
Investigate the sample memory image in this module's `exercise/` directory.

- **Sample type:** a small benign/inert raw memory-like blob (`exercise/memory.raw`) — it is NOT a real infected RAM capture and contains NO live malware; it is a plain file seeded with harmless ransom-note strings, a fake C2 URL, a simulated AES key, and registry-like artifacts so the tools produce realistic hits with zero risk.
- **Safe origin / generation:** the file is generated locally with the reproducible command below (no network egress). It only contains ASCII strings and random padding.

Reproducible generator (creates the exact benign sample):
```bash
mkdir -p exercise
{
  head -c 4096 /dev/zero
  printf 'YOUR FILES HAVE BEEN ENCRYPTED! Contact evilmail@example.com to recover.\n'
  printf 'Payment portal: http://203.0.113.10/pay\n'
  printf 'LOCKBIT_TEST_MARKER ransom.note.decrypt\n'
  printf 'AES_KEY: ABCDEFGHIJKLMNOP\n'
  printf 'REGISTRY: \Registry\Machine\System\ControlSet001\Services\VSS\Start = 0x4\n'
  head -c 4096 /dev/urandom
} > exercise/memory.raw
sha256sum exercise/memory.raw
```

Tasks:
1. Use `yara` with the rule below to confirm the ransom-note marker and crypto key.
2. Use `bulk_extractor` to carve the C2 URL, contact email, and AES key.
3. Use Volatility 3's `windows.yarascan` to attribute the ransom-note strings to a process (even though this is a flat dump, the plugin will still work for demonstration).

Provided YARA rule (`exercise/ransom.yar`):
```bash
cat > exercise/ransom.yar <<'EOF'
rule ransom_note_test
{
    meta:
        description = "Detects ransom note and crypto key markers"
    strings:
        $a = "HAVE BEEN ENCRYPTED"
        $b = "LOCKBIT_TEST_MARKER"
        $c = "AES_KEY: ABCDEFGHIJKLMNOP"
    condition:
        any of them
}
EOF
```
(Rule syntax — `strings:`/`condition:` sections and the `any of them` set operator — follows the YARA writing-rules reference: https://yara.readthedocs.io/en/stable/writingrules.html)

## SOC analyst perspective
A defender treats a captured memory image as ground truth when disk logs may be tampered. In an incident, you ingest network alerts from Security Onion (Suricata/Zeek) that flag a suspicious outbound connection to 203.0.113.10, then pivot to the endpoint's RAM capture.

Concrete detection logic and pivots:
- **Network pivot:** Suricata alerts surface in Security Onion's Alerts interface; pivot from an alert into the corresponding Zeek `conn.log` record to get the 4-tuple, duration, and byte counts (Zeek log reference: https://docs.zeek.org/en/master/logs/conn.html; Security Onion analyst workflow: https://docs.securityonion.net/en/2.4/). Filter Elastic on `destination.ip: 203.0.113.10` to find every host that beaconed to the same infrastructure — this maps to **T1071** (Application Layer Protocol, https://attack.mitre.org/techniques/T1071/) and, if the C2 uses web protocols, **T1071.001** (Web Protocols, https://attack.mitre.org/techniques/T1071/001/). For encrypted C2, look for **T1573.001 (Encrypted Channel: Symmetric Cryptography)** in Zeek's `ssl.log` (e.g., `ssl.log.cipher` fields indicating weak or unusual ciphers).
- **Endpoint corroboration:** Volatility 3's `windows.netscan` recovers the owning PID for that foreign IP, and `windows.cmdline` shows the launching path. A binary running from `%TEMP%`/`%APPDATA%` is consistent with **T1204** (User Execution) and staging in **T1074** (Data Staged); mass file rewrites map to **T1486** (Data Encrypted for Impact, https://attack.mitre.org/techniques/T1486/). Use `windows.handles` to check for open file handles to encrypted files or ransom notes (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.handles).
- **Family confirmation:** YARA hits on ransom-note strings (via `yara` on the flat dump, or `windows.yarascan` for per-process attribution) confirm the family. Feed the confirmed strings/hashes back into Security Onion as new Suricata rules (e.g., `alert http any any -> any any (msg:"Ransomware Note String"; content:"YOUR FILES HAVE BEEN ENCRYPTED"; sid:1000001;)`) or Elastic detections for retroactive hunting across `conn.log`/`http.log`/`dns.log`.
- **IOC building:** bulk_extractor's `url.txt`/`email.txt`/`aes_keys.txt` rapidly produce a carved indicator list to push into detection and threat-intel enrichment. For example, the AES key can be used to decrypt files if the ransomware uses symmetric encryption (**T1486**).
- **Defense evasion detection:** Use `windows.malfind` to detect process injection (**T1055**), and `windows.registry.printkey` to check for disabled recovery options (**T1490**). Monitor **Windows Event ID 104** (Event Log Cleared) for **T1070.001 (Indicator Removal: Clear Windows Event Logs)**, and **Sysmon Event ID 25** (Process Tampering) for **T1562.003 (Impair Defenses: Impair Command History Logging)** (https://attack.mitre.org/techniques/T1070/001/ and https://attack.mitre.org/techniques/T1562/003/).

Detection nuance: because ransomware often encrypts fast, the strongest early SOC signals are behavioral — spikes in `conn.log`/`dns.log` to unfamiliar destinations, shadow-copy deletion (**T1490**), and volume of file-modify events (e.g., **Sysmon Event ID 11** for file creation) — rather than a single AV hit. Correlate these with **Windows Event ID 4663** (File System Object Access) to detect mass encryption (https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663).

**Detection Engineering & Threat Hunting Pivots**
- **Process Injection Detection**: Monitor **Sysmon Event ID 8** (CreateRemoteThread) for threads created in a target process by a source process (e.g., `powershell.exe` injecting into `svchost.exe`). This detects **T1055** (Process Injection) and **T1055.001** (Dynamic-Link Library Injection). Correlate with **Sysmon Event ID 10** (ProcessAccess) to identify suspicious access patterns (e.g., `PROCESS_VM_WRITE` or `PROCESS_VM_OPERATION`). Use **Windows Event ID 4688** (Process Creation) to detect child processes of `explorer.exe` or `svchost.exe` with unusual command lines (e.g., `cmd.exe /c vssadmin delete shadows`). This maps to **T1059** (Command and Scripting Interpreter) and **T1490** (Inhibit System Recovery). (Sources: Microsoft Sysmon Documentation, MITRE ATT&CK T1055, T1055.001, T1059, T1490)
- **Network-Based Detection**: Hunt for **T1071.001 (Web Protocols)** in **Zeek’s `http.log`** by filtering for unusual `user_agent` strings (e.g., `curl` or custom agents) or POST requests to `/pay` or `/api` endpoints. Pair this with **Suricata alerts** for known ransomware C2 IPs (e.g., `alert http any any -> $HOME_NET any (msg:"Ransomware C2 Beacon"; content:"/pay"; sid:1000002;)`). Detect **T1573.001 (Encrypted Channel: Symmetric Cryptography)** by analyzing **Zeek’s `ssl.log`** for unusual cipher suites (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`) or self-signed certificates. Use **Elasticsearch** to filter on `ssl.cipher: "TLS_RSA_WITH_AES_128_CBC_SHA"` and correlate with `destination.ip` from `conn.log`. (Sources: Zeek Log Reference, Suricata Rule Writing Guide, MITRE ATT&CK T1071.001, T1573.001)
- **Registry and File System Detection**: Hunt for **T1112 (Modify Registry)** by querying **Windows Event ID 4657** (Registry Value Modified) for changes to `HKLM\System\CurrentControlSet\Services\VSS\Start` (value `0x4` disables VSS). This detects **T1490** (Inhibit System Recovery). Monitor **Sysmon Event ID 11** (FileCreate) for ransom notes (e.g., `*_HOW_TO_DECRYPT.txt`) or encrypted files (e.g., `*.locked`). Correlate with **Windows Event ID 4663** (File System Object Access) to detect mass encryption. (Sources: Microsoft Windows Event Log Documentation, MITRE ATT&CK T1112, T1490)
- **Defense Evasion Detection**: Detect **T1070.001 (Clear Windows Event Logs)** by monitoring **Windows Event ID 1102** (Event Log Cleared). Correlate with **Sysmon Event ID 25** (ProcessTampering) to identify processes tampering with event logs. Hunt for **T1562.001 (Impair Defenses: Disable or Modify Tools)** by querying **Windows Event ID 4688** for processes launching `sc stop WinDefend` or `net stop wscsvc` (disabling Windows Defender or Security Center). (Sources: Microsoft Windows Event Log Documentation, MITRE ATT&CK T1070.001, T1562.001)
- **Threat-Hunting Pivots**: Pivot from `conn.log` to `dns.log` to identify DGA (Domain Generation Algorithm) patterns in `query` fields (e.g., `^[a-z0-9]{10}\.com$`). This maps to **T1568.002 (Dynamic Resolution: Domain Generation Algorithms)**. Use `http.log` to hunt for unusual `uri` paths (e.g., `/c2` or `/api/key`) or `user_agent` strings (e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64) EvilRansomware/1.0`). Create a dashboard to correlate `process.command_line` (from Sysmon Event ID 1) with `destination.ip` (from Zeek `conn.log`) to identify processes beaconing to known-bad IPs. Hunt for **T1059.001 (PowerShell)** by filtering on `process.name: "powershell.exe"` and `process.command_line: "*-enc*"` or `"*[Convert]::FromBase64String*"`. (Sources: Zeek Log Reference, Elastic Security Labs: Detecting Ransomware with Sysmon, MITRE ATT&CK T1568.002, T1059.001)

**Advanced Detection: Lateral Movement & Persistence**
- **Lateral Movement Detection**: Hunt for **T1570 (Lateral Tool Transfer)** by correlating **Zeek’s `smb_mapping.log`** for SMB file transfers with **Windows Event ID 4624** (Account Logon) for successful logons from the same source IP. Look for `smb_mapping.log.action` values like `SMB::FILE_OPEN` or `SMB::FILE_WRITE` to a network share, followed by **Windows Event ID 4688** (Process Creation) on the target host. This indicates the ransomware binary was transferred and executed laterally. (Sources: Zeek SMB Log Reference, Microsoft Event ID 4624, MITRE ATT&CK T1570)
- **Persistence Detection**: Hunt for **T1547.001 (Registry Run Keys)** by querying **Windows Event ID 4657** (Registry Value Modified) for changes to `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` or `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Ransomware often adds entries to maintain persistence after reboot. Correlate with **Sysmon Event ID 13** (RegistryEvent) for `SetValue` operations on these keys. (Sources: Microsoft Event ID 4657, Sysmon Event ID 13, MITRE ATT&CK T1547.001)

## Attacker perspective
An attacker deploying ransomware runs an encryptor from a temporary path, often injecting into or spawning from a legitimate process to blend in (**T1055** Process Injection, https://attack.mitre.org/techniques/T1055/; **T1036** Masquerading, https://attack.mitre.org/techniques/T1036/). They contact a C2 or payment portal and drop a ransom note file across directories (**T1486**, https://attack.mitre.org/techniques/T1486/). To evade detection, they may also use **T1027 (Obfuscated Files or Information)** to pack payloads or encode commands.

Concrete TTPs and the artifacts they leave in RAM:
- **Defense evasion / anti-recovery:** deleting Volume Shadow Copies via `vssadmin delete shadows` or `wmic shadowcopy delete` (**T1490** Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/). Even after the process exits, its command line and image path may persist in `EPROCESS`/PEB structures recoverable by `windows.psscan` and `windows.cmdline`. Registry modifications to disable VSS (e.g., `HKLM\System\CurrentControlSet\Services\VSS\Start = 4`) are recoverable via `windows.registry.printkey`.
- **Process injection / hollowing:** RWX private memory regions and unbacked executable pages in the VAD tree are recoverable with `windows.malfind` (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind), which surfaces injected code that never touched disk. Attackers may use **T1055.001 (Dynamic-Link Library Injection)** or **T1055.012 (Process Hollowing)** to inject into `svchost.exe` or `explorer.exe` (https://attack.mitre.org/techniques/T1055/001/ and https://attack.mitre.org/techniques/T1055/012/).
- **C2 and note templates:** live/residual sockets to the C2 (`windows.netscan`), plus the ransom-note template string and sometimes symmetric keys or config blobs still resident on the heap — carved by bulk_extractor or matched by YARA. Attackers may use **T1071.001 (Web Protocols)** or **T1573.001 (Encrypted Channel: Symmetric Cryptography)** for C2 (https://attack.mitre.org/techniques/T1071/001/ and https://attack.mitre.org/techniques/T1573/001/).
- **Evasion techniques and their limits:** attackers delete the on-disk binary and note post-encryption, unlink processes (DKOM), pack/obfuscate payloads (**T1027**), and clear event logs (**T1070**). These defeat many disk artifacts but the memory image still preserves:
  - Pool-scannable process objects (`windows.psscan`), unlinked strings (`windows.strings`), and socket structures (`windows.netscan`) — exactly what Volatility 3 recovers.
  - Unbacked RWX memory regions (`windows.malfind`) and injected code.
  - Registry hives (`windows.registry.hivelist`) and modified keys (`windows.registry.printkey`), even if the on-disk hive is deleted.
  - Carved indicators (URLs, emails, keys) via bulk_extractor, which operates on raw bytes without filesystem dependencies.

Attackers may also use **T1564.003 (Hide Artifacts: Hidden Window)** to run the encryptor in a hidden window, or **T1562.001 (Impair Defenses: Disable or Modify Tools)** to disable AV/EDR (https://attack.mitre.org/techniques/T1564/003/ and https://attack.mitre.org/techniques/T1562/001/). These techniques leave artifacts in memory, such as modified registry keys or process command lines.

**Advanced Adversary Emulation & Evasion**
- **Process Doppelgänging (T1055.013):** Attackers may use Windows Transactional NTFS (TxF) to create a modified copy of a legitimate executable (e.g., `notepad.exe`), inject the ransomware payload, and roll back the transaction—leaving no trace on disk. Memory artifacts include a process with a mismatched PEB (Process Environment Block): the original image name appears legitimate, but the process’s memory sections contain the encrypted payload and hollowed-out regions. (Source: CrowdStrike on Process Doppelgänging)
- **Parent PID Spoofing (T1134.004):** Spawning the ransomware process under a trusted parent like `explorer.exe` or `svchost.exe` bypasses process ancestry heuristics. This spoofing leaves an artifact in the EPROCESS block’s `InheritedFromUniqueProcessId` field, which can be recovered via memory forensics. (Source: Mandiant on Parent PID Spoofing)
- **Direct Syscalls & ETW Disabling:** To avoid user-mode API hooks, attackers use direct syscalls (e.g., Hell’s Gate / Halo’s Gate) and disable ETW (Event Tracing for Windows) to prevent telemetry. The red team also clears the VAD (Virtual Address Descriptor) using “dead drop” injection to hinder memory scanning. These emulated techniques mirror real-world ransomware operations and leave distinct forensic footprints for blue team analysis.

**Common Pitfalls & Result Validation**
Analysts often misinterpret ransomware memory artifacts due to **over-reliance on single indicators** or **ignoring process context**. A frequent mistake is assuming all suspicious strings (e.g., `.locked` extensions) confirm ransomware—these may stem from benign file operations or unrelated malware (e.g., **T1037.004: Boot or Logon Initialization Scripts**). Validate findings by cross-referencing process trees, loaded modules, and network connections (e.g., **T1071.004: DNS Application Layer Protocol**). For example, if `cmd.exe` spawns `vssadmin.exe` to delete shadow copies, check parent processes for signs of **T1491.001: Internal Defacement** (e.g., `wmic` or PowerShell invocations).

False positives arise when analysts conflate **legitimate encryption tools** (e.g., BitLocker) with ransomware. To avoid this, verify:
1. **Process injection** (e.g., **T1055.002: Portable Executable Injection**) via `malfind` or `dlllist` in Volatility.
2. **Unusual child processes** (e.g., `notepad.exe` spawning `certutil.exe`).
3. **Memory-resident payloads** by checking for hollowed processes or anomalous memory sections.

Always correlate memory artifacts with disk/registry evidence (e.g., `UserAssist` keys for executed binaries). For authoritative validation, consult:
- [CERT-EU’s ransomware memory forensics guide](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_ransomware.pdf)
- [FireEye’s memory analysis best practices](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/pf/ms/mandiant-memory-forensics.pdf)

**Advanced Evasion: Timestomping & File Deletion**
- **Timestomping (T1070.006):** Attackers modify file timestamps (e.g., `SetFileTime` API) to blend with legitimate files. Memory artifacts include `$STANDARD_INFORMATION` attribute changes in the MFT, which can be recovered via `windows.mftparser` in Volatility. (Source: MITRE ATT&CK T1070.006)
- **File Deletion (T1070.004):** Ransomware deletes the encryptor binary after execution. Memory artifacts include `FILE_OBJECT` structures in kernel pools, recoverable via `windows.filescan` in Volatility. (Source: MITRE ATT&CK T1070.004)

## Answer key
- **YARA:** `rule ransom_note_test` matches on `$a` ("HAVE BEEN ENCRYPTED"), `$b` ("LOCKBIT_TEST_MARKER"), and `$c` ("AES_KEY: ABCDEFGHIJKLMNOP").
```bash
yara -s exercise/ransom.yar exercise/memory.raw
```
Expected: `ransom_note_test exercise/memory.raw` with matched offsets for all three strings (the `-s` flag prints matched strings and offsets — https://yara.readthedocs.io/en/stable/commandline.html).

- **bulk_extractor URL + email + AES key:** the carved C2 URL is `http://203.0.113.10/pay`, the contact email is `evilmail@example.com`, and the AES key is `ABCDEFGHIJKLMNOP`.
```bash
bulk_extractor -E aes -o exercise/be_out exercise/memory.raw
grep -i "203.0.113.10" exercise/be_out/url.txt
grep -i "evilmail@example.com" exercise/be_out/email.txt
grep -i "ABCDEFGHIJKLMNOP" exercise/be_out/aes_keys.txt
```
Expected: all three greps return the seeded indicators (the `email`, `url`, and `aes` scanners are enabled by default or via `-E`; see the bulk_extractor manual, https://github.com/simsong/bulk_extractor).

- **Volatility 3 yarascan:** Use `windows.yarascan` to attribute the ransom-note strings to a process (even though this is a flat dump, the plugin will still work for demonstration).
```bash
vol -f exercise/memory.raw windows.yarascan -Y "HAVE BEEN ENCRYPTED"
```
Expected: output showing the physical offset and process context (if any) where the string was found. Nuance: in a real memory image, this would attribute the string to a specific PID (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.yarascan).

- **Sample sha256:** because the benign sample includes random padding, its digest varies per generation. Record the digest printed by the generator's `sha256sum exercise/memory.raw` as the authoritative value for your build. To create a fixed, reproducible digest, replace the two `head -c ... /dev/urandom`/`/dev/zero` lines with `head -c 8192 /dev/zero` (all-zero padding); that deterministic variant yields a stable sha256 you can pin in CI.

## MITRE ATT&CK & DFIR phase
- **T1486** Data Encrypted for Impact — the ransomware encryption behavior. https://attack.mitre.org/techniques/T1486/
- **T1071** Application Layer Protocol — C2/payment-portal communication observed via netscan. https://attack.mitre.org/techniques/T1071/
- **T1071.001** Web Protocols — C2 using HTTP/HTTPS. https://attack.mitre.org/techniques/T1071/001/
- **T1055** Process Injection — potential injected encryptor code in memory (see `windows.malfind`). https://attack.mitre.org/techniques/T1055/
- **T1055.001** Dynamic-Link Library Injection — DLL injection into legitimate processes. https://attack.mitre.org/techniques/T1055/001/
- **T1055.012** Process Hollowing — process hollowing into `svchost.exe` or `explorer.exe`. https://attack.mitre.org/techniques/T1055/012/
- **T1027** Obfuscated Files or Information — packed/obfuscated payloads whose strings are recovered from RAM. https://attack.mitre.org/techniques/T1027/
- **T1036** Masquerading — legitimately-named binaries used as cover. https://attack.mitre.org/techniques/T1036/
- **T1490** Inhibit System Recovery — shadow-copy deletion commonly seen with ransomware. https://attack.mitre.org/techniques/T1490/
- **T1112** Modify Registry — registry modifications to disable recovery or establish persistence. https://attack.mitre.org/techniques/T1112/
- **T1070** Indicator Removal — clearing event logs or deleting files. https://attack.mitre.org/techniques/T1070/
- **T1070.001** Clear Windows Event Logs — clearing event logs to hide activity. https://attack.mitre.org/techniques/T1070/001/
- **T1070.004** File Deletion — deleting the encryptor binary or ransom notes. https://attack.mitre.org/techniques/T1070/004/
- **T1059.001** Command and Scripting Interpreter: PowerShell — encoded PowerShell commands for execution. https://attack.mitre.org/techniques/T1059/001/
- **T1573.001** Encrypted Channel: Symmetric Cryptography — encrypted C2 communication. https://attack.mitre.org/techniques/T1573/001/
- **T1055.013** Process Doppelgänging — advanced process injection technique using Windows Transactional NTFS (TxF). https://attack.mitre.org/techniques/T1055/013/
- **T1134.004** Parent PID Spoofing — spoofing the parent process ID to evade detection. https://attack.mitre.org/techniques/T1134/004/
- **T1568.002** Dynamic Resolution: Domain Generation Algorithms — DGA patterns in DNS queries. https://attack.mitre.org/techniques/T1568/002/
- **T1562.001** Impair Defenses: Disable or Modify Tools — disabling AV/EDR. https://attack.mitre.org/techniques/T1562/001/
- **T1564.003** Hide Artifacts: Hidden Window — running the encryptor in a hidden window. https://attack.mitre.org/techniques/T1564/003/
- **T1071.004** DNS Application Layer Protocol — C2 communication over DNS. https://attack.mitre.org/techniques/T1071/004/
- **T1037.004** Boot or Logon Initialization Scripts — persistence via startup scripts. https://attack.mitre.org/techniques/T1037/004/
- **T1491.001** Internal Defacement — defacing internal systems as part of ransomware impact. https://attack.mitre.org/techniques/T1491/001/
- **T1570** Lateral Tool Transfer — transferring ransomware binaries across the network. https://attack.mitre.org/techniques/T1570/
- **T1547.001** Registry Run Keys — persistence via registry run keys. https://attack.mitre.org/techniques/T1547/001/
- **T1070.006** Timestomp — modifying file timestamps to evade detection. https://attack.mitre.org/techniques/T1070/006/
- **DFIR phases:** identification (triage the alert), examination/analysis (Volatility 3 + YARA + bulk_extractor on the image), and reporting (IOC list from carved indicators). The memory-forensics analysis workflow aligns with SANS FOR508 guidance (https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).


### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Kernel Memory Dump Via LiveKD** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_livekd_kernel_memory_dump.yml; license: Detection Rule License / DRL):

```yaml
title: Kernel Memory Dump Via LiveKD
id: c7746f1c-47d3-43d6-8c45-cd1e54b6b0a2
status: test
description: Detects execution of LiveKD with the "-m" flag to potentially dump the kernel memory
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
    - https://4sysops.com/archives/creating-a-complete-memory-dump-without-a-blue-screen/
    - https://kb.acronis.com/content/60892
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-16
modified: 2024-03-13
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\livekd.exe'
              - '\livekd64.exe'
        - OriginalFileName: 'livekd.exe'
    selection_cli:
        CommandLine|contains|windash: ' -m'
    condition: all of selection_*
falsepositives:
    - Unlikely in production environment
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/susp_office_template_injection.yar, author: Florian Roth):

```yara
rule EXPL_Office_TemplateInjection_Aug19 {
   meta:
      old_rule_name = "EXPL_Office_TemplateInjection"
      description = "Detects possible template injections in Office documents, particularly those that load content from external sources"
      author = "Florian Roth"
      reference = "https://attack.mitre.org/techniques/T1221/"
      date = "2019-08-22"
      modified = "2025-03-20"
      score = 75
      hash = "f2bdf3716b39d29a9c6c3b7b3355e935594b8d8e9149a784a59dc2381fa1628a"
      id = "2a7e1021-97be-510b-8826-d15ac06ed00e"
   strings:
      $x1 = /attachedTemplate" Target="http[s]?:\/\/[^"]{4,60}/ ascii

      $fp1 = ".sharepoint.com"  // this could cause false negatives if the malicious template is hosted on sharepoint
      $fp2 = ".office.com"  // this could cause false negatives if the malicious template is hosted on office.com
   condition:
      filesize < 20MB
      and $x1
      and not 1 of ($fp*)
}
```

**Real-world context (MITRE T1057 -- Process Discovery):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1057/ -- real in-the-wild use includes Akira, APT1, APT28, APT3, APT37.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Adversary Emulation & Red-Team Perspective

From a red-team perspective, ransomware operators exploit memory-resident techniques to evade traditional file-based detection and maintain persistence during encryption. A common tactic involves **process hollowing (T1055.012: Process Hollowing)**, where the attacker spawns a legitimate process (e.g., `svchost.exe`) in a suspended state, hollows out its memory, and injects malicious shellcode to execute ransomware payloads directly in memory. This avoids writing the payload to disk, reducing forensic artifacts. Another prevalent technique is **reflective code loading (T1406.001: Reflective Code Loading)**, where the ransomware binary is loaded directly into memory without relying on the Windows loader, further obscuring its execution.

Attackers may also abuse **Windows API calls** (e.g., `VirtualAlloc`, `CreateRemoteThread`) to allocate and execute memory regions dynamically, leaving minimal traces beyond transient memory artifacts like injected threads or anomalous process handles. Evasion considerations include:
- **Obfuscating API calls** (e.g., dynamic resolution via hashing) to thwart static analysis.
- **Timing-based execution** (e.g., delaying encryption until after initial compromise) to bypass behavioral detections.
- **Leveraging legitimate tools** (e.g., `PsExec`, `WMI`) for lateral movement before memory injection to blend in with normal activity.

Artifacts left behind include:
- **Unbacked memory regions** (detectable via volatility plugins like `malfind`).
- **Anomalous parent-child process relationships** (e.g., `explorer.exe` spawning `cmd.exe` with injected threads).
- **Modified process memory permissions** (e.g., `PAGE_EXECUTE_READWRITE` flags).

For deeper emulation, red teams can use frameworks like **Cobalt Strike** or **Sliver** to simulate these TTPs, while defenders should monitor for suspicious memory allocations and process injection patterns.

**Sources:**
- [MITRE ATT&CK: Reflective Code Loading (T1406.001)](https://attack.mitre.org/techniques/T1406/001/)
- [FireEye: Process Hollowing and Other Malware Evasion Techniques](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1486 (Data Encrypted for Impact)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1486/
- **Threat actors documented using it:** Akira (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **Volatility 3**:
  - Invocation model, `--info`, symbol tables, and plugin behavior (`windows.info`, `pslist`, `psscan`, `pstree`, `cmdline`, `netscan`, `malfind`, `yarascan`, `registry.hivelist`, `registry.printkey`, `handles`):
    - Volatility 3 docs — https://volatility3.readthedocs.io/en/latest/
    - Basics / `--info` — https://volatility3.readthedocs.io/en/latest/basics.html
    - Symbol tables — https://volatility3.readthedocs.io/en/latest/symbol-tables.html
    - Windows plugins reference — https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html
    - Source — https://github.com/volatilityfoundation/volatility3
    - The Volatility Foundation — https://www.volatilityfoundation.org/
  - `windows.malfind` and process injection detection:
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind
    - SANS FOR508: Memory Forensics — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
  - `windows.yarascan` for per-process YARA scanning:
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.yarascan
  - `windows.registry.hivelist` and `windows.registry.printkey` for registry analysis:
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.hivelist
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.printkey

- **YARA**:
  - `--version`, `-s` flag, and rule syntax (`strings:`/`condition:`/`any of them`):
    - YARA command-line reference — https://yara.readthedocs.io/en/stable/commandline.html
    - YARA writing rules — https://yara.readthedocs.io/en/stable/writingrules.html
    - Source — https://github.com/VirusTotal/yara
    - Kali Tools (yara) — https://www.kali.org/tools/yara/
  - YARA for crypto key detection:
    - https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings

- **bulk_extractor**:
  - `-V`, `-o`, `-E` behavior, and default `url`/`email`/`aes` scanners:
    - Source & manual — https://github.com/simsong/bulk_extractor
    - Feature scanners — https://github.com/simsong/bulk_extractor/wiki/Feature-Scanners
  - AES key carving:
    - https://github.com/simsong/bulk_extractor/wiki/AES-Key-Finder

- **Tool availability on analyst distros**:
  - REMnux tool listings — https://docs.remnux.org/discover-the-tools/
  - SANS SIFT Workstation — https://www.sans.org/tools/sift-workstation/

- **Security Onion / Suricata / Zeek**:
  - Analyst workflow, Suricata alerts, Zeek `conn.log`, `http.log`, `ssl.log`, and pivots:
    - Security Onion docs — https://docs.securityonion.net/en/2.4/
    - Zeek log reference — https://docs.zeek.org/en/master/logs/index.html
    - Suricata rule writing — https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html
    - Elasticsearch integration — https://docs.securityonion.net/en/2.4/elasticsearch.html

- **MITRE ATT&CK techniques cited**:
  - T1486 — https://attack.mitre.org/techniques/T1486/
  - T1071 — https://attack.mitre.org/techniques/T1071/ ; T1071.001 — https://attack.mitre.org/techniques/T1071/001/ ; T1071.004 — https://attack.mitre.org/techniques/T1071/004/
  - T1055 — https://attack.mitre.org/techniques/T1055/ ; T1055.001 — https://attack.mitre.org/techniques/T1055/001/ ; T1055.012 — https://attack.mitre.org/techniques/T1055/012/ ; T1055.013 — https://attack.mitre.org/techniques/T1055/013/ ; T1055.002 — https://attack.mitre.org/techniques/T1055/002/
  - T1027 — https://attack.mitre.org/techniques/T1027/
  - T1036 — https://attack.mitre.org/techniques/T1036/
  - T1490 — https://attack.mitre.org/techniques/T1490/
  - T1112 — https://attack.mitre.org/techniques/T1112/
  - T1070 — https://attack.mitre.org/techniques/T1070/ ; T1070.001 — https://attack.mitre.org/techniques/T1070/001/ ; T1070.004 — https://attack.mitre.org/techniques/T1070/004/ ; T1070.006 — https://attack.mitre.org/techniques/T1070/006/
  - T1059 — https://attack.mitre.org/techniques/T1059/ ; T1059.001 — https://attack.mitre.org/techniques/T1059/001/
  - T1573 — https://attack.mitre.org/techniques/T1573/ ; T1573.001 — https://attack.mitre.org/techniques/T1573/001/
  - T1041 — https://attack.mitre.org/techniques/T1041/
  - T1547.001 — https://attack.mitre.org/techniques/T1547/001/
  - T1562.001 — https://attack.mitre.org/techniques/T1562/001/ ; T1562.003 — https://attack.mitre.org/techniques/T1562/003/
  - T1564.003 — https://attack.mitre.org/techniques/T1564/003/
  - T1568.002 — https://attack.mitre.org/techniques/T1568/002/
  - T1134.004 — https://attack.mitre.org/techniques/T1134/004/
  - T1037.004 — https://attack.mitre.org/techniques/T1037/004/
  - T1491.001 — https://attack.mitre.org/techniques/T1491/001/
  - T1570 — https://attack.mitre.org/techniques/T1570/

- **RFC 5737** (documentation IP ranges incl. 203.0.113.0/24) — https://datatracker.ietf.org/doc/html/rfc5737

- **Windows Event Logs**:
  - Event ID 4688 (Process Creation) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
  - Event ID 4663 (File System Object Access) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
  - Event ID 104 (Event Log Cleared) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-104
  - Event ID 4657 (Registry Value Modified) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657
  - Event ID 1102 (Event Log Cleared) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
  - Event ID 4624 (Account Logon) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624

- **Sysmon Events**:
  - Event ID 1 (Process Creation) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
  - Event ID 8 (CreateRemoteThread) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-8-createremotethread
  - Event ID 10 (ProcessAccess) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-10-processaccess
  - Event ID 11 (FileCreate) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-11-filecreate
  - Event ID 13 (RegistryEvent) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-13-registryevent
  - Event ID 25 (ProcessTampering) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-25-processtampering

- **SANS FOR508** (IR/threat-hunting & memory forensics methodology) — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

- **Detection Engineering**:
  - CISA #StopRansomware Guide — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a
  - Elastic Security Labs: Detecting Ransomware with Sysmon — https://www.elastic.co/security-labs/detecting-ransomware-with-sysmon

- **Adversary Emulation & Evasion**:
  - CrowdStrike on Process Doppelgänging — https://www.crowdstrike.com/blog/process-doppelanging-a-new-way-to-impersonate-processes/
  - Mandiant on Parent PID Spoofing — https://www.mandiant.com/resources/blog/tracking-parent-pid-spoofing

- **Validation & Best Practices**:
  - CERT-EU’s ransomware memory forensics guide — https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_ransomware.pdf
  - FireEye’s memory analysis best practices — https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/pf/ms/mandiant-memory-forensics.pdf

## Related modules
- [Memory forensics](../02-memory-forensics/README.md) -- shares bulk_extractor for carving IOCs from RAM captures.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- shares bulk_extractor and extends the Volatility 3 plugin workflow used here, including advanced process injection analysis.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares yara for signature-based hunting of C2 indicators and extends network-based detection logic.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares bulk_extractor within a full host-triage pipeline, including registry and file system artifact analysis.

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1569/002/
- https://attack.mitre.org/techniques/T1053/005/
- https://github.com/SigmaHQ/sigma-specification
- https://attack.mitre.org/techniques/T1406/001/
- https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

<!-- cyberlab-enriched: v6 -->
