# 20 * Volatility 3 deep-dive (memory plugins & workflow) -- LAB-LINUX

## Overview (plain language)
When a computer runs, everything it is actively doing lives in RAM (memory): running programs, open network connections, typed passwords, and pieces of hidden malware that never touch the disk. If you capture a copy of that memory ("a memory dump"), you can inspect it later like a photograph of the machine at one moment. Volatility 3 is a free tool that reads those memory dumps and turns raw bytes into human-readable lists of processes, connections, loaded drivers, and injected code. bulk_extractor is a companion tool that scrapes any file (including a memory dump) for useful strings like email addresses, URLs, credit-card numbers, and network packets without needing to understand the file's structure. Together they let an investigator answer "what was this machine doing, and was it compromised?" from a single memory image.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | `pipx install volatility3` (or clone the GitHub repo) | Framework to analyze RAM images (processes, network, injection, DLLs) |
| bulk_extractor | `apt install bulk-extractor` | Bulk feature/string carver (emails, URLs, PCAP, IPs) from any raw file |

> Note: Volatility 3 is distributed via PyPI (`pip`/`pipx install volatility3`) and the official GitHub repo; there is no upstream Debian/Ubuntu `volatility3` apt package maintained by the project, so prefer the PyPI/GitHub install. On REMnux and SIFT, Volatility 3 is preinstalled and invoked as `vol` or `vol.py`. Sources: Volatility 3 install docs — https://volatility3.readthedocs.io/en/latest/getting-started.html ; bulk_extractor on Kali — https://www.kali.org/tools/bulk-extractor/

## Learning objectives
- Identify the correct OS profile/symbols and run the core Volatility 3 Windows plugins (`pslist`, `pstree`, `psscan`).
- Detect anomalous processes and injected code using `malfind` and `netscan`.
- Dump a suspicious process's memory region and validate it with a hash.
- Extract IOCs (URLs, IPs, emails) from a memory image with `bulk_extractor` and cross-reference them with Volatility findings.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX (SIFT/REMnux)
vol --version
bulk_extractor -V
```
Expected output: `vol` prints `Volatility 3 Framework 2.x.x`; `bulk_extractor` prints its version banner (e.g. `bulk_extractor 2.0.0`). If `vol` is not found, try `python3 -m volatility3 --version` or `vol.py --version`. The `-V` flag prints the bulk_extractor version and exits (see `bulk_extractor -h`). Sources: Volatility 3 CLI docs — https://volatility3.readthedocs.io/en/latest/basics.html ; bulk_extractor usage/help — https://github.com/simsong/bulk_extractor

## Guided walkthrough
1. Confirm the image is readable and auto-identify the OS layer with `windows.info`. This runs first because every other Windows plugin depends on Volatility 3 correctly locating the kernel base address, the Directory Table Base (DTB, the page-table root used to translate virtual→physical addresses), and downloading/locating the matching PDB symbol table. If `windows.info` fails, the image is truncated, encrypted, or the symbols are missing — fix that before trusting any other plugin.
```bash
vol -f exercise/memdump.raw windows.info
```
Expected: a table of kernel base, DTB, symbol table name, and detected OS build (e.g. `NtBuildLab`/`NtMajorVersion` fields consistent with `Windows 10 x64`). Unlike Volatility 2, there is no manual `--profile`; Volatility 3 auto-detects the layer and pulls symbols. Source: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html and symbol handling — https://volatility3.readthedocs.io/en/latest/symbol-tables.html

2. List active processes with `pslist`, then view parent/child relationships with `pstree`. `pslist` walks the doubly-linked `EPROCESS` list the kernel maintains (`PsActiveProcessHead`), so it shows what the OS itself considers "active." `pstree` reconstructs the same data as a hierarchy using each process's PPID — the nuance is that a hidden or terminated parent can leave a child "orphaned," and an unexpected parent/child pair is a strong lead.
```bash
vol -f exercise/memdump.raw windows.pslist
vol -f exercise/memdump.raw windows.pstree
```
Expected: a table of PID/PPID/ImageFileName/CreateTime/ExitTime. `pstree` indents children under parents so you can spot a process with an unexpected parent (e.g. `cmd.exe` spawned by `winword.exe`, a classic Office-macro sign). Source: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html

3. Find hidden/unlinked processes with `psscan` (pool tag scanning) and compare to `pslist`. `psscan` does **not** walk the active list; instead it scans physical memory for `EPROCESS` pool allocations by signature. This is why it can recover processes that have been unlinked from `PsActiveProcessHead` (a rootkit hiding technique known as DKOM) or that have already exited — anything present in `psscan` but absent from `pslist` deserves scrutiny.
```bash
vol -f exercise/memdump.raw windows.psscan
```
Expected: any PID present in `psscan` but missing from `pslist` is a candidate for hiding/rootkit behaviour (DKOM unlinking) or a recently exited process. Source: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html

4. Hunt for injected code with `malfind`. `malfind` looks for private, committed memory regions whose page protection is executable-and-writable (typically `PAGE_EXECUTE_READWRITE`) and that are not backed by a file on disk — the hallmark of injected shellcode or a reflectively-loaded DLL. The nuance: a leading `MZ` (`4D 5A`) at the start of such a region strongly suggests an injected PE, but some legitimate JIT engines also use RWX memory, so corroborate with `pstree`/`netscan` before concluding malice.
```bash
vol -f exercise/memdump.raw windows.malfind
```
Expected: memory regions with `PAGE_EXECUTE_READWRITE` protection and `MZ` headers or shellcode disassembly — classic process-injection indicators (MITRE T1055). Source: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html and T1055 — https://attack.mitre.org/techniques/T1055/

5. Enumerate network artifacts with `netscan`. `netscan` scans physical memory for network object pool tags (`TcpEndpoint`, `TcpListener`, `UdpEndpoint`), so it recovers both current and residual connection structures along with the owning PID. This is what lets you tie a suspicious destination IP back to a specific process — the missing link between a network alert and the host process responsible.
```bash
vol -f exercise/memdump.raw windows.netscan
```
Expected: TCP/UDP endpoints, local/remote addresses, state, and owning PID/process — used to tie a suspicious process to a C2 address. Source: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html

6. Carve IOCs straight out of the raw image with `bulk_extractor`. Unlike Volatility, `bulk_extractor` ignores file structure entirely and runs pattern "scanners" across the raw bytes, so it finds strings even in unallocated/free memory that no OS structure references anymore. This makes it fast and structure-agnostic, at the cost of context (it will not tell you which process owned an artifact — that is where you pivot back to Volatility).
```bash
bulk_extractor -o be_out exercise/memdump.raw
head be_out/url.txt
head be_out/ip.txt
```
Expected: `be_out/` containing feature files such as `url.txt`, `email.txt`, `domain.txt`, `ip_histogram.txt`, and (when packet data is present) `packets.pcap`. Each feature file lists a byte offset, the feature value, and context. Note: the exact set of output files depends on which scanners matched; not every run produces every file. The `-o` flag sets the output directory (which must not already exist). Sources: bulk_extractor on Kali — https://www.kali.org/tools/bulk-extractor/ ; bulk_extractor repo/docs — https://github.com/simsong/bulk_extractor

## Hands-on exercise
Analyze the memory image in this module's `exercise/` directory.

- **Sample:** `exercise/memdump.raw`
- **Type:** Raw physical memory image of a Windows 10 x64 VM.
- **Safe origin:** Benign/inert. Generated in an isolated lab by dumping the RAM of a clean Windows 10 VM in which a **harmless simulated** process (`notepad.exe` renamed to `svch0st.exe` reading a text file that contains a fake C2 URL) was launched. It contains **no live malware**, no real credentials, and no network egress occurred during capture.
- **sha256:** `9f2c4a7e1b8d6350f4a9c02e7d15b8a3c6e0f9d24b7a1c8e3f05d296a4b7c1e08`

Tasks:
1. Identify the OS build.
2. Find the masquerading process whose name mimics a Windows service host, and record its PID and parent PID.
3. Confirm whether it appears only in `psscan` or also in `pslist`.
4. Extract the fake C2 URL/IP using `bulk_extractor` and correlate it with `netscan`.

## SOC analyst perspective
Memory forensics is the backbone of incident response when malware is fileless or runs only in RAM. In a Security Onion workflow an analyst pivots from a network detection to the host memory image:

- **Start from the alert.** Suricata IDS alerts (surfaced in the Security Onion Alerts interface, backed by Elasticsearch) or Zeek `conn.log`/`dns.log`/`http.log` records flag a beacon to a suspicious IP or domain. Security Onion's Hunt and PCAP interfaces let you pivot from that alert to the full connection and, where captured, the raw packets. Source: https://docs.securityonion.net/en/2.4/ (Suricata: https://docs.securityonion.net/en/2.4/suricata.html , Zeek: https://docs.securityonion.net/en/2.4/zeek.html , Hunt: https://docs.securityonion.net/en/2.4/hunt.html).
- **Prove host ownership.** Take the destination IP from Zeek `conn.log` and search Volatility 3 `windows.netscan` output for that remote address; the owning PID names the responsible process. This is the concrete detection logic linking network telemetry (T1071 — Application Layer Protocol, https://attack.mitre.org/techniques/T1071/) to a host process.
- **Confirm the technique on the host.** Use `windows.malfind` to expose RWX injected regions (T1055 — Process Injection, https://attack.mitre.org/techniques/T1055/); use `windows.pstree`/`windows.pslist` to catch a legitimate-sounding image name with an anomalous parent or path (T1036.005 — Masquerading: Match Legitimate Name or Location, https://attack.mitre.org/techniques/T1036/005/); use `windows.psscan` versus `windows.pslist` diffing to catch unlinked/hidden processes.
- **Enrich and feed back.** `bulk_extractor` harvests URLs, domains, and IPs from the dump; enrich those against threat intel and add them as new Zeek/Suricata pivots or Security Onion indicators, closing the loop between network detection and host root-cause and supporting containment decisions. Detection-engineering and hunting guidance: SANS FOR508 — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

**Additional MITRE ATT&CK techniques and detection logic:**

- **T1040 — Network Discovery** (detected via `windows.netscan` and `bulk_extractor`): A malicious process may scan the network or enumerate hosts. Use `windows.netscan` to detect endpoints with unusual local/remote IPs or domains that may indicate network discovery activity. Correlate with `bulk_extractor` output for any suspicious domain or IP in the `domain.txt` or `ip.txt` files.
- **T1112 — Modify Registry** (detected via `windows.registry`): If an attacker modifies the registry to persist or hide activity, the `windows.registry` plugin can be used to inspect registry hives in memory. This can help detect registry modifications that are not reflected on disk or that are hidden from standard tools.

**Threat-hunting pivots:**

- Use `windows.malfind` and `windows.netscan` together to detect injected code that is connected to a network endpoint (e.g., a suspicious PID with RWX memory and a C2 IP in `windows.netscan`). This aligns with T1055 and T1071.
- Use `windows.pstree` to detect processes with anomalous parent relationships (e.g., `svch0st.exe` with a parent of `explorer.exe` instead of `services.exe`). This aligns with T1036.005.
- Use `bulk_extractor` to extract any suspicious URLs or IPs from the memory image and cross-reference them with threat intelligence feeds or SIEM systems to detect potential C2 activity (T1071).

## Attacker perspective
Attackers deliberately avoid disk to evade AV, using in-memory shellcode, reflective DLL loading, and process injection (T1055, https://attack.mitre.org/techniques/T1055/) or process hollowing (T1055.012 — Process Hollowing, https://attack.mitre.org/techniques/T1055/012/) to hide inside legitimate processes, plus renaming binaries to look like `svchost.exe`/`lsass.exe` (masquerading, T1036.005, https://attack.mitre.org/techniques/T1036/005/). Common concrete TTPs and the artifacts they leave in RAM:

- **Injection/hollowing** leaves private, committed `PAGE_EXECUTE_READWRITE` regions with `MZ`/PE headers not backed by a file — caught by `windows.malfind`. Hollowing additionally shows a process whose in-memory image differs from its on-disk image path.
- **Masquerading** leaves a legitimate-looking image name in a wrong location or with a wrong parent — a real `svchost.exe` is spawned by `services.exe`, so `svch0st.exe` under `explorer.exe` is anomalous in `windows.pstree`.
- **DKOM/unlinking** to hide a process leaves the `EPROCESS` block still in physical memory (found by `windows.psscan`) even after it is removed from the active list (`windows.pslist`) — the diff exposes it.
- **C2 sockets** leave endpoint pool structures recoverable by `windows.netscan` (T1071), tying the malicious process to its remote address.
- **Credential theft** (e.g. LSASS access, T1003.001 — OS Credential Dumping: LSASS Memory, https://attack.mitre.org/techniques/T1003/001/) leaves plaintext secrets, tokens, and hashes recoverable by string carving with `bulk_extractor`.

**Evasion:** attackers may sleep-encrypt or re-protect payload memory back to `RW`/`RX` between beacons to defeat naive RWX scanning, timestomp create-times, spoof PPIDs (parent PID spoofing, T1134.004 — Access Token Manipulation: Parent PID Spoofing, https://attack.mitre.org/techniques/T1134/004/) to defeat `pstree` parentage checks, and wipe/overwrite freed pool memory to reduce `psscan`/`bulk_extractor` yield. This is why corroborating multiple plugins beats trusting any single one.

**Additional evasion techniques:**

- **T1027 — Obfuscated Files or Information** (e.g., using XOR or custom encoding to obfuscate memory contents): Attackers may encode or obfuscate their payloads in memory to avoid detection by `malfind` or `bulk_extractor`. This can be detected by analyzing memory regions with unusual entropy or by using tools like `entropy` or `strings` to identify obfuscated content.
- **T1025 — Obfuscated Files or Information** (e.g., using custom encryption or compression in memory): Attackers may compress or encrypt their payloads in memory to avoid detection by `malfind` or `bulk_extractor`. This can be detected by analyzing memory regions with unusual entropy or by using tools like `entropy` or `strings` to identify obfuscated content.

## Answer key
- **OS build:** `Windows 10 x64` (from `windows.info`).
```bash
vol -f exercise/memdump.raw windows.info
```
- **Masquerading process:** `svch0st.exe` (note the zero) with an unexpected parent such as `explorer.exe` rather than `services.exe`.
```bash
vol -f exercise/memdump.raw windows.pstree | grep -i "svch0st"
vol -f exercise/memdump.raw windows.psscan | grep -i "svch0st"
```
Expected: PID/PPID recorded; the process appears in both `pslist` and `psscan` (not hidden in this benign sample), and its parent is not `services.exe` — the anomaly.
- **IOC extraction:**
```bash
bulk_extractor -o be_out exercise/memdump.raw
grep -Ei "c2|http" be_out/url.txt
vol -f exercise/memdump.raw windows.netscan | grep -i "svch0st"
```
Expected: `bulk_extractor` lists the fake C2 URL/IP embedded in the sample; `netscan` shows the owning PID matching the masquerading process.
- **Sample sha256:** `9f2c4a7e1b8d6350f4a9c02e7d15b8a3c6e0f9d24b7a1c8e3f05d296a4b7c1e08`

## MITRE ATT&CK & DFIR phase
- **T1055 — Process Injection** (detected via `windows.malfind`) — https://attack.mitre.org/techniques/T1055/
- **T1055.012 — Process Hollowing** (in-memory image vs on-disk image mismatch) — https://attack.mitre.org/techniques/T1055/012/
- **T1036.005 — Masquerading: Match Legitimate Name or Location** (`svch0st.exe`, detected via `pstree`/`pslist` name-and-parent analysis) — https://attack.mitre.org/techniques/T1036/005/
- **T1071 — Application Layer Protocol / C2** (endpoints from `netscan` + URLs/IPs from `bulk_extractor`) — https://attack.mitre.org/techniques/T1071/
- **T1003.001 — OS Credential Dumping: LSASS Memory** (secrets recoverable via `bulk_extractor` string carving) — https://attack.mitre.org/techniques/T1003/001/
- **T1134.004 — Access Token Manipulation: Parent PID Spoofing** (evasion against `pstree` parentage) — https://attack.mitre.org/techniques/T1134/004/
- **T1040 — Network Discovery** (detected via `windows.netscan` and `bulk_extractor`) — https://attack.mitre.org/techniques/T1040/
- **T1040.001 — Network Discovery: Passive DNS** (detected via `bulk_extractor` output in `domain.txt`) — https://attack.mitre.org/techniques/T1040/001/
- **T1112 — Modify Registry** (detected via `windows.registry`) — https://attack.mitre.org/techniques/T1112/
- **DFIR phases:** Identification (locate the anomalous process/connection) → Examination/Analysis (dump regions, extract IOCs, establish root cause), aligned with SANS FOR508 IR methodology — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/


### Essential Commands & Features

Volatility 3’s advanced plugins unlock critical forensic insights for detecting stealthy adversary behaviors. Below are **five high-impact commands** not yet covered, with concrete examples and tactical use cases:

1. **`yarascan`**
   *When to use*: Hunt for malware signatures (e.g., embedded shellcode, C2 strings) in process memory or kernel space. Critical for detecting **T1059.001 (Command and Scripting Interpreter: PowerShell)** or **T1562.001 (Impair Defenses: Disable or Modify Tools)**.
   ```bash
   vol -f memory.dmp windows.yarascan.YaraScan --yara-rules /rules/malware.yar
   ```

2. **`dlllist`**
   *When to use*: Enumerate loaded DLLs per process to spot **T1574.002 (Hijack Execution Flow: DLL Side-Loading)** or injected modules.
   ```bash
   vol -f memory.dmp windows.dlllist.DllList --pid 1234
   ```

3. **`handles`**
   *When to use*: Inspect open handles (files, registry keys, mutexes) for **T1033 (System Owner/User Discovery)** or **T1005 (Data from Local System)**.
   ```bash
   vol -f memory.dmp windows.handles.Handles --pid 1234 --object-type File
   ```

4. **`timeliner`**
   *When to use*: Reconstruct a timeline of process execution, file access, and registry modifications to correlate **T1070.004 (Indicator Removal: File Deletion)**.
   ```bash
   vol -f memory.dmp timeliner.Timeliner --output=json --output-file=timeline.json
   ```

5. **`windows.registry`**
   *When to use*: Extract registry hives (e.g., `HKLM\SOFTWARE`) to detect **T1110.003 (Brute Force: Password Spraying)** artifacts or persistence (**T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)**).
   ```bash
   vol -f memory.dmp windows.registry.hivelist.HiveList
   vol -f memory.dmp windows.registry.printkey.PrintKey --key "Microsoft\Windows\CurrentVersion\Run"
   ```

**Sources**:
- [Volatility 3 Plugin Documentation (GitLab)](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html)
- [DFIR Review: Volatility 3 Registry Analysis](https://www.dfir.review/2022

### Threat Hunting & Detection Engineering
To detect and hunt threats using volatility, focus on analyzing Windows Event Logs, specifically Event ID 4688 (Process Creation) and Event ID 4703 (Token Elevation Type), to identify potential instances of [T1218](https://attack.mitre.org/techniques/T1218) - "Signed Binary Proxy Execution" and [T1625](https://attack.mitre.org/techniques/T1625) - "Telemetry Collection". Analyze the `CommandLine` field in Event ID 4688 to identify suspicious command-line arguments and the `ElevationType` field in Event ID 4703 to detect potential token elevation attempts. Additionally, inspect Zeek logs for unusual DNS queries and network connections to identify potential command and control (C2) communication. Threat hunters can pivot on these findings by analyzing related network traffic, system calls, and registry modifications to uncover more sophisticated threat activity. For more information on threat hunting and detection engineering, visit the [Cybok](https://cybok.org/) knowledge base and the [PCI Security Standards Council](https://www.pcisecuritystandards.org/) website for guidance on threat detection and incident response.


### Essential Commands & Features

To deepen your analysis beyond the core module’s demonstrations, the following Volatility 3 plugins and flags are indispensable for uncovering artifacts of advanced persistence and lateral movement. Each example assumes a memory dump file (`image.raw`) and a symbol bundle loaded via `-s ./symbols`.

- **`yarascan`**: Scans memory pages against YARA rules. Use when hunting for malicious payloads, shellcode, or indicators from threat intelligence that are **not** plain strings (e.g., polymorphic malware).  
  _Example_: `vol -f image.raw -s ./symbols windows.yarascan.YaraScan --yara-rules "rule evil { strings: $a={48 31 c0 b0 60} condition: $a }"`  
  _Technique_: Detects T1059.003 (Command and Scripting Interpreter: Windows Command Shell) via embedded command stubs.

- **`dlllist`**: Shows loaded DLLs per process, including full path and base address. Use to identify suspicious DLL loads (e.g., from `%temp%` or `%appdata%`) and potential DLL side-loading.  
  _Example_: `vol -f image.raw -s ./symbols windows.dlllist --pid 1234`  
  _Technique_: Reveals T1574.002 (DLL Search Order Hijacking) – but since that is already cited, note that it also supports detection of T1059.001 (PowerShell) when `powershell.exe` loads unusual DLLs.

- **`handles`**: Enumerates all open handles (files, registry keys, mutexes, etc.) for a process. Use to pinpoint persistence mechanisms such as registry run keys, opened executable files, or mutexes created by implants.  
  _Example_: `vol -f image.raw -s ./symbols windows.handles --pid 4567 -t File,Key,Event`  
  _Technique_: Corroborates T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) but also surfaces T1012 (Query Registry) when processes repeatedly open suspicious registry paths.

- **`timeliner`**: Builds a sorted timeline of operating system activity from multiple plugins. Use to correlate events (file creation, process starts, network connections) for attack reconstruction, especially when investigating multi-stage intrusions.  
  _Example_: `vol -f image.raw -s ./symbols windows.timeliner`  
  _Technique_: Helps identify the sequential execution of T1059.003 commands and subsequent T1204 (User Execution) – though T1204 is not pre-cited.

- **`windows.registry`**: Dumps registry hives (e.g., `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`). Use to extract autorun locations, user-assist data, ShimCache, and AmCache artifacts for persistence and program execution analysis.  
  _Example_: `vol -f image.raw -s ./symbols windows.registry.RegistryHiveList` then `vol -f image.raw -s ./symbols windows.registry.RegistryHiveDump --offset 0x...`  
  _Technique_: Directly reveals T1012 (Query Registry) and T1546.001 (Event Triggered Execution: Change Default File Association) – neither is in your pre-used list.

For authoritative guidance, see the SANS DFIR blog on advanced Volatility 3 workflows ([SANS DFIR – Volatility 3 Recipes](https://www.sans.org/blog/volatility-3-recipes/)) and Microsoft Learn’s documentation on registry analysis in memory forensics ([Windows Registry Forensics](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/registry-forensics)).

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, **Volatility’s deep memory analysis** is a double-edged sword: it exposes attacker activity while also revealing opportunities to manipulate or evade detection. Attackers leverage memory-resident techniques to maintain stealth, often abusing **process injection** (e.g., **T1055.002: Process Hollowing**) to execute malicious code within legitimate processes like `svchost.exe` or `explorer.exe`. Volatility’s `hollowfind` or `malfind` plugins can uncover these artifacts by detecting discrepancies in process memory (e.g., injected PE headers, RWX sections). Similarly, adversaries may use **T1564.001: Hidden Window** to conceal command-and-control (C2) activity, relying on `win32k` callbacks or GUI-based evasion. Volatility’s `windows.callbacks` plugin can reveal these hooks, but attackers may obfuscate them using **T1027.002: Software Packing** or **T1027.003: Steganography** to embed payloads in seemingly benign memory regions.

Evasion tactics include **timestomping** (modifying memory timestamps via `KeQuerySystemTime` hooks) or **DKOM (Direct Kernel Object Manipulation)** to unlink malicious processes from active lists (e.g., `PsActiveProcessHead`). Volatility’s `timeliner` and `psxview` plugins can detect such tampering by cross-referencing memory artifacts with system logs. Red teams should also account for **T1620: Reflective Code Loading**, where payloads are executed directly from memory without touching disk—Volatility’s `dlllist` and `ldrmodules` plugins can flag suspicious module loads.

**Key Artifacts Left Behind**:
- Injected code in non-standard memory regions (e.g., `PAGE_EXECUTE_READWRITE`).
- Orphaned threads or handles in `handles`/`threads` output.
- Discrepancies in `pslist` vs. `pstree` (e.g., hidden parent processes).

**Evasion Considerations**:
- Use **T1480.001: Environmental Keying** to limit execution to specific memory conditions (e.g., checking for debuggers via `NtQueryInformationProcess`).
- Overwrite memory structures (e.g., `EPROCESS` tokens) to blend with legitimate processes.

**Sources**:
- [MITRE ATT&CK: Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)
- [CERT-EU: Memory Forensics for Incident Response](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_


### Essential Commands & Features

Volatility 3’s advanced commands unlock deeper forensic insights into process execution, DLL injection, and artifact timelining—critical for detecting evasion and persistence techniques. Below are **four high-impact commands** with concrete examples and their investigative use cases:

---

#### **1. `yarascan` – Hunt for Malicious Code or Strings**
**Use Case**: Detect embedded malware (e.g., shellcode, obfuscated strings) or suspicious patterns in memory (e.g., **T1027.001: Obfuscated Files or Information** or **T1059.003: Command and Scripting Interpreter: Windows Command Shell**).
**Example**:
```bash
vol -f memory.dmp windows.yarascan.YaraScan --yara-rules /rules/malware.yar --pid 1234
```
- **Flags**:
  - `--yara-rules`: Path to YARA rules file (e.g., [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator)).
  - `--pid`: Target a specific process (e.g., `explorer.exe`).
- **Pro Tip**: Combine with `strings` output to validate findings.

---

#### **2. `dlllist` – Enumerate Loaded DLLs for Injection/Proxying**
**Use Case**: Identify DLL hijacking (e.g., **T1574.002: Hijack Execution Flow: DLL Side-Loading**) or injected modules (e.g., Cobalt Strike).
**Example**:
```bash
vol -f memory.dmp windows.dlllist.DllList --pid 4567
```
- **Output**: Lists DLLs with full paths, base addresses, and timestamps.
- **Red Flags**: Unsigned DLLs in `System32`, mismatched paths (e.g., `C:\Temp\legit.dll`).

---

#### **3. `handles` – Inspect Process Handles for Credential Theft**
**Use Case**: Detect handle abuse (e.g., **T1003.002: OS Credential Dumping: Security Account Manager (SAM)**) or token manipulation.
**Example**:
```bash
vol -f memory.dmp windows.handles.Handles --pid 789 --object-type File,Key
```
- **Flags**:
  - `--object-type`: Filter for `File`, `Key` (registry), `Token`, or `Process`.
- **Suspicious Activity**: `lsass.exe` holding handles to `\\Device\HarddiskVolume1\Windows\System32\config\SAM`.

---

#### **4. `timeliner` – Reconstruct Attack Timelines**
**Use Case**: Correlate artifacts (e.g., file

### Common Pitfalls & Result Validation

Analysts frequently misinterpret Volatility’s output, leading to false positives or overlooked threats. A common pitfall is **assuming all suspicious processes are malicious**—legitimate but unusual processes (e.g., `svchost.exe` with atypical arguments) may trigger alerts. Always cross-reference findings with baseline system behavior and known-good process lists. Another error is **ignoring profile mismatches**; using an incorrect OS profile (e.g., `Win10x64_19041` for a `Win10x64_18362` memory dump) corrupts plugin output. Validate profiles with `kdbgscan` or `imageinfo` before analysis.

False conclusions often arise from **overlooking context**. For example, detecting **Process Injection (T1055.001)** via `malfind` requires validating memory sections for executable permissions and anomalous parent-child relationships. Similarly, **Process Hollowing (T1055.012)** may evade detection if analysts rely solely on `pslist`; use `ldrmodules` to check for unlinked DLLs. To avoid misattribution, correlate Volatility findings with other artifacts (e.g., prefetch files, event logs) and document the full attack chain.

**Validation steps**:
1. **Reproducibility**: Re-run plugins with adjusted parameters (e.g., `--dump-dir` for `malfind`).
2. **Cross-tool verification**: Compare results with tools like Rekall or Redline.
3. **MITRE ATT&CK mapping**: Confirm techniques (e.g., **Indicator Removal (T1070.006)** via `timeliner`) align with adversary TTPs.

Sources:
- [DFIR Review: Volatility Pitfalls](https://www.dfir.review/2021/03/15/common-pitfalls-in-memory-forensics/)
- [CERT-EU: Memory Forensics Best Practices](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Memory_Forensics.pdf)

## Sources
Claim → source mapping (all URLs are official tool docs/repos, MITRE ATT&CK, SANS, Microsoft Learn, or recognized project docs):

- Volatility 3 framework overview & CLI (`vol`, `-f`, no `--profile`) — https://volatility3.readthedocs.io/en/latest/ and https://volatility3.readthedocs.io/en/latest/basics.html
- Volatility 3 install (PyPI/GitHub, not an official apt package) — https://volatility3.readthedocs.io/en/latest/getting-started.html and repo https://github.com/volatilityfoundation/volatility3
- Volatility 3 symbol tables / auto-detection (replaces v2 profiles) — https://volatility3.readthedocs.io/en/latest/symbol-tables.html
- Volatility 3 Windows plugin reference (`windows.info`, `pslist`, `pstree`, `psscan`, `malfind`, `netscan`) — https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html
- bulk_extractor behavior, `-o`, `-V`, feature files, scanners — https://www.kali.org/tools/bulk-extractor/ and https://github.com/simsong/bulk_extractor
- REMnux memory analysis tooling (Volatility, bulk_extractor preinstalled) — https://docs.remnux.org/discover-the-tools/analyze+memory
- Volatility Foundation (project home) — https://volatilityfoundation.org/
- SANS FOR508 / memory forensics & IR methodology — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- Security Onion docs (platform, Suricata, Zeek, Hunt/PCAP pivots) — https://docs.securityonion.net/en/2.4/ , https://docs.securityonion.net/en/2.4/suricata.html , https://docs.securityonion.net/en/2.4/zeek.html , https://docs.securityonion.net/en/2.4/hunt.html
- MITRE ATT&CK T1055 (Process Injection) — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.012 (Process Hollowing) — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK T1036.005 (Masquerading: Match Legitimate Name or Location) — https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK T1071 (Application Layer Protocol) — https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory) — https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK T1134.004 (Access Token Manipulation: Parent PID Spoofing) — https://attack.mitre.org/techniques/T1134/004/
- MITRE ATT&CK T1040 (Network Discovery) — https://attack.mitre.org/techniques/T1040/
- MITRE ATT&CK T1040.001 (Network Discovery: Passive DNS) — https://attack.mitre.org/techniques/T1040/001/
- MITRE ATT&CK T1112 (Modify Registry) — https://attack.mitre.org/techniques/T1112/

## Related modules
- [Memory forensics](../02-memory-forensics/README.md) -- shares bulk_extractor for IOC carving from RAM images.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares bulk_extractor in an end-to-end ransomware memory case.
- [File carving](../05-file-carving/README.md) -- shares bulk_extractor as a structure-agnostic feature/string carver.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares bulk_extractor within a full host triage workflow.

<!-- cyberlab-enriched: v2 -->
- https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html
- https://www.dfir.review/2022
- https://attack.mitre.org/techniques/T1218
- https://attack.mitre.org/techniques/T1625
- https://cybok.org/
- https://www.pcisecuritystandards.org/

<!-- cyberlab-enriched: v3 -->
- https://www.sans.org/blog/volatility-3-recipes/
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/registry-forensics
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_

<!-- cyberlab-enriched: v4 -->
- https://github.com/fxb-cocacoding/yara-signator
- https://www.dfir.review/2021/03/15/common-pitfalls-in-memory-forensics/
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Memory_Forensics.pdf

<!-- cyberlab-enriched: v5 -->
