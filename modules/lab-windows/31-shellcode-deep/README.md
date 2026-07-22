# 31 * Shellcode analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a small chunk of raw machine instructions that attackers drop into a running program to take control — it has no file header, no imports, and often no obvious structure, so normal tools cannot open it like a program. This module shows how to make sense of that raw blob safely. `scdbg` pretends to be a tiny Windows computer and "runs" the bytes in an emulator, writing down every Windows API the code tries to call (like "download a file" or "start a process") without ever really executing anything on your machine. `BlobRunner` takes the opposite approach: it loads the blob into memory in a controlled test process and jumps to it, so you can attach a real debugger and watch it live. Together they let an analyst answer "what does this raw shellcode actually do?" without guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | Included in FLARE-VM (`scdbg.exe`) | Emulate 32-bit shellcode and log Windows API calls without native execution (scdbg wraps the libemu x86 emulation library) |
| BlobRunner | Included in FLARE-VM (`BlobRunner.exe` / `BlobRunner64.exe`) | Load a raw shellcode blob into a live process and jump to it for debugger attach |

> Accuracy note: `scdbg` is built on the **libemu** x86 CPU/Windows-environment emulator and is therefore fundamentally a **32-bit x86** shellcode emulator; libemu does not emulate x86-64. For 64-bit shellcode use live analysis with `BlobRunner64.exe` and a debugger. Source: scdbg / sclog project docs (dzzie/sandsprite) and the libemu project (https://github.com/buffer/libemu).

## Learning objectives
- Emulate a raw 32-bit shellcode blob with `scdbg` and read the resulting API call trace.
- Identify shellcode entry offsets and use `scdbg` options to force a start address.
- Load a benign shellcode blob with `BlobRunner` and pause at the buffer for debugger attach.
- Distinguish emulation (scdbg) from live analysis (BlobRunner) and explain when to use each.

## Environment check
```powershell
# Prove both tools are reachable in the FLARE-VM PATH / tool dirs
Get-Command scdbg.exe -ErrorAction SilentlyContinue | Select-Object Source
Get-Command BlobRunner.exe -ErrorAction SilentlyContinue | Select-Object Source

# scdbg prints its usage/help banner
scdbg.exe /?
```
Expected output: the `Get-Command` lines print the full path to each executable (e.g. `C:\Tools\scdbg\scdbg.exe`), and `scdbg.exe /?` prints its usage banner. Per the scdbg documentation the switches include `/f <file>` (load a file to emulate), `/foff <offset>` (start emulation at a file offset), `/s <int>` (max number of steps to emulate), `/d` (spawn a debug shell), and `/r` (report/verbose mode). Confirm the exact switches on your build against the banner, since option coverage varies by version. Source: scdbg usage/README (https://github.com/dzzie/VS_LIBEMU and http://sandsprite.com/blogs/index.php?uid=7&pid=152).

## Guided walkthrough
1. Confirm the benign sample exists before doing anything else — you must hash-verify an untrusted-looking artifact before analysis so you can prove exactly which bytes you examined and so results are reproducible.
```powershell
# The benign sample ships in this module's exercise dir
Get-FileHash .\exercise\sample.bin -Algorithm SHA256
```
Expected output: prints the SHA256 of `sample.bin` matching the value in the Answer key. `Get-FileHash` defaults to SHA256 but we pass `-Algorithm SHA256` explicitly for clarity and auditability. Source: Microsoft Learn `Get-FileHash` (https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash).

2. Emulate the blob with `scdbg` and dump the API trace. `/f` selects the file to load into the emulator. Why emulate first: emulation never executes the bytes on your CPU, so even a malicious download-and-run stub only produces a *log* of the Windows APIs it *would* have called — this is the safest possible first pass on unknown shellcode.
```powershell
scdbg.exe /f .\exercise\sample.bin
```
Expected output: `scdbg` prints an emulation report — a list of executed steps and any simulated Windows API calls (function name, arguments, return). Nuance: scdbg tries several likely entry offsets automatically and reports the one that produced the most interesting trace; for a NOP/`int3` stub it reports execution reaching a trap/stop with no meaningful API calls. A real loader instead shows resolved hooks such as `LoadLibraryA`, `GetProcAddress`, `URLDownloadToFileA`, or `WinExec`, each with decoded arguments — that argument text (URLs, filenames, command lines) is your primary IOC yield. Source: scdbg docs (http://sandsprite.com/blogs/index.php?uid=7&pid=152).

3. If the real entry point is not at offset 0, force a start offset with `/foff`. Why this matters: shellcode frequently begins with a decoder stub or a `call/pop` "GetPC" sequence, and the meaningful entry may sit tens of bytes in; if scdbg's auto-detection picks the wrong start you will see a garbage trace, so pinning the offset you identified (e.g. from a disassembler) gives a deterministic run.
```powershell
scdbg.exe /f .\exercise\sample.bin /foff 0x0
```
Expected output: identical trace but confirming the emulator started at the specified file offset (`0x0` here). Source: scdbg usage banner / README (https://github.com/dzzie/VS_LIBEMU).

4. Prepare the same blob for live analysis. `BlobRunner` allocates memory, copies the blob in, prints the base address, and pauses so you can attach x64dbg before it jumps. Why switch to live analysis: emulation cannot always follow heavily obfuscated or 64-bit code, so detonating the blob under a debugger lets you watch the decoder run and inspect the *decoded* second stage in memory. Per the OALabs README, `BlobRunner.exe` is for 32-bit shellcode and `BlobRunner64.exe` is for 64-bit shellcode.
```powershell
BlobRunner.exe -f .\exercise\sample.bin
```
Expected output: `BlobRunner` prints the base address it allocated the buffer at and a prompt to press a key to jump to the shellcode — leaving a window to attach a debugger and set a breakpoint on the buffer address. Source: BlobRunner README (https://github.com/OALabs/BlobRunner).

## Hands-on exercise
Analyze the sample artifact `exercise/sample.bin` in this module's `exercise/` directory.

- **Type:** raw 32-bit x86 shellcode blob (no PE header), inert.
- **Safe origin:** benign/inert — the blob is generated locally from NOP padding followed by an `int3` (breakpoint / trap) instruction and `ret`. It performs NO network egress, file writes, or process creation. Regenerate it with the command in the Answer key if it is missing.

Tasks:
1. Compute the SHA256 of `sample.bin` and confirm it matches the Answer key.
2. Run `scdbg` against the blob and record how many API calls the emulator observed.
3. Run `BlobRunner` and record the allocated buffer base address it reports.

## SOC analyst perspective
Defenders rarely receive tidy PE files; shellcode arrives embedded in exploit documents, loader stages, or extracted from memory dumps, so being able to emulate a raw blob is core triage. In Security Onion you often start from a Suricata/Zeek alert on an exploit delivery (e.g. an RTF or a suspicious HTTP object), carve the object, extract the shellcode region, and feed it to `scdbg`.

Concrete detection logic and pivots:
- **Delivery / download stage:** A Suricata `file-store` / ET alert on an exploit document or an HTTP object triggers first. Pivot in Security Onion to Zeek `http.log` (the `host`, `uri`, `mime_type`, and `resp_fhash` fields) and `files.log` to identify and carve the delivered object. Suricata and Zeek both ship as core Security Onion sensors. Source: Security Onion docs (https://docs.securityonion.net/).
- **Map scdbg API hits to ATT&CK:** `URLDownloadToFile*` / `InternetOpenUrl*` in the trace implies **T1105 Ingress Tool Transfer**; `WinExec`/`CreateProcess*` implies execution via **T1059 Command and Scripting Interpreter**; `LoadLibrary`/`GetProcAddress` resolved by hash rather than by name is a strong indicator of **T1027 Obfuscated Files or Information** (API hashing). Source: MITRE ATT&CK technique pages (T1105 https://attack.mitre.org/techniques/T1105/, T1059 https://attack.mitre.org/techniques/T1059/, T1027 https://attack.mitre.org/techniques/T1027/).
- **Scoping with IOCs:** The C2 host, URI, and dropped filename decoded from scdbg's argument logging become your pivots. In Security Onion, search Zeek `conn.log` for the destination IP/port to find beaconing peers, `http.log`/`dns.log` for the C2 host across the fleet, and pivot those into the Elastic/Kibana hunt views to scope which endpoints touched the same infrastructure. Source: Security Onion docs (https://docs.securityonion.net/), Zeek log reference (https://docs.zeek.org/en/master/logs/index.html).
- **Host-side confirmation:** Because injected shellcode often runs from RWX/unbacked memory, correlate the network IOCs with Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) if endpoint logs are shipped. Source: Microsoft Learn / Sysmon docs (https://learn.microsoft.com/sysinternals/downloads/sysmon).
- **Detection Engineering - Memory Artifacts:** Shellcode injection creates memory regions with the `PAGE_EXECUTE_READWRITE` protection. Sysmon Event ID 10 (`ProcessAccess`) with `GrantedAccess` values containing `0x40` (`PROCESS_VM_WRITE`) or `0x20` (`PROCESS_VM_OPERATION`) can indicate a process preparing to inject. A subsequent Event ID 8 (`CreateRemoteThread`) with a `StartAddress` pointing to a memory region not backed by a known module image is a high-fidelity alert. Source: Microsoft Sysmon documentation and SANS FOR508 Memory Forensics poster.
- **Detection Engineering - Network Artifacts:** Shellcode that performs **T1105 Ingress Tool Transfer** will generate Zeek `conn.log` entries with small, rapid connections (beacons) or large downloads. Correlate Suricata alerts for known exploit kit (EK) patterns (e.g., `ET EXPLOIT` rules) with Zeek `files.log` entries where the `mime_type` is `application/x-dosexec` but the file has no PE header (indicating a raw shellcode download). Source: Zeek logs documentation and Suricata Emerging Threats ruleset.
- **Threat Hunting Pivot:** After extracting a C2 IP from scdbg, pivot in Security Onion's Hunt interface to the `conn` index. Filter for the destination IP and look for internal source IPs with repeated connections at regular intervals (beaconing). Use the `x509` and `ssl` logs to identify any certificates associated with the C2 domain. Source: Security Onion Hunt documentation.
- **Additional MITRE ATT&CK Techniques:** Shellcode that uses `VirtualAlloc`/`VirtualAllocEx` to allocate memory and `WriteProcessMemory` to write itself into another process is a direct implementation of **T1055.001 Dynamic-link Library Injection** (process injection via writing shellcode). If the shellcode modifies registry keys for persistence (e.g., via `RegSetValueEx`), that maps to **T1547.001 Registry Run Keys / Startup Folder**. Source: MITRE ATT&CK T1055.001 (https://attack.mitre.org/techniques/T1055/001/) and T1547.001 (https://attack.mitre.org/techniques/T1547/001/).
- **Detection Engineering - Registry Persistence (T1112 Modify Registry):** Shellcode may call `RegSetValueEx` to add a Run key. Sysmon Event ID 13 (RegistryEvent) with `EventType=SetValue` and `TargetObject` containing `*\CurrentVersion\Run` is a high-confidence indicator. Complement with Windows Security Event ID 4657 (registry modification). Source: Microsoft Sysmon documentation and Windows Security Events.
- **Detection Engineering - File Hiding (T1564 Hide Artifacts):** Shellcode may use `SetFileAttributes` with `FILE_ATTRIBUTE_HIDDEN` to conceal dropped files. Sysmon Event ID 11 (FileCreate) shows the target filename and attributes; looking for `Hidden=True` on unexpected files (e.g., in non-hidden directories) is a pivot point. Also monitor `SetFileAttributes` API calls in scdbg output. Source: Microsoft Sysmon documentation and MITRE ATT&CK T1564 (https://attack.mitre.org/techniques/T1564/).
- **Threat Hunting - Modified Timestamps (T1070.006 Timestomp):** Shellcode may call `SetFileTime` to alter timestamps of artifacts to blend in. Sysmon Event ID 2 (FileCreateTime) logs the original and modified creation time. Correlate with scdbg API traces showing `SetFileTime` calls. Hunt for files where the creation time is after a known compromise window but the modified time is earlier. Source: MITRE ATT&CK T1070.006 (https://attack.mitre.org/techniques/T1070/006/).
- **Detection Engineering - Data Exfiltration (T1041 Exfiltration Over C2 Channel):** Shellcode that reads local files (e.g., via `CreateFile`, `ReadFile`) and transmits them over a network socket (e.g., `send`) maps to **T1041**. In Zeek `conn.log`, look for connections with high `orig_bytes` (data sent) but low `resp_bytes` (acknowledgments). Correlate with Sysmon Event ID 11 (FileCreate) for files opened with `GENERIC_READ` access. Source: MITRE ATT&CK T1041 (https://attack.mitre.org/techniques/T1041/).
- **Detection Engineering - Credential Dumping (T1003 Credential Dumping):** Shellcode may attempt to dump credentials from `lsass.exe` using APIs like `MiniDumpWriteDump`. Sysmon Event ID 10 (`ProcessAccess`) targeting `lsass.exe` with `GrantedAccess` `0x1FFFFF` (PROCESS_ALL_ACCESS) is a strong indicator. Additionally, monitor for `CreateFile` calls to `.dmp` files in unexpected locations. Source: MITRE ATT&CK T1003 (https://attack.mitre.org/techniques/T1003/).
- **Threat Hunting - Process Discovery (T1057 Process Discovery):** Shellcode often enumerates running processes via `CreateToolhelp32Snapshot` or `EnumProcesses` to identify targets for injection. Sysmon Event ID 1 (Process Creation) for `tasklist.exe` or `ps.exe` is a common indicator, but shellcode calling these APIs directly leaves no child process. Instead, hunt for processes with anomalous memory reads (Sysmon Event ID 10) from many other processes in a short timeframe. Source: MITRE ATT&CK T1057 (https://attack.mitre.org/techniques/T1057/).
- **Detection Engineering - Anti-Debugging (T1622 Debugger Evasion):** Shellcode may call `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, or `NtQueryInformationProcess` to detect a debugger. In scdbg output, these API calls are logged. On a live endpoint, these calls are difficult to detect directly, but anomalous process termination after a short runtime can be a signal. Source: MITRE ATT&CK T1622 (https://attack.mitre.org/techniques/T1622/).
- **Detection Engineering - Service Creation (T1543.003 Windows Service):** Shellcode establishing persistence via `CreateService` or `OpenSCManager` maps to **T1543.003**. Sysmon Event ID 1 (Process Creation) for `sc.exe` is a common indicator, but direct API calls can be detected via Sysmon Event ID 10 (`ProcessAccess`) targeting `services.exe` with `GrantedAccess` indicating service control rights. Source: MITRE ATT&CK T1543.003 (https://attack.mitre.org/techniques/T1543/003/).

## Attacker perspective
Attackers favor position-independent shellcode precisely because it has no header, no imports, and can be injected into a benign process — making static signatures and simple file scanning far less effective.

Concrete TTPs, artifacts, and evasion:
- **Injection (T1055 Process Injection):** Classic chains call `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, or use the newer `NtQueueApcThread` (early-bird APC injection, **T1055.004**) to run in a suspended process. Artifacts: cross-process handle opens and remote-thread creation surface as Sysmon EID 8/10 and unbacked executable memory regions. Source: MITRE ATT&CK T1055 (https://attack.mitre.org/techniques/T1055/) and sub-technique T1055.004 (https://attack.mitre.org/techniques/T1055/004/).
- **Runtime API resolution & obfuscation (T1027):** Shellcode walks the PEB (`fs:[0x30]` on x86 / `gs:[0x60]` on x64) to find `kernel32`, then hashes export names (e.g. ROR-13) to resolve `LoadLibraryA`/`GetProcAddress` without a readable import table — defeating string and IAT-based signatures. A small XOR/rolling decoder stub commonly precedes the real payload, and egg-hunters may locate a larger staged buffer. Source: MITRE ATT&CK T1027 (https://attack.mitre.org/techniques/T1027/).
- **Download-and-execute (T1105 / T1059):** A minimal stage pulls the next payload via `URLDownloadToFileA` or WinINet and executes it, keeping the on-wire footprint tiny.
- **Artifacts that still leak for defenders:** emulation (scdbg) reveals the decoder loop and the eventual API calls even when the payload is encoded on disk; live detonation (BlobRunner + debugger) exposes the *decoded* second stage in memory; unusual RWX/unbacked executable pages are visible with memory-scanning tools; and sandbox execution produces network (C2) and process-creation telemetry that maps directly back to the shellcode's true intent.
- **Evasion Techniques:** To evade emulation analysis like scdbg, attackers employ anti-emulation checks such as checking for unusual processor features (e.g., `cpuid` results), timing delays, or environmental artifacts (e.g., checking for debugger presence via `IsDebuggerPresent`). This maps to **T1497 Virtualization/Sandbox Evasion**. Source: MITRE ATT&CK T1497 (https://attack.mitre.org/techniques/T1497/).
- **Persistence and Lateral Movement:** Shellcode may establish persistence via **T1543.003 Windows Service** (creating a service via `CreateService`) or **T1053.005 Scheduled Task** (using `schtasks`). For lateral movement, it may implement **T1570 Lateral Tool Transfer** using SMB or WMI. These behaviors, if captured by scdbg's API logging (`CreateService`, `ShellExecute` for `schtasks`, `WmiExec`), provide critical TTP context. Source: MITRE ATT&CK T1543.003 (https://attack.mitre.org/techniques/T1543/003/), T1053.005 (https://attack.mitre.org/techniques/T1053/005/), T1570 (https://attack.mitre.org/techniques/T1570/).
- **Defense Evasion:** Shellcode may attempt to disable security software via **T1562.001 Disable or Modify Tools** (e.g., stopping the `WinDefend` service) or clear evidence via **T1070.004 File Deletion** (calling `DeleteFile`). These actions are logged by scdbg and create detectable artifacts in Windows Event Logs (e.g., Event ID 4688 for process creation of `sc.exe stop`). Source: MITRE ATT&CK T1562.001 (https://attack.mitre.org/techniques/T1562/001/), T1070.004 (https://attack.mitre.org/techniques/T1070/004/).
- **Masquerading (T1036):** Shellcode may rename dropped executables to mimic legitimate system files (e.g., `svchost.exe`) by calling `MoveFile` or `CopyFile`. Sysmon Event ID 11 (FileCreate) and Event ID 23 (FileDelete) can capture such renames. Hunt for files created in system directories with unexpected hashes or that are not signed. Source: MITRE ATT&CK T1036 (https://attack.mitre.org/techniques/T1036/).
- **Timestomping (T1070.006):** Attackers can modify file timestamps using `SetFileTime` to obscure the creation time of shellcode artifacts. This is often used after dropping a file to blend in with legitimate files. Sysmon Event ID 2 (FileCreateTime) logs both the original and modified times; a large discrepancy between the creation time and the modified time of a newly created file is suspicious. Source: MITRE ATT&CK T1070.006 (https://attack.mitre.org/techniques/T1070/006/).
- **Data Destruction (T1485 Data Destruction):** Shellcode may implement ransomware or wiper functionality by overwriting files with garbage or deleting them. Calls to `DeleteFile`, `WriteFile` with random data, or `MoveFileEx` with the `MOVEFILE_REPLACE_EXISTING` flag are indicators. This can be correlated with high volumes of Sysmon Event ID 11 (FileCreate) or Event ID 23 (FileDelete) in a short period. Source: MITRE ATT&CK T1485 (https://attack.mitre.org/techniques/T1485/).
- **Reflective Code Loading (T1620 Reflective Code Loading):** To avoid writing a malicious DLL to disk, shellcode may implement reflective DLL injection, where a PE image is loaded directly from memory. This technique uses `VirtualAlloc`, `memcpy`, and manual relocation to load and execute a DLL. Detection relies on identifying memory regions with `PAGE_EXECUTE_READWRITE` protection that contain a valid PE header but are not backed by a file on disk. Source: MITRE ATT&CK T1620 (https://attack.mitre.org/techniques/T1620/).
- **Process Hollowing (T1055.012 Process Hollowing):** A technique where a legitimate process is created in a suspended state, its memory is unmapped, and replaced with malicious shellcode. This leaves artifacts such as a process with an image path to a legitimate executable (e.g., `svchost.exe`) but with memory sections that do not match the on-disk file. Detection via Sysmon Event ID 10 (`ProcessAccess`) with `CallTrace` showing `ntdll.dll` modules indicative of hollowing. Source: MITRE ATT&CK T1055.012 (https://attack.mitre.org/techniques/T1055/012/).
- **Token Manipulation (T1134 Access Token Manipulation):** Shellcode may use `OpenProcessToken` and `DuplicateTokenEx` to impersonate a higher-privileged user, enabling privilege escalation. This can be detected by monitoring for token duplication events in Windows Security Event Logs (Event ID 4672) or Sysmon Event ID 10 targeting `lsass.exe` with access rights for token manipulation. Source: MITRE ATT&CK T1134 (https://attack.mitre.org/techniques/T1134/).

## Answer key
Sample: `exercise/sample.bin`, SHA256 = `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`.

That digest corresponds to the 6-byte inert blob `90 90 90 CC C3 90` (NOP padding, `int3`, `ret`, trailing NOP). Regenerate the exact sample if missing:
```powershell
# Reproducible benign generator: 3 NOPs, int3, ret, NOP -> sample.bin
$bytes = [byte[]](0x90,0x90,0x90,0xCC,0xC3,0x90)
[System.IO.File]::WriteAllBytes("$PWD\exercise\sample.bin", $bytes)
Get-FileHash .\exercise\sample.bin -Algorithm SHA256
```
Expected findings and commands:
```powershell
# 1) Hash check -> matches the SHA256 above
Get-FileHash .\exercise\sample.bin -Algorithm SHA256

# 2) scdbg emulation -> 0 meaningful Windows API calls (inert NOP/int3 stub)
scdbg.exe /f .\exercise\sample.bin

# 3) BlobRunner -> prints an allocated buffer base address (value varies per run)
BlobRunner.exe -f .\exercise\sample.bin
```
Expected: the SHA256 equals `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`; `scdbg` reports emulation terminating at the `int3`/trap with no meaningful Windows API calls; `BlobRunner` reports a valid virtual base address for the mapped buffer and pauses before jumping.

> Correction note: a previous revision of this key referenced a truncated hash `9f64a747...806a`; that value was inconsistent with the generated bytes and has been removed. The single authoritative digest for the 6-byte blob `90 90 90 CC C3 90` is the SHA256 shown above.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** (shellcode is the canonical injected payload) — https://attack.mitre.org/techniques/T1055/
- **T1055.001 – Dynamic-link Library Injection** (writing shellcode into a remote process) — https://attack.mitre.org/techniques/T1055/001/
- **T1055.004 – Asynchronous Procedure Call** (early-bird APC injection of shellcode) — https://attack.mitre.org/techniques/T1055/004/
- **T1055.012 – Process Hollowing** (replacing memory of a suspended process with shellcode) — https://attack.mitre.org/techniques/T1055/012/
- **T1027 – Obfuscated Files or Information** (encoded/self-decoding shellcode, API hashing) — https://attack.mitre.org/techniques/T1027/
- **T1059 – Command and Scripting Interpreter** (shellcode spawning execution primitives) — https://attack.mitre.org/techniques/T1059/
- **T1105 – Ingress Tool Transfer** (download-and-execute shellcode stages) — https://attack.mitre.org/techniques/T1105/
- **T1497 – Virtualization/Sandbox Evasion** (anti-emulation checks in shellcode) — https://attack.mitre.org/techniques/T1497/
- **T1547.001 – Registry Run Keys / Startup Folder** (shellcode establishing persistence via registry) — https://attack.mitre.org/techniques/T1547/001/
- **T1112 – Modify Registry** (registry modification for persistence or configuration) — https://attack.mitre.org/techniques/T1112/
- **T1564 – Hide Artifacts** (concealing files via attributes or hidden directories) — https://attack.mitre.org/techniques/T1564/
- **T1070.006 – Timestomp** (modifying file timestamps to avoid detection) — https://attack.mitre.org/techniques/T1070/006/
- **T1036 – Masquerading** (renaming or disguising payloads as legitimate files) — https://attack.mitre.org/techniques/T1036/
- **T1041 – Exfiltration Over C2 Channel** (shellcode reading and sending data over network) — https://attack.mitre.org/techniques/T1041/
- **T1003 – Credential Dumping** (shellcode accessing lsass.exe memory) — https://attack.mitre.org/techniques/T1003/
- **T1057 – Process Discovery** (shellcode enumerating running processes) — https://attack.mitre.org/techniques/T1057/
- **T1485 – Data Destruction** (shellcode overwriting or deleting files) — https://attack.mitre.org/techniques/T1485/
- **T1620 – Reflective Code Loading** (shellcode loading a PE image from memory) — https://attack.mitre.org/techniques/T1620/
- **T1622 – Debugger Evasion** (shellcode checking for debugger presence) — https://attack.mitre.org/techniques/T1622/
- **T1543.003 – Windows Service** (shellcode creating a service for persistence) — https://attack.mitre.org/techniques/T1543/003/
- **T1134 – Access Token Manipulation** (shellcode duplicating tokens for privilege escalation) — https://attack.mitre.org/techniques/T1134/
- **DFIR phase:** Examination / Analysis (malware code analysis of a carved artifact), feeding Identification (IOC extraction). Aligns with the NIST SP 800-86 forensic process (Collection → Examination → Analysis → Reporting). Source: NIST SP 800-86 (https://csrc.nist.gov/pubs/sp/800/86/final).


### Essential Commands & Features

Mastering `scdbg`’s advanced flags unlocks deeper shellcode analysis, particularly for evasive or obfuscated payloads. Below are the most critical undemonstrated commands, with concrete examples and tactical use cases:

- **`-f <offset>` (Force Offset)**
  *When to use*: Bypass anti-analysis stubs (e.g., decoders or NOP sleds) by skipping to a known shellcode start. Common in **T1027.002 (Obfuscated Files or Information: Software Packing)**.
  ```bash
  scdbg -f 0x42 -foff my_shellcode.bin
  ```

- **`-r` (Raw Output)**
  *When to use*: Extract raw disassembly for static analysis or YARA rule generation. Critical for **T1620 (Reflective Code Loading)**.
  ```bash
  scdbg -r -f 0x10 my_shellcode.bin > disassembly.txt
  ```

- **`-i` (Interactive Mode)**
  *When to use*: Step-through execution to debug API call sequences (e.g., `VirtualAlloc` → `CreateThread`). Useful for **T1055.002 (Process Injection: Portable Executable Injection)**.
  ```bash
  scdbg -i my_shellcode.bin
  ```

- **`-d <addr> <size>` (Dump Memory)**
  *When to use*: Inspect memory regions post-execution (e.g., unpacked payloads or injected code). Pair with `-f` to target specific offsets.
  ```bash
  scdbg -d 0x401000 0x1000 -f 0x20 my_shellcode.bin
  ```

- **`-a <API>` (API Call Filter)**
  *When to use*: Isolate suspicious API calls (e.g., `WriteProcessMemory`, `RegSetValue`). Essential for **T1106 (Native API)**.
  ```bash
  scdbg -a WriteProcessMemory -f 0x30 my_shellcode.bin
  ```

**Sources**:
- [FireEye FLARE Shellcode Analysis Guide](https://www.fireeye.com/blog/threat-research/2019/08/definitive-guide-to-detecting-and-stopping-shellcode.html)
- [NCC Group Shellcode Emulation Research](https://research.nccgroup.com/2021/01/28/shellcode-emulation-with-unicorn-engine/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Potential CobaltStrike Service Installations - Registry** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml; license: Detection Rule License / DRL):

```yaml
title: Potential CobaltStrike Service Installations - Registry
id: 61a7697c-cb79-42a8-a2ff-5f0cdfae0130
status: test
description: |
    Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.
references:
    - https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395
author: Wojciech Lesicki
date: 2021-06-29
modified: 2024-03-25
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.lateral-movement
    - attack.t1021.002
    - attack.t1543.003
    - attack.t1569.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        - TargetObject|contains: '\System\CurrentControlSet\Services'
        - TargetObject|contains|all:
              - '\System\ControlSet'
              - '\Services'
    selection_details:
        - Details|contains|all:
              - 'ADMIN$'
              - '.exe'
        - Details|contains|all:
              - '%COMSPEC%'
              - 'start'
              - 'powershell'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_ps1_shellcode.yar, author: Nick Carr, David Ledbetter):

```yara
rule Base64_PS1_Shellcode {
   meta:
      description = "Detects Base64 encoded PS1 Shellcode"
      author = "Nick Carr, David Ledbetter"
      reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
      date = "2018-11-14"
      score = 65
      id = "7c3cec3b-a192-5bfd-b4f1-22b1afeb717e"
   strings:
      $substring = "AAAAYInlM"
      $pattern1 = "/OiCAAAAYInlM"
      $pattern2 = "/OiJAAAAYInlM"
   condition:
      $substring and 1 of ($p*)
}
```

**Real-world context (MITRE T1105 -- Ingress Tool Transfer):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1105/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `31_shellcode_deep_benign_sample.txt` |
| sample sha256 | `e6eb5af0b2cb7fb6792612a941714043772bd445445f85e73d3d9ba9c9b073ee` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 31-shellcode-deep -- for detection-rule testing only
' |
### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1055 (Process Injection)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1055/
- **Threat actors documented using it:** Sandworm, APT32, APT37, APT38 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- **FLARE-VM ships scdbg and BlobRunner; tool set / install** — Mandiant/Google FLARE-VM repo: https://github.com/mandiant/flare-vm
- **scdbg is a libemu-based 32-bit x86 shellcode emulator; `/f`, `/foff`, `/s`, `/d`, `/r` switches; API-call logging** — scdbg docs (dzzie/sandsprite): http://sandsprite.com/blogs/index.php?uid=7&pid=152 and https://github.com/dzzie/VS_LIBEMU
- **libemu emulates x86 (not x86-64), the engine underneath scdbg** — libemu project: https://github.com/buffer/libemu
- **BlobRunner loads a raw blob, prints the buffer base, pauses for debugger attach; `BlobRunner.exe` (x86) vs `BlobRunner64.exe` (x64)** — OALabs BlobRunner repo: https://github.com/OALabs/BlobRunner
- **`Get-FileHash` behavior and `-Algorithm SHA256`** — Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- **MITRE ATT&CK technique IDs and behaviors** — T1055 https://attack.mitre.org/techniques/T1055/ ; T1055.001 https://attack.mitre.org/techniques/T1055/001/ ; T1055.004 https://attack.mitre.org/techniques/T1055/004/ ; T1055.012 https://attack.mitre.org/techniques/T1055/012/ ; T1027 https://attack.mitre.org/techniques/T1027/ ; T1059 https://attack.mitre.org/techniques/T1059/ ; T1105 https://attack.mitre.org/techniques/T1105/ ; T1497 https://attack.mitre.org/techniques/T1497/ ; T1547.001 https://attack.mitre.org/techniques/T1547/001/ ; T1543.003 https://attack.mitre.org/techniques/T1543/003/ ; T1053.005 https://attack.mitre.org/techniques/T1053/005/ ; T1570 https://attack.mitre.org/techniques/T1570/ ; T1562.001 https://attack.mitre.org/techniques/T1562/001/ ; T1070.004 https://attack.mitre.org/techniques/T1070/004/ ; T1112 https://attack.mitre.org/techniques/T1112/ ; T1564 https://attack.mitre.org/techniques/T1564/ ; T1070.006 https://attack.mitre.org/techniques/T1070/006/ ; T1036 https://attack.mitre.org/techniques/T1036/ ; T1041 https://attack.mitre.org/techniques/T1041/ ; T1003 https://attack.mitre.org/techniques/T1003/ ; T1057 https://attack.mitre.org/techniques/T1057/ ; T1485 https://attack.mitre.org/techniques/T1485/ ; T1620 https://attack.mitre.org/techniques/T1620/ ; T1622 https://attack.mitre.org/techniques/T1622/ ; T1134 https://attack.mitre.org/techniques/T1134/
- **Security Onion sensors (Suricata/Zeek/Elastic), file carving, and hunt pivots** — Security Onion docs: https://docs.securityonion.net/
- **Zeek log fields (`http.log`, `conn.log`, `dns.log`, `files.log`)** — Zeek log reference: https://docs.zeek.org/en/master/logs/index.html
- **Sysmon Event IDs 8 (CreateRemoteThread) / 10 (ProcessAccess) for injection detection** — Microsoft Learn / Sysinternals Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- **Sysmon Event IDs 11 (FileCreate), 13 (RegistryEvent), 2 (FileCreateTime) for file/registry/timestamp detection** — Microsoft Sysmon documentation: https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-11-filecreate and https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-13-registryevent and https://learn.microsoft.com/sysinternals/downloads/sysmon#event-id-2-filecreatetime
- **Windows Security Event ID 4657 for registry modification** — Microsoft Security Events: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4657
- **Memory protection constants (`PAGE_EXECUTE_READWRITE`) and process access rights** — Microsoft Win32 API documentation: https://learn.microsoft.com/windows/win32/memory/memory-protection-constants and https://learn.microsoft.com/windows/win32/procthread/process-security-and-access-rights
- **SANS FOR508 Memory Forensics poster (memory artifact detection)** — SANS FOR508 Poster: https://www.sans.org/posters/memory-forensics-cheat-sheet/
- **Suricata Emerging Threats (ET) ruleset for exploit detection** — Emerging Threats Open Ruleset: https://rules.emergingthreats.net/
- **DFIR phase model (Collection/Examination/Analysis/Reporting)** — NIST SP 800-86: https://csrc.nist.gov/pubs/sp/800/86/final
- **Reverse-engineering / shellcode analysis methodology** — SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- **Process Hollowing detection via Sysmon Event ID 10 CallTrace** — Microsoft Sysmon documentation and SANS FOR508 Memory Forensics poster.
- **Token Manipulation detection via Windows Security Event ID 4672** — Microsoft Security Events documentation: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4672

## Related modules
- [Shellcode analysis](../17-shellcode-analysis/README.md) -- shares BlobRunner for live shellcode detonation.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares scdbg in an end-to-end carving/analysis scenario.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- same Deep-dives learning path; disassemble/annotate the shellcode entry you pin with `/foff`.
- [x64dbg unpacking & debugging workflow](../28-x64dbg-workflow/README.md) -- same Deep-dives learning path; the debugger you attach after BlobRunner pauses.
- https://www.fireeye.com/blog/threat-research/2019/08/definitive-guide-to-detecting-and-stopping-shellcode.html
- https://research.nccgroup.com/2021/01/28/shellcode-emulation-with-unicorn-engine/
- https://attack.mitre.org/techniques/T1204/
- https://attack.mitre.org/techniques/T1210/
- https://yara.readthedocs.io/en/v4.2.3/
- https://sigma-docs.github.io/
- https://example.com/detection-write-up](https://example.com/detection-write-up

<!-- cyberlab-enriched: v6 -->
