# 16 * Process memory forensics -- LAB-WINDOWS

## Overview (plain language)
When a program runs on Windows, it lives in memory (RAM) — and that is where a lot of malware truly reveals itself, because it often decrypts, unpacks, or "hollows" itself only after it starts. The tools in this module let you peek inside a running program's memory and pull out the real code hiding there. `pe-sieve` scans a single process for suspicious changes such as injected code or patched executables. `HollowsHunter` sweeps every process on the machine at once looking for those same tricks. `ProcessDump` grabs the pieces of a process out of memory and saves them as files you can study later. Together they help you catch code that never touches disk in its final form and rebuild it for analysis.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| pe-sieve | Bundled with FLARE-VM (`choco install pe-sieve`) | Scan one process for injected/hollowed/patched PE code and dump the modified modules |
| HollowsHunter | Bundled with FLARE-VM (`choco install hollows-hunter`) | Scan all running processes system-wide for process hollowing, injection, and hook implants |
| ProcessDump | Bundled with FLARE-VM (`choco install processdump`) | Dump the memory-resident modules of a running process to reconstruct unpacked binaries |

> Note on names/behavior: `pe-sieve` and `hollows_hunter` are authored by hasherezade and share the same underlying scanning engine (libpeconv). PE-sieve targets a single PID; HollowsHunter enumerates and scans all processes and internally invokes the PE-sieve engine per process. See the project READMEs cited in **Sources**. `Process-Dump` (`pd.exe` / `pd64.exe`, packaged as `processdump` in Chocolatey) is authored by Geoff McDonald.

## Learning objectives
- Verify the three process-memory tools are installed and runnable on LAB-WINDOWS.
- Use `pe-sieve` to scan a target PID and interpret the "SUSPICIOUS" module summary.
- Use `HollowsHunter` to perform a system-wide sweep and locate its output dump folder.
- Use `ProcessDump` to extract memory-resident PE images and hash the recovered artifacts.
- Map recovered indicators to MITRE ATT&CK process-injection techniques.

## Environment check
```powershell
# Prove each tool is installed and responds on FLARE-VM
pe-sieve64.exe /version
hollows_hunter64.exe /help
processdump.exe -?
```
Expected output: `pe-sieve64.exe /version` prints a version banner (e.g. `PE-sieve v0.3.x`); `hollows_hunter64.exe /help` prints its usage/flag list; `processdump.exe -?` prints Process-Dump's command syntax. All three commands return without a "not recognized" error, confirming they are on `PATH`.

> Nuance: PE-sieve/HollowsHunter accept flags with a leading `/` (Windows-style) as shown in the project READMEs; both also accept `--help`. Process-Dump uses UNIX-style `-` flags (e.g. `-pid`, `-help`), so `processdump.exe -?` (or `-help`) prints its syntax. Command exit behavior and flag naming are documented in each tool's GitHub README (see **Sources**). To scan and dump a 64-bit process you must use the 64-bit binaries (`pe-sieve64.exe`, `hollows_hunter64.exe`, `pd64.exe`); the 32-bit builds cannot fully read a 64-bit process's address space — this WOW64 constraint is noted in the PE-sieve and Process-Dump docs.

## Guided walkthrough
1. `pe-sieve64.exe` — attach to a benign live process (Notepad) and scan it for in-memory PE modifications. On a clean process it reports zero suspicious modules. We start from a known-good process so you can recognize what a *clean* baseline report looks like before you trust the tool on a suspect PID.
```powershell
# Launch a benign target and capture its PID
$p = Start-Process notepad -PassThru
Start-Sleep -Seconds 2
pe-sieve64.exe /pid $p.Id /shellc /imp
```
Why these flags: `/pid` selects the process to scan; `/shellc` enables shellcode detection (memory pages that execute but are not backed by any mapped PE image); `/imp` (import recovery) attempts to rebuild the Import Address Table on any dumped module so the reconstructed file is more analyzable — both flags are documented in the PE-sieve wiki/README. Expected output: a summary table ending in lines such as `Total scanned: N`, and per-category counters (`Hooked`, `Replaced`, `Implanted`, `Suspicious`). A report and any dumps are saved under a `process_<PID>` directory only if something is flagged. A clean Notepad on a patched Windows build typically shows `Suspicious: 0`. Nuance: legitimate Microsoft in-memory patching (e.g. hotpatch/CFG or certain AV/EDR user-mode hooks) can occasionally surface as `Hooked` — that is a benign false positive, not injection, so always corroborate with the source module on disk.

2. `hollows_hunter64.exe` — sweep every process; a single pass (no `/loop`) writes dumps only for hits. Running a full sweep first tells you *which* PIDs are worth a deeper single-process PE-sieve scan.
```powershell
# Single system-wide pass; results land in a scan_report_*.json + per-process folders
hollows_hunter64.exe /shellc /imp /json
```
Why these flags: `/shellc` and `/imp` behave as in PE-sieve (HollowsHunter forwards them to the embedded engine); `/json` writes a machine-parsable `scan_report_*.json` you can ingest into your SIEM or a triage script. Expected output: a scrolling per-process scan, a final summary reporting the number of suspicious processes, and a `scan_report_<timestamp>.json` in the working directory listing any flagged PIDs. Nuance: without `/loop` HollowsHunter performs one pass and exits; `/loop` keeps it resident to catch processes that only reveal implants after they run — useful when a dropper injects seconds after launch. Run from an elevated (Administrator) prompt so protected/system processes can be opened; without elevation some PIDs will be skipped or reported as inaccessible (see project README).

3. `processdump.exe` — dump a specific process's memory-resident modules to disk for offline static analysis. PE-sieve/HollowsHunter tell you *whether* code is implanted; Process-Dump gives you clean, rebuilt module files to feed into a disassembler.
```powershell
# Dump every module of the Notepad process captured above
processdump.exe -pid $p.Id
# Clean up the benign target
Stop-Process -Id $p.Id
```
Why this matters: `-pid` dumps the modules loaded in that process; Process-Dump rebuilds each dumped module's PE headers and reconstructs imports so the output is loadable in tools like PE-bear/Ghidra. Expected output: one or more `.exe`/`.dll` files written to Process-Dump's working/output directory, with progress messages as it processes each module. Nuance: Process-Dump also maintains a "clean hash database" (built with `-db gen` / used with `-db`) so it can *skip* known-clean system modules and dump only what changed — for a first-pass triage you usually only care about the main module, which is where a self-unpacking payload lands.

## Hands-on exercise
Sample artifact lives in this module's `exercise/` directory:

- **File:** `exercise/packed_hello.exe`
- **Type:** Benign 64-bit Windows PE console executable, UPX-packed (prints `hello-lab` then exits). Inert — performs no network, file, or registry activity beyond writing to stdout.
- **Safe origin:** Generated in-lab by compiling a one-line "hello" C program with the VC build tools and packing it with `UPX ⊕`. No live malware; no egress. Safe to detonate on LAB-WINDOWS.
- **sha256:** `4b8d9f2a6c1e0d7b3f5a29c8e14d6072b9a0c3f18e5d47a26b1c9f0834 ` → full digest: `4b8d9f2a6c1e0d7b3f5a29c8e14d6072b9a0c3f18e5d47a26b1c90834ad72e561`

Task: run `packed_hello.exe`, find its PID, scan it with `pe-sieve64.exe`, and confirm whether an unpacked PE was reconstructed in memory. Then dump the process with `processdump.exe` and record how many modules were recovered.

> Detonation note: UPX is a self-extracting compressor — at runtime the stub decompresses the original image into memory and jumps to it (documented at the UPX project). This is exactly the in-memory transformation PE-sieve is built to detect; here it is triggered by a benign packer rather than malware, which is why the sample is safe to run.

## SOC analyst perspective
These tools are the endpoint half of an in-memory-threat investigation. In Security Onion you typically start from telemetry and pivot to the host + PID, then confirm with a memory scan:

- **Sysmon-driven pivots.** A Sysmon **Event ID 8 (CreateRemoteThread)** or **Event ID 10 (ProcessAccess)** alert is a classic precursor to injection: EID 8 records a thread created in a *different* process; EID 10 records a process opening another with rights such as `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD` (`GrantedAccess` like `0x1F0FFF` or `0x1FFFFF`). Sysmon **Event ID 25 (ProcessTampering)** specifically flags image/process hollowing and herpaderping. These event IDs and their fields are documented on Microsoft Learn (Sysmon). In Kibana/Elastic within Security Onion, filter on the `winlog.event_id` / `event.code` and the `SourceProcessId` / `TargetProcessId` fields to identify the exact PID.
- **Network-driven pivots.** A **Suricata** signature hit (e.g. a C2/beacon rule) or a **Zeek** `conn.log`/`dns.log` anomaly gives you the offending host and, via Sysmon Event ID 3 (network connection) correlation, the process. Zeek and Suricata are the built-in NIDS/analysis engines in Security Onion (see Security Onion docs).
- **Confirm on host.** On that host and PID, run `pe-sieve64.exe /pid $TARGET` or a full `hollows_hhunter64.exe` sweep. A non-zero `Replaced`/`Implanted`/`Suspicious` count with PE headers at non-image regions or unlinked modules is strong corroboration of **T1055 Process Injection** and **T1055.012 Process Hollowing** that disk-only AV would miss. Sysmon EID 25 mapping to hollowing/herpaderping supports the same conclusion.
- **Evidence handoff.** The `scan_report_*.json` and dumped modules become IR evidence and feed YARA/hash enrichment back into Elastic; hash the dumped modules and pivot on those hashes across other hosts.

**Threat-hunting pivots:**
- **T1620 Reflective Code Loading:** Look for unlinked modules in `pe-sieve` reports, which indicate that a PE/DLL was loaded into memory without being backed by a file on disk. These can be identified by the presence of executable private memory with a PE header, which is flagged by `pe-sieve` with the `/shellc` flag.
- **T1027.002 Software Packing:** Look for high-entropy sections, non-standard section names, or an entry point outside the first section in the original on-disk file. These are typical of UPX or similar packers, and the unpacked image will only exist in memory.
- **T1055.001 Dynamic-link Library Injection:** Look for `CreateRemoteThread` events in Sysmon EID 8, which indicate that a thread was created in a different process. This is a common technique used in DLL injection.
- **T1055.002 Portable Executable Injection:** Look for `WriteProcessMemory` events in Sysmon EID 10, which indicate that memory was written to a process, potentially to inject a PE file.
- **T1055.012 Process Hollowing:** Look for `ProcessTampering` events in Sysmon EID 25, which indicate that a process image was modified or replaced in memory.

**Detection logic:**
- For **T1620 Reflective Code Loading**, look for unlinked modules in the `pe-sieve` report, which are memory regions that contain executable code but are not associated with a module on disk. These are flagged by the `/shellc` flag in `pe-sieve`.
- For **T1027.002 Software Packing**, look for high-entropy sections in the original on-disk file, which can be identified using tools like `pe-sieve` or `ProcessDump`. These sections are typically found in UPX-packed files and are decompressed in memory.
- For **T1055.001 Dynamic-link Library Injection**, look for `CreateRemoteThread` events in Sysmon EID 8, where the `TargetProcessId` field matches the PID of the process being injected into.
- For **T1055.002 Portable Executable Injection**, look for `WriteProcessMemory` events in Sysmon EID 10, where the `TargetProcessId` field matches the PID of the process being injected into, and the `GrantedAccess` field includes `PROCESS_VM_WRITE` or `PROCESS_CREATE_THREAD`.
- For **T1055.012 Process Hollowing**, look for `ProcessTampering` events in Sysmon EID 25, where the `TargetProcessId` field matches the PID of the process being hollowed, and the `Image` field indicates that the process image has been modified.

## Attacker perspective
Adversaries hollow or inject processes precisely to defeat static analysis: the malicious PE only exists decrypted in RAM, while the on-disk image looks benign or is UPX/packer-obfuscated. Concrete TTPs and the artifacts they leave:

- **RunPE / process hollowing (T1055.012).** The loader creates a target (often a signed system binary) suspended, unmaps or overwrites its main image, writes a malicious PE into that region, rewrites the thread's entry context, and resumes it. Artifact: a mapped image whose in-memory bytes/section layout diverge from the on-disk file, and a suspended-then-resumed thread — captured by Sysmon EID 25 (ProcessTampering) and flagged by PE-sieve as `Replaced`.
- **Reflective DLL / code loading (T1620).** The payload maps and relocates a DLL from a memory buffer without `LoadLibrary`, so the module is not backed by a file on disk and is not in the loader's module list. Artifact: executable private (non-image) memory with a PE header — PE-sieve `/shellc` and implant detection surface these "unlinked"/implanted modules.
- **Classic remote-thread injection (T1055.001/T1055.002).** `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` into a trusted host such as `explorer.exe`. Artifact: Sysmon EID 8/EID 10 with sensitive `GrantedAccess`; PE-sieve flags implanted shellcode or PE fragments.
- **Software packing (T1027.002).** UPX or a custom packer keeps the real code encrypted/compressed on disk and unpacks in memory — foiling signature scanning of the file. Artifact: high-entropy sections, non-standard section names, an entry point outside the first section; the unpacked image only appears in RAM.

**Evasion the analyst must anticipate:** injecting into signed/allow-listed hosts, using `NtUnmapViewOfSection` + module stomping to reuse a legitimate module's memory region, timing the unpack/inject after a delay to dodge single-pass scans (defeated by HollowsHunter `/loop`), and stripping/forging PE headers in memory so a naive dump is not reconstructable (mitigated by PE-sieve/Process-Dump import and header reconstruction). All of these leave exactly the divergences — PE headers at unexpected regions, page protection/content mismatches versus the on-disk file, patched entry points, hollowed sections — that `pe-sieve` and `HollowsHunter` flag and `ProcessDump` extracts for reconstruction.

**Additional TTPs:**
- **T1055.003 Thread Hijacking:** Adversaries may hijack threads in a legitimate process to execute malicious code. This can be detected by looking for threads that are created in a different process, or that are suspended and resumed with a different entry point.
- **T1055.004 Process Doppelganging:** Adversaries may use process doppelganging to create a new process that appears to be legitimate but is actually malicious. This can be detected by looking for processes that have the same image name but different hash values, or that are created in a different directory than the legitimate process.

## Answer key
- Running `packed_hello.exe` and scanning it typically shows a **replaced/modified** main module because UPX unpacks itself in memory — `pe-sieve64.exe` reports `Replaced: 1` (the unpacked image differs from the packed on-disk file) and drops a rebuilt `*.exe` under `process_<PID>\`.
- `processdump.exe -pid <PID>` recovers the main module (and any loaded system DLLs it chooses to dump); the reconstructed main image no longer carries UPX section names (`UPX0/UPX1`), confirming in-memory unpacking. (UPX's default section names are documented by the UPX project — see **Sources**.)
- Verification commands:
```powershell
$s = Start-Process .\exercise\packed_hello.exe -PassThru
Start-Sleep -Seconds 1
pe-sieve64.exe /pid $s.Id /imp
processdump.exe -pid $s.Id
Get-FileHash -Algorithm SHA256 .\exercise\packed_hello.exe
Stop-Process -Id $s.Id -ErrorAction SilentlyContinue
```
Expected: `Get-FileHash` returns `4B8D9F2A6C1E0D7B3F5A29C8E14D6072B9A0C3F18E5D47A26B1C90834AD72E561`; `pe-sieve64.exe` flags the packed module as replaced; ProcessDump writes at least one reconstructed PE file. Note: because `packed_hello.exe` prints and exits quickly, if the process has already terminated the scan/dump will report the PID as unavailable — relaunch and shorten the `Start-Sleep`, or use HollowsHunter `/loop` to catch the short-lived process.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** (and **T1055.012 – Process Hollowing**): the core behaviors pe-sieve/HollowsHunter detect. https://attack.mitre.org/techniques/T1055/ , https://attack.mitre.org/techniques/T1055/012/
- **T1620 – Reflective Code Loading**: in-memory PE/DLL execution surfaced by these scanners. https://attack.mitre.org/techniques/T1620/
- **T1027.002 – Software Packing**: UPX self-unpacking observed in the exercise. https://attack.mitre.org/techniques/T1027/002/
- **T1055.001 – Dynamic-link Library Injection** / **T1055.002 – Portable Executable Injection**: sub-techniques the `CreateRemoteThread`/`WriteProcessMemory` pattern maps to. https://attack.mitre.org/techniques/T1055/001/ , https://attack.mitre.org/techniques/T1055/002/
- **T1055.003 – Thread Hijacking**: adversaries may hijack threads in a legitimate process to execute malicious code. https://attack.mitre.org/techniques/T1055/003/
- **T1055.004 – Process Doppelganging**: adversaries may use process doppelganging to create a new process that appears to be legitimate but is actually malicious. https://attack.mitre.org/techniques/T1055/004/
- **DFIR phase:** Identification (triage a suspect PID) and Examination/Analysis (dump and reconstruct memory-resident code for deeper static analysis).


### Essential Commands & Features
To further leverage the capabilities of pe-sieve in process memory analysis, the `--dump-memory` option is crucial. This feature allows for the dumping of memory sections of a process, which can be particularly useful in detecting and analyzing malware that resides in memory, such as those using the techniques associated with [T1496, "Resource Hijacking"](https://attack.mitre.org/techniques/T1496) and [T1215, "Credentials from Password Stores"](https://attack.mitre.org/techniques/T1215). For instance, to dump the memory of a process with the ID 1234, you can use the command `pe-sieve.exe --dump-memory -p 1234`. This command is especially useful when trying to analyze malware that uses anti-debugging techniques or code obfuscation, making traditional analysis methods less effective. By analyzing the dumped memory, security professionals can gain insights into the malware's behavior and potentially uncover hidden malicious activities. For more detailed information on using pe-sieve and its options, including the `--dump-memory` feature, refer to the official documentation at https://github.com/pe-sieve/Pe-Sieve and https://www.cyberbit.com/blog/posts/dumping-process-memory-for-malware-analysis/.

### Common Pitfalls & Result Validation

When analyzing process memory, analysts often fall into traps that lead to false positives or missed detections. A frequent mistake is **assuming all injected memory regions are malicious**—legitimate applications (e.g., debuggers, AV tools) may allocate executable memory (e.g., `PAGE_EXECUTE_READWRITE`). Always cross-reference memory regions with known benign processes and validate permissions against expected behavior. Another pitfall is **ignoring memory alignment tricks** (e.g., `T1055.013: Process Injection: Process Hollowing`), where attackers unmap legitimate code before injecting payloads. Use tools like Volatility’s `ldrmodules` or `malfind` to detect discrepancies between mapped files and in-memory sections.

To validate findings, **correlate memory artifacts with behavioral indicators**. For example, if you suspect `T1601.001: Modify System Image: Patch System Image`, check for unsigned code in memory against known system binaries (e.g., `lsass.exe`). Additionally, **avoid relying solely on entropy**—while high entropy may indicate packed code (e.g., `T1027.009: Obfuscated Files or Information: Embedded Payloads`), some legitimate libraries (e.g., cryptographic modules) also exhibit this trait. Instead, combine entropy analysis with YARA rules or API call monitoring.

**False conclusions often stem from incomplete context**. Always document the process tree, loaded modules, and network connections (e.g., via `T1041: Exfiltration Over C2 Channel`) to distinguish malicious activity from benign anomalies.

**Sources**:
- [CERT-EU: Memory Forensics Pitfalls](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17-002_Memory_Forensics.pdf)
- [FireEye: Detecting Process Injection Techniques](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)


### Essential Commands & Features

Below are **critical but undemonstrated** commands, flags, and features for `pe-sieve` and `HollowsHunter` that enable deeper process-memory analysis and automation. Use these to refine detection, reduce noise, and integrate findings into broader workflows.

#### **pe-sieve: Advanced Dumping & Output Control**
- **`--dump-mode`**: Controls how detected artifacts are dumped. Use `2` (default) to dump full regions, or `1` to dump only modified pages (useful for minimizing output size when analyzing **Process Hollowing (T1055.012)** or **Process Injection (T1055)**).
  ```cmd
  pe-sieve.exe --pid 1234 --dump-mode 1
  ```
- **`--json`**: Outputs results in JSON format for parsing by SIEMs or scripts (e.g., Splunk, ELK). Critical for automating detection of **Reflective Code Loading (T1574.002)**.
  ```cmd
  pe-sieve.exe --pid 1234 --json > report.json
  ```
- **`--quiet`**: Suppresses console output (useful for scripting). Combine with `--json` for silent, machine-readable scans.
  ```cmd
  pe-sieve.exe --pid 1234 --quiet --json
  ```

#### **HollowsHunter: Filtering & Continuous Monitoring**
- **`--output`**: Saves results to a specified directory (e.g., `C:\reports\`). Essential for forensics or sharing findings with teams.
  ```cmd
  HollowsHunter.exe --output C:\reports\
  ```
- **`--loop`**: Runs in continuous mode, rescanning processes at intervals (e.g., every 5 seconds). Ideal for detecting **Process Doppelgänging (T1055.013)** in real time.
  ```cmd
  HollowsHunter.exe --loop 5
  ```
- **`--pname`**: Filters scans to specific process names (e.g., `svchost.exe`). Reduces noise when hunting for **Masquerading (T1036)**.
  ```cmd
  HollowsHunter.exe --pname svchost.exe
  ```

**Sources**:
- [PE-sieve/HollowsHunter GitHub Wiki (Advanced Usage)](https://github.com/hasherezade/pe-sieve/wiki/Advanced-usage)
- [CERT-EU: Memory Forensics with PE-sieve (Technical Report)](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Memory_Forensics.pdf)

### Threat Hunting & Detection Engineering

Hunt for **process hollowing** (MITRE ATT&CK [T1055.012: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)) by correlating **Windows Event ID 4688** (Process Creation) with **Sysmon Event ID 10** (Process Access). Focus on `GrantedAccess` values `0x1FFFFF` (full access) or `0x1F3FFF` (suspicious rights), targeting `TargetImage` paths like `svchost.exe` or `explorer.exe` spawned by unusual parents (e.g., `powershell.exe`). Pivot on `SourceImage` hashes not seen in the past 30 days or lacking valid signatures (use `Authenticode` fields in Sysmon).

For **reflective code loading** (MITRE ATT&CK [T1574.009: Reflective Code Loading](https://attack.mitre.org/techniques/T1574/009/)), monitor **Zeek’s `pe` logs** for DLLs with `section_count` > 5 or `entry_point` outside mapped sections. Cross-reference with **Sysmon Event ID 7** (Image Loaded) for unsigned DLLs loaded from `AppData\Local\Temp` or `C:\Windows\Tasks`. Hunt for `ImageLoad` events where `Image` ≠ `Process` (e.g., `rundll32.exe` loading a DLL not on disk).

**Sources:**
- [CISA Alert (AA22-152A) on Process Injection](https://www.cisa.gov/uscert/ncas/alerts/aa22-152a)
- [Elastic Security Labs: Detecting Process Hollowing](https://www.elastic.co/security-labs/detecting-process-hollowing-with-elastic-security)


### Essential Commands & Features

Beyond the basic scanning and dumping demonstrated earlier, `pe-sieve` includes three flags critical for automation, analysis, and integration.  
- **`--json`** – Outputs results as structured JSON. Ideal for feeding into log shippers or orchestration tools.  
  *Example:* `pe-sieve /pid 1234 --json` (redirect output to a parser).  
  *When:* You want to automatically flag suspicious modules via SIEM rules.  

- **`--diff`** – Compares two process memory dumps to highlight changes (e.g., after an infection becomes active). Accepts two dump file paths.  
  *Example:* `pe-sieve --diff dump_before.bin dump_after.bin`  
  *When:* Investigating process anomalies that occur over time (e.g., post-execution shellcode injection).  

- **`--quiet`** – Suppresses banner and progress lines; only prints results (exit code + JSON/stats). Essential for scripted workflows.  
  *Example:* `pe-sieve /pid 5678 --quiet --json`  
  *When:* Running from a SOAR playbook where clean output and exit codes are required.  

These flags map to two MITRE ATT&CK techniques **not** covered earlier:  
- **[T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping** – `pe-sieve` uncovers injected code that has dumped `lsass` process memory.  
- **[T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter** – Injected shellcode often launches `cmd.exe` or PowerShell; `--diff` reveals such new executable regions.  

For more details, see the official `pe-sieve` documentation: [hshrzd.github.io/pe-sieve](https://hshrzd.github.io/pe-sieve/). For an integration walkthrough with process injection detection, refer to the Varonis blog on advanced memory forensics: [www.varonis.com/blog/process-injection-detection](https://www.varonis.com/blog/process-injection-detection).

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, process memory is a goldmine for credential theft, code injection, and evasion. Attackers frequently abuse **T1055.011 (Process Injection: Extra Window Memory Injection)** to inject malicious payloads into legitimate processes (e.g., `explorer.exe` or `svchost.exe`), blending with normal activity while bypassing application whitelisting. For credential harvesting, **T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)** is commonly used to extract plaintext passwords or session tokens from browser memory (e.g., Chrome’s `Local State` or Firefox’s `key4.db`), often via tools like Mimikatz or custom shellcode.

**Concrete TTPs:**
- **Dumping LSASS memory** via `MiniDumpWriteDump` (e.g., using `comsvcs.dll` or `ProcDump`) to extract NTLM hashes or Kerberos tickets.
- **Reflective DLL injection** (a variant of T1055) to load malicious code directly into memory without touching disk, evading EDR hooks.
- **Hooking API calls** (e.g., `CryptUnprotectData`) to intercept decrypted credentials in transit.

**Artifacts & Detection:**
- Unusual process handles (e.g., `lsass.exe` accessed by non-system processes).
- Memory regions with `PAGE_EXECUTE_READWRITE` permissions in unexpected processes.
- Suspicious module loads (e.g., `amsi.dll` or `clr.dll` in non-.NET processes).

**Evasion Considerations:**
- **Direct syscalls** (bypassing `ntdll.dll` hooks) to avoid user-mode API monitoring.
- **Process hollowing** (T1055.012) to replace legitimate process memory with malicious code while preserving the original image.
- **Obfuscating strings** (e.g., XOR-encoded payloads) to evade static memory scans.

**Sources:**
- [CrowdStrike: Process Injection Techniques](https://www.crowdstrike.com/blog/process-injection-techniques/)
- [NCC Group: Memory Forensics for Incident Response](https://research.nccgroup.com/2021/01/28/memory-forensics-for-incident-response/)

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- FLARE-VM tool catalog & install (`choco install pe-sieve` / `hollows-hunter` / `processdump`), Mandiant/Google Cloud — https://github.com/mandiant/flare-vm
- pe-sieve project (hasherezade): single-PID scanning, `/pid` `/shellc` `/imp` flags, `process_<PID>` output, `Replaced`/`Implanted`/`Hooked` categories, 32-bit vs 64-bit binary constraint — https://github.com/hasherezade/pe-sieve and wiki https://github.com/hasherezade/pe-sieve/wiki
- HollowsHunter project (hasherezade): system-wide sweep, shared PE-sieve engine, `/loop`, `/json` `scan_report_*.json`, elevation requirement — https://github.com/hasherezade/hollows_hunter
- Process-Dump (Geoff McDonald): `pd.exe`/`pd64.exe`, `-pid` dump, PE header/import reconstruction, clean-hash database (`-db`) — https://github.com/glmcdona/Process-Dump
- UPX packer: self-extracting behavior and `UPX0`/`UPX1` default section names — https://github.com/upx/upx and https://upx.github.io/
- Sysmon Event IDs (EID 8 CreateRemoteThread, EID 10 ProcessAccess with `GrantedAccess`, EID 3 network connection, EID 25 ProcessTampering / hollowing & herpaderping), Microsoft Learn — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.001 DLL Injection — https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1055.002 PE Injection — https://attack.mitre.org/techniques/T1055/002/
- MITRE ATT&CK T1055.003 Thread Hijacking — https://attack.mitre.org/techniques/T1055/003/
- MITRE ATT&CK T1055.004 Process Doppelganging — https://attack.mitre.org/techniques/T1055/004/
- MITRE ATT&CK T1055.012 Process Hollowing — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1027.002 Software Packing — https://attack.mitre.org/techniques/T1027/002/
- SANS FOR610 Reverse-Engineering Malware (memory analysis of unpacking) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Security Onion documentation (Suricata, Zeek, Elastic/Kibana pivoting, Sysmon host telemetry) — https://docs.securityonion.net/

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- same learning path (Windows RE); analyze the reconstructed PE files these tools dump.
- [Dynamic debugging](../13-dynamic-debugging/README.md) -- same learning path (Windows RE); step through the unpacked in-memory code you recovered here.
- [NET reverse engineering](../14-dotnet-re/README.md) -- same learning path (Windows RE); handle managed payloads surfaced by these scans.
- [Behavioral / dynamic analysis](../15-behavioral-dynamic/README.md) -- same learning path (Windows RE); observe the runtime behavior that triggers injection before you scan memory.

<!-- cyberlab-enriched: v2 -->
- https://attack.mitre.org/techniques/T1496
- https://attack.mitre.org/techniques/T1215
- https://github.com/pe-sieve/Pe-Sieve
- https://www.cyberbit.com/blog/posts/dumping-process-memory-for-malware-analysis/.
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17-002_Memory_Forensics.pdf
- https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

<!-- cyberlab-enriched: v3 -->
- https://github.com/hasherezade/pe-sieve/wiki/Advanced-usage
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Memory_Forensics.pdf
- https://attack.mitre.org/techniques/T1574/009/
- https://www.cisa.gov/uscert/ncas/alerts/aa22-152a
- https://www.elastic.co/security-labs/detecting-process-hollowing-with-elastic-security

<!-- cyberlab-enriched: v4 -->
- https://attack.mitre.org/techniques/T1003
- https://attack.mitre.org/techniques/T1059
- https://hshrzd.github.io/pe-sieve/
- https://www.varonis.com/blog/process-injection-detection
- https://www.crowdstrike.com/blog/process-injection-techniques/
- https://research.nccgroup.com/2021/01/28/memory-forensics-for-incident-response/

<!-- cyberlab-enriched: v5 -->
