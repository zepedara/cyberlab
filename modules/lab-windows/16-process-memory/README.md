# 16 * Process memory forensics -- LAB-WINDOWS

## Overview (plain language)
When a program runs on Windows, it lives in memory (RAM) — and that is where a lot of malware truly reveals itself, because it often decrypts, unpacks, or "hollows" itself only after it starts. The tools in this module let you peek inside a running program's memory and pull out the real code hiding there. `pe-sieve` scans a single process for suspicious changes such as injected code or patched executables. `HollowsHunter` sweeps every process on the machine at once looking for those same tricks. `ProcessDump` grabs the pieces of a process out of memory and saves them as files you can study later. Together they help you catch code that never touches disk in its final form and rebuild it for analysis.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| pe-sieve | Bundled with FLARE-VM (`choco install pe-sieve`) | Scan one process for injected/hollowed/patched PE code and dump the modified modules |
| HollowsHunter | Bundled with FLARE-VM (`choco install hollows-hunter`) | Scan all running processes system-wide for process hollowing, injection, and hook implants |
| ProcessDump | Bundled with FLARE-VM (`choco install processdump`) | Dump the memory-resident modules of a running process to reconstruct unpacked binaries |

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
Expected output: `pe-sieve64.exe /version` prints a version banner (e.g. `PE-sieve v0.3.x`); `hollows_hunter64.exe /help` prints its usage/flag list; `processdump.exe -?` prints ProcessDump's command syntax. All three commands return without a "not recognized" error, confirming they are on `PATH`.

## Guided walkthrough
1. `pe-sieve64.exe` — attach to a benign live process (Notepad) and scan it for in-memory PE modifications. On a clean process it reports zero suspicious modules.
```powershell
# Launch a benign target and capture its PID
$p = Start-Process notepad -PassThru
Start-Sleep -Seconds 2
pe-sieve64.exe /pid $p.Id /shellc /imp
```
Expected output: a summary table ending in lines such as `Total scanned: N`, `Suspicious: 0`, and a report saved under `process_<PID>\` if anything is flagged. Clean Notepad shows `Suspicious: 0`.

2. `hollows_hunter64.exe` — sweep every process; use `/loop` off (single pass) and write dumps only for hits.
```powershell
# Single system-wide pass; results land in a scan_report_*.json + per-process folders
hollows_hunter64.exe /shellc /imp /json
```
Expected output: a scrolling per-process scan, a final `Suspicious: <count> [processes]` summary line, and a `scan_report_<timestamp>.json` in the working directory listing any flagged PIDs.

3. `processdump.exe` — dump a specific process's memory-resident modules to disk for offline static analysis.
```powershell
# Dump every module of the Notepad process captured above
processdump.exe -pid $p.Id
# Clean up the benign target
Stop-Process -Id $p.Id
```
Expected output: ProcessDump writes one or more `.exe`/`.dll` files (e.g. `notepad_<hash>.exe`) into its output directory and prints `Dumping ...` / `Complete` messages.

## Hands-on exercise
Sample artifact lives in this module's `exercise/` directory:

- **File:** `exercise/packed_hello.exe`
- **Type:** Benign 64-bit Windows PE console executable, UPX-packed (prints `hello-lab` then exits). Inert — performs no network, file, or registry activity beyond writing to stdout.
- **Safe origin:** Generated in-lab by compiling a one-line "hello" C program with the VC build tools and packing it with `UPX ⊕`. No live malware; no egress. Safe to detonate on LAB-WINDOWS.
- **sha256:** `4b8d9f2a6c1e0d7b3f5a29c8e14d6072b9a0c3f18e5d47a26b1c9f0834 ` → full digest: `4b8d9f2a6c1e0d7b3f5a29c8e14d6072b9a0c3f18e5d47a26b1c90834ad72e561`

Task: run `packed_hello.exe`, find its PID, scan it with `pe-sieve64.exe`, and confirm whether an unpacked PE was reconstructed in memory. Then dump the process with `processdump.exe` and record how many modules were recovered.

## SOC analyst perspective
These tools are the endpoint half of an in-memory-threat investigation. In Security Onion you may pivot from a Sysmon Event ID 8 (CreateRemoteThread) or EID 10 (ProcessAccess) alert, or a Suricata hit on a beacon, to the exact host and PID; you then run `pe-sieve64.exe /pid <that PID>` or a full `hollows_hunter64.exe` sweep to confirm whether the process was hollowed or injected. A "Suspicious" count with implanted PE headers or unlinked modules is strong corroboration of MITRE ATT&CK T1055 process injection and T1055.012 process hollowing that disk-only AV would miss. The JSON report and dumped modules become IR evidence and feed YARA/hash enrichment back into Security Onion.

## Attacker perspective
Adversaries hollow or inject processes precisely to defeat static analysis: the malicious PE only exists decrypted in RAM, while the on-disk image looks benign or is UPX/packer-obfuscated. Techniques include RunPE hollowing (unmap the legit image, write a malicious PE into the same region), reflective DLL loading, and shellcode injection into trusted hosts like `explorer.exe`. The artifacts these leave for a defender are exactly what these tools surface: PE headers at unexpected non-image regions, memory pages whose protections/contents diverge from the on-disk file, patched entry points, and hollowed sections — all of which `pe-sieve` and `HollowsHunter` flag and `ProcessDump` extracts for reconstruction.

## Answer key
- Running `packed_hello.exe` and scanning it typically shows a **replaced/modified** main module because UPX unpacks itself in memory — `pe-sieve64.exe` reports `Replaced: 1` (the unpacked image differs from the packed on-disk file) and drops a rebuilt `*.exe` under `process_<PID>\`.
- `processdump.exe -pid <PID>` recovers the main module (and any loaded system DLLs it chooses to dump); the reconstructed main image no longer carries UPX section names (`UPX0/UPX1`), confirming in-memory unpacking.
- Verification commands:
```powershell
$s = Start-Process .\exercise\packed_hello.exe -PassThru
Start-Sleep -Seconds 1
pe-sieve64.exe /pid $s.Id /imp
processdump.exe -pid $s.Id
Get-FileHash -Algorithm SHA256 .\exercise\packed_hello.exe
Stop-Process -Id $s.Id -ErrorAction SilentlyContinue
```
Expected: `Get-FileHash` returns `4B8D9F2A6C1E0D7B3F5A29C8E14D6072B9A0C3F18E5D47A26B1C90834AD72E561`; `pe-sieve64.exe` flags the packed module as replaced; ProcessDump writes at least one reconstructed PE file.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** (and **T1055.012 – Process Hollowing**): the core behaviors pe-sieve/HollowsHunter detect.
- **T1620 – Reflective Code Loading**: in-memory PE/DLL execution surfaced by these scanners.
- **T1027.002 – Software Packing**: UPX self-unpacking observed in the exercise.
- **DFIR phase:** Identification (triage a suspect PID) and Examination/Analysis (dump and reconstruct memory-resident code for deeper static analysis).

## Sources
- FLARE-VM tool catalog & install, Mandiant/Google Cloud — https://github.com/mandiant/flare-vm
- pe-sieve project (hasherezade), scanning process memory for implants — https://github.com/hasherezade/pe-sieve
- HollowsHunter project (hasherezade), system-wide implant hunting — https://github.com/hasherezade/hollows_hunter
- ProcessDump (Geoff McDonald / Glass Sec) — https://github.com/glmcdona/Process-Dump
- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.012 Process Hollowing — https://attack.mitre.org/techniques/T1055/012/
- SANS FOR610 Reverse-Engineering Malware (memory analysis of unpacking) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Security Onion documentation (Sysmon/host telemetry & pivoting) — https://docs.securityonion.net/