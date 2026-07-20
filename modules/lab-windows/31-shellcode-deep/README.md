# 31 * Shellcode analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a small chunk of raw machine instructions that attackers drop into a running program to take control — it has no file header, no imports, and often no obvious structure, so normal tools cannot open it like a program. This module shows how to make sense of that raw blob safely. `scdbg` pretends to be a tiny Windows computer and "runs" the bytes in an emulator, writing down every Windows API the code tries to call (like "download a file" or "start a process") without ever really executing anything on your machine. `BlobRunner` takes the opposite approach: it loads the blob into memory in a controlled test process and jumps to it, so you can attach a real debugger and watch it live. Together they let an analyst answer "what does this raw shellcode actually do?" without guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | Included in FLARE-VM (`scdbg.exe`) | Emulate 32/64-bit shellcode and log Windows API calls without native execution |
| BlobRunner | Included in FLARE-VM (`BlobRunner.exe` / `BlobRunner64.exe`) | Load a raw shellcode blob into a live process and jump to it for debugger attach |

## Learning objectives
- Emulate a raw shellcode blob with `scdbg` and read the resulting API call trace.
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
Expected output: the `Get-Command` lines print the full path to each executable (e.g. `C:\Tools\scdbg\scdbg.exe`), and `scdbg.exe /?` prints its usage banner listing switches such as `/f`, `/s`, and `/foff`.

## Guided walkthrough
1. Generate a small benign shellcode blob (a harmless "call WinExec / ExitProcess" style stub is not needed — we use an inert byte pattern plus a documented sample). First confirm the sample exists.
```powershell
# The benign sample ships in this module's exercise dir
Get-FileHash .\exercise\sample.bin -Algorithm SHA256
```
Expected output: prints the SHA256 of `sample.bin` matching the value in the Answer key.

2. Emulate the blob with `scdbg` and dump the API trace. `/f` selects the file.
```powershell
scdbg.exe /f .\exercise\sample.bin
```
Expected output: `scdbg` prints an emulation report — a list of executed steps and any simulated Windows API calls (function name, arguments, return). For a NOP-only stub it reports execution reaching the end / an emulation stop without meaningful API calls.

3. If the real entry point is not at offset 0, force a start offset with `/foff`.
```powershell
scdbg.exe /f .\exercise\sample.bin /foff 0x0
```
Expected output: identical trace but confirming the emulator started at the specified file offset (`0x0` here).

4. Prepare the same blob for live analysis. `BlobRunner` maps it and pauses so you can attach x64dbg.
```powershell
BlobRunner.exe -f .\exercise\sample.bin
```
Expected output: `BlobRunner` prints the base address it allocated the buffer at and a prompt like "Press any key to jump to the shellcode..." — leaving a window to attach a debugger and set a breakpoint on the buffer address.

## Hands-on exercise
Analyze the sample artifact `exercise/sample.bin` in this module's `exercise/` directory.

- **Type:** raw 32-bit x86 shellcode blob (no PE header), inert.
- **Safe origin:** benign/inert — the blob is generated locally from NOP padding followed by an `int3` (breakpoint / trap) instruction and `ret`. It performs NO network egress, file writes, or process creation. Regenerate it with the command in the Answer key if it is missing.

Tasks:
1. Compute the SHA256 of `sample.bin` and confirm it matches the Answer key.
2. Run `scdbg` against the blob and record how many API calls the emulator observed.
3. Run `BlobRunner` and record the allocated buffer base address it reports.

## SOC analyst perspective
Defenders rarely receive tidy PE files; shellcode arrives embedded in exploit documents, loader stages, or extracted from memory dumps, so being able to emulate a raw blob is core triage. In Security Onion you often start from a Suricata/Zeek alert on an exploit delivery (e.g. an RTF or a suspicious HTTP object), carve the object with the PCAP, extract the shellcode region, and feed it to `scdbg`. The API trace immediately maps to MITRE ATT&CK behaviors: `URLDownloadToFile` implies T1105 Ingress Tool Transfer, `WinExec`/`CreateProcess` implies T1059 Command and Scripting Interpreter execution, and calls resolving APIs by hash suggest T1027 obfuscation. Those extracted C2 hosts and dropped filenames become IOCs you pivot on across Security Onion's Zeek `conn.log` and `http.log` to scope the incident.

## Attacker perspective
Attackers favor position-independent shellcode precisely because it has no header, no imports table, and can be injected into a benign process — making static signatures and simple file scanning far less effective (T1055 Process Injection, T1027 Obfuscated Files or Information). They frequently resolve API addresses at runtime by walking the PEB and hashing export names, encode the payload with a small XOR/rolling decoder stub, and use egg-hunters to locate a larger stage. Artifacts still leak for defenders: emulation reveals the decoder loop and the eventual API calls, unusual RWX memory regions and unbacked executable pages show up in process memory, and BlobRunner-style live detonation exposes the decoded second stage in the debugger. Sandbox execution also produces network and process telemetry that maps directly back to the shellcode's true intent.

## Answer key
Sample: `exercise/sample.bin`, SHA256 = `9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a`.

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
Expected: hash equals `9f64a747...806a`; `scdbg` reports emulation terminating with no API calls; `BlobRunner` reports a valid heap/virtual base address for the mapped buffer and pauses before jumping.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** (shellcode is the canonical injected payload).
- **T1027 – Obfuscated Files or Information** (encoded/self-decoding shellcode, API hashing).
- **T1059 – Command and Scripting Interpreter** (shellcode spawning execution primitives).
- **T1105 – Ingress Tool Transfer** (download-and-execute shellcode stages).
- **DFIR phase:** Examination / Analysis (malware code analysis of a carved artifact), feeding Identification (IOC extraction).

## Sources
- FLARE-VM package list and tool set — Mandiant/Google FLARE: https://github.com/mandiant/flare-vm
- scdbg (libemu-based shellcode emulator) documentation — David Zimmer / dzzie: http://sandsprite.com/blogs/index.php?uid=7&pid=152
- BlobRunner project (raw shellcode loader for debugger attach) — OALabs: https://github.com/OALabs/BlobRunner
- MITRE ATT&CK techniques T1055, T1027, T1059, T1105: https://attack.mitre.org/techniques/T1055/
- SANS FOR610 Reverse-Engineering Malware (shellcode analysis methodology): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/