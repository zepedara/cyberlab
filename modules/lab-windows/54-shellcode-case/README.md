# 54 * Scenario: shellcode extraction & analysis -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a small chunk of raw machine instructions that attackers inject into a program to make it run their code — it is not a normal `.exe`, just bytes. Because it has no friendly file structure, you cannot just double-click it. Instead, analysts use two kinds of tools: an *emulator* like **scdbg**, which pretends to be a tiny Windows CPU and "runs" the bytes in a safe, fake environment while logging every Windows API the shellcode tries to call, and a *debugger* like **x64dbg**, which lets you load the bytes into memory and step through them instruction by instruction on a real (but controlled) machine. Together they answer: what does this blob actually *do* — download a file, spawn a shell, decode a stage-two payload? This module walks you through extracting shellcode from a benign carrier and analyzing its behavior without ever letting it touch the internet.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | Pre-installed on FLARE-VM (`scdbg.exe`) | Emulates 32-bit shellcode and logs Windows API calls it attempts, without native execution |
| x64dbg | Pre-installed on FLARE-VM (`x64dbg`) | Interactive user-mode debugger to step through shellcode loaded into memory |

## Learning objectives
- Extract a raw shellcode blob from a benign carrier file into a standalone `.bin`.
- Emulate the blob with `scdbg` and enumerate the Windows API calls it resolves and invokes.
- Identify the shellcode's likely intent (e.g., API hashing, `WinExec`, download) from emulation output.
- Load and single-step the same blob in x64dbg to confirm the emulated behavior at the instruction level.

## Environment check
```powershell
# Prove both tools resolve on LAB-WINDOWS (FLARE-VM).
# scdbg prints its usage/version banner when run with no valid input.
scdbg.exe /? 

# x64dbg ships as x64dbg.exe / x32dbg.exe; confirm the launcher is present.
Get-Command x32dbg.exe, x64dbg.exe -ErrorAction SilentlyContinue |
  Select-Object Name, Source
```
Expected output: `scdbg.exe /?` prints an options list (e.g. `/f <file>`, `/foff`, `/s`). `Get-Command` prints one or two rows showing the resolved paths of the debugger executables. If a name is missing, launch it from the FLARE-VM Start-menu shortcut to confirm installation.

## Guided walkthrough
1. Generate a benign, inert 32-bit shellcode sample (a tiny stub that only calls `WinExec("calc.exe")`-style API hashing — see Hands-on for the exact generator). Place it in `exercise/`.
```powershell
# Confirm the sample exists and note its size/hash before analysis.
Get-FileHash .\exercise\sample_shellcode.bin -Algorithm SHA256
```
Expected: prints a SHA256 hash matching the value in the Answer key.

2. Emulate the blob with `scdbg`. The emulator loads the bytes at a virtual base, runs them, and logs each resolved/called API.
```powershell
# /f loads the file as raw shellcode; scdbg auto-detects the entry offset.
scdbg.exe /f .\exercise\sample_shellcode.bin
```
Expected: a call trace such as lines showing `GetProcAddress`, `LoadLibraryA`, and a terminal `WinExec(calc.exe)` (or similar) followed by `Stepcount` summary. This is emulation only — no real process is spawned.

3. Re-run scdbg with an explicit start offset and API report if auto-detect misses the entry.
```powershell
# /foff sets a file offset for the entry point; /s <n> caps the step count.
scdbg.exe /f .\exercise\sample_shellcode.bin /foff 0 /s 2000000
```
Expected: same API trace; `/s` prevents runaway loops from hanging the emulator.

4. Load the blob in x64dbg for instruction-level confirmation. In the GUI: `File > Open`, pick `sample_shellcode.bin` (open as raw is done via a small loader stub, or drop the bytes into a scratch process's memory and set EIP). Set a breakpoint on `kernel32!WinExec` and run.
```powershell
# Launch the 32-bit debugger; the rest is GUI-driven.
x32dbg.exe
```
Expected: execution halts at the `WinExec` breakpoint; the stack shows a pointer to the `calc.exe` string, confirming scdbg's finding.

## Hands-on exercise
Analyze the sample in this module's `exercise/` directory.

- **Sample type:** raw 32-bit x86 shellcode blob, `exercise/sample_shellcode.bin`.
- **Safe origin:** benign/inert. It is generated locally by the reproducible NASM command below. It contains only API-hashing stubs that resolve and call `WinExec` against the string `calc.exe`; it performs **no network egress** and does not persist. Run analysis under scdbg emulation first (never a real native run against untrusted bytes).
- **Reproducible generator** (uses NASM from the catalog; produces the exact bytes hashed in the Answer key):
```powershell
# Build the benign shellcode from source in exercise/ using NASM (FLARE-VM).
nasm -f bin .\exercise\sample_shellcode.asm -o .\exercise\sample_shellcode.bin
Get-FileHash .\exercise\sample_shellcode.bin -Algorithm SHA256
```
Where `exercise/sample_shellcode.asm` is a WinExec("calc.exe") stub using PEB-walk API resolution.

**Tasks:**
1. Report the sample's SHA256.
2. List every Windows API `scdbg` observes being resolved/called.
3. State the shellcode's intent in one sentence.
4. Confirm the `WinExec` argument string in x64dbg.

## SOC analyst perspective
In an incident, shellcode rarely arrives as a neat file — it is carved from packet captures, office-document macros, or memory dumps of an injected process. A defender uses `scdbg` to triage such carved blobs quickly: the API trace reveals C2 URLs, spawned processes, or staging behavior without running live malware. In Security Onion, Suricata/Zeek alerts on the delivery (e.g., an HTTP object flagged by a YARA/ET rule) give you the raw bytes to extract; the scdbg trace then maps directly to MITRE ATT&CK techniques like Process Injection (T1055) and Native API abuse (T1106). x64dbg confirms exact behavior when emulation is incomplete, and its findings feed detection engineering — new host or network signatures for the resolved APIs and strings.

## Attacker perspective
Attackers favor position-independent shellcode because it runs anywhere in memory and sidesteps disk-based AV that keys on PE structure. Techniques like PEB-walk API resolution and API hashing (T1027 obfuscation) hide `LoadLibrary`/`GetProcAddress` and function names from static scanners, so a naive `strings` finds nothing. Stagers commonly resolve `WinExec`, `CreateProcess`, or download-and-exec calls (T1105). Yet the shellcode still leaves artifacts: the injected memory region is often `RWX`, the resolved API sequence is observable in an API monitor, spawned child processes show anomalous parentage, and the decoded strings and network callbacks surface under emulation — exactly what scdbg and x64dbg expose.

## Answer key
- **Sample SHA256:** produced deterministically by the NASM generator above; obtain the learner's value with:
```powershell
Get-FileHash .\exercise\sample_shellcode.bin -Algorithm SHA256 |
  Select-Object -ExpandProperty Hash
```
- **APIs observed under scdbg** (task 2): `LoadLibraryA` (or kernel32 resolution via PEB walk), `GetProcAddress`, and `WinExec`.
```powershell
scdbg.exe /f .\exercise\sample_shellcode.bin
```
Expected trace ends with a `WinExec(calc.exe)`-style line and a step-count summary.
- **Intent** (task 3): the shellcode resolves kernel32 APIs via PEB/hashing and executes a local command (`calc.exe`) — a benign proof-of-concept of a process-launch stager.
- **x64dbg confirmation** (task 4): break on `kernel32!WinExec`; the first stacked argument points to the ASCII string `calc.exe`.

## MITRE ATT&CK & DFIR phase
- **T1055 — Process Injection** (shellcode is the injectable payload).
- **T1106 — Native API** (direct Windows API invocation, e.g., WinExec).
- **T1027 — Obfuscated Files or Information** (API hashing / PEB-walk resolution).
- **T1105 — Ingress Tool Transfer** (staging variants that download follow-on payloads).
- **DFIR phase:** Examination / Analysis (reverse engineering and behavioral triage of extracted artifacts).

## Sources
- Mandiant / FLARE-VM installer & tooling: https://github.com/mandiant/flare-vm
- scdbg (dependency of the Didier Stevens shellcode workflow) — REMnux/FLARE shellcode analysis notes: https://docs.remnux.org/discover-the-tools/analyze+code/emulate+code
- x64dbg documentation: https://help.x64dbg.com/en/latest/
- NASM manual: https://www.nasm.us/docs.php
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1106 Native API: https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- SANS FOR610 Reverse-Engineering Malware (shellcode analysis): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/