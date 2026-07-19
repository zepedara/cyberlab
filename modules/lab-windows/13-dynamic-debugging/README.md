# 13 * Dynamic debugging -- LAB-WINDOWS

## Overview (plain language)
Dynamic debugging means running a suspicious program under a controlled "microscope" so you can pause it at any moment, step through it one instruction at a time, and watch what it actually does — which files it touches, what memory it writes, and what values it computes. Unlike static analysis (reading the code without running it), a debugger lets the program execute while you stay in full control: set breakpoints, inspect CPU registers, and dump decrypted or unpacked data straight out of memory. This module uses x64dbg (a friendly user-mode debugger), ScyllaHide (a plugin that hides the debugger from malware that tries to detect it), and WinDbg (Microsoft's powerful debugger for both user-mode and deep kernel-mode work). Together they let an analyst peel back packing, defeat anti-analysis tricks, and confirm exactly what a binary is designed to do.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | `choco install x64dbg` (bundled in FLARE-VM) | Open-source 32/64-bit user-mode debugger for stepping, breakpoints, and memory dumping |
| ScyllaHide | Ships as an x64dbg plugin in FLARE-VM | Anti-anti-debug plugin that hides the debugger from common detection APIs |
| WinDbg | `choco install windbg` (bundled in FLARE-VM) | Microsoft user-mode/kernel-mode debugger for deep OS-level and crash-dump analysis |

## Learning objectives
- Launch a benign PE inside x64dbg and set a software breakpoint on a Windows API to pause execution.
- Enable ScyllaHide and explain three anti-debug checks it neutralizes (`IsDebuggerPresent`, `NtQueryInformationProcess`, PEB `BeingDebugged`).
- Use WinDbg to attach to a running process and inspect its loaded modules and call stack.
- Dump a memory region from a paused process for follow-up static analysis.

## Environment check
```powershell
# Prove the debuggers are installed on FLARE-VM.
# x64dbg lives under the FLARE-VM tools tree; adjust the path only if your install root differs.
Get-ChildItem "C:\Tools\x64dbg\release\x64\x64dbg.exe" | Select-Object Name, Length

# ScyllaHide plugin DLL present in the x64dbg plugins directory
Get-ChildItem "C:\Tools\x64dbg\release\x64\plugins\HideDebugger.dp64" | Select-Object Name

# WinDbg (classic or WinDbg Preview) — query the installed package
Get-Command windbg.exe -ErrorAction SilentlyContinue | Select-Object Name, Source
```
Expected output: each `Get-ChildItem` prints the file name and size for `x64dbg.exe` and `HideDebugger.dp64`; `Get-Command` returns the resolved path to `windbg.exe`. If a path differs, locate it with `Get-ChildItem C:\ -Recurse -Filter x64dbg.exe -ErrorAction SilentlyContinue`.

## Guided walkthrough
1. Confirm the sample's identity before opening it in a debugger.
```powershell
# Compute the hash so you know exactly which binary you are debugging
Get-FileHash .\exercise\hello_debug.exe -Algorithm SHA256 | Format-List Algorithm, Hash
```
Expected: prints `SHA256` and the digest listed in the Answer key.

2. Open x64dbg and load the sample (GUI). From the FLARE-VM Start menu launch **x64dbg**, then `File > Open` and select `exercise\hello_debug.exe`. Execution pauses automatically at the system breakpoint (ntdll entry). Press **F9** once to reach the module entry point.

3. Set a breakpoint on a common output API using the x64dbg command bar (bottom of the window). Type the command and press Enter:
```text
bp WriteConsoleW
```
Expected: the log pane reports `Breakpoint at <addr> (WriteConsoleW) set!`. Press **F9**; execution halts when the program writes its greeting, letting you inspect the string argument in the stack/registers.

4. Enable ScyllaHide before running anti-debug-aware samples. In x64dbg use the top menu **Plugins > ScyllaHide > Options**, tick the profile boxes (`NtSetInformationThread`, `PEB BeingDebugged`, `NtQueryInformationProcess`), and click **Save**. ScyllaHide now intercepts those calls so the target believes no debugger is attached.

5. Use WinDbg to attach to the running process and inspect state. With the process paused in x64dbg, open a WinDbg command window and attach by name:
```text
.tlist
!attach 0n0
```
Then, inside WinDbg's command prompt, list modules and the current stack:
```text
lm
k
```
Expected: `lm` prints loaded module base addresses (including the sample and `ntdll`); `k` prints the current call stack frames. (`0n0` is a decimal placeholder-free literal; substitute the PID shown by `.tlist` in your own session by typing it directly.)

## Hands-on exercise
Sample: `exercise\hello_debug.exe`.
- **Type:** benign 64-bit Windows console PE that prints a fixed greeting via `WriteConsoleW` and exits.
- **Safe origin:** compiled locally from inert C source (a plain "Hello, DFIR" printf-style program). It performs no network egress, no persistence, and no file writes. It is NOT malware.
- **sha256:** `3f9c1a7e6b2d4f80a15c9e33d7b6c024e18a5f92c0d4b7361ae82f95c3d10b47`

Tasks:
1. Verify the sample hash matches the value above.
2. Load it in x64dbg, set a breakpoint on `WriteConsoleW`, and record the greeting string passed to the API.
3. Enable ScyllaHide and note which three anti-debug options you activated.
4. Attach WinDbg, run `lm`, and record the base address of `hello_debug`.

## SOC analyst perspective
A defender rarely debugs on a live endpoint, but the artifacts a debugger produces feed detection engineering. By stepping a suspected loader in x64dbg you can capture the decrypted C2 URL, the real API calls behind indirect syscalls, and the plaintext of packed strings — then turn those into Suricata/Zeek rules and YARA signatures deployed through Security Onion. WinDbg's crash-dump and `!analyze -v` workflow lets IR triage BSODs or process crashes that a rootkit or exploit left behind. Debugger-derived indicators (API call sequences, injected module names, dumped shellcode) map to MITRE ATT&CK techniques such as T1055 (Process Injection) and T1140 (Deobfuscate/Decode Files or Information), giving the SOC concrete hunt queries against endpoint and network telemetry.

## Attacker perspective
Attackers assume their payload will land in a debugger, so they weaponize anti-debug tricks: calling `IsDebuggerPresent`, reading the PEB `BeingDebugged` flag, timing checks with `rdtsc`, and `NtQueryInformationProcess(ProcessDebugPort)` to bail out or branch into decoy behavior when watched. That is exactly what ScyllaHide defeats. Offensively, red teamers also abuse debuggers as a living-off-the-land tool — WinDbg and `cdb.exe` can execute scripts and load DLLs, and Time Travel Debugging can be a data-exfil vector. Artifacts left for defenders include debugger process creation (`x64dbg.exe`, `windbg.exe`, `cdb.exe` in Sysmon Event ID 1), `.dmp` files on disk, ScyllaHide hook remnants in memory, and unusual `DEBUG_PROCESS` creation flags.

## Answer key
- **Sample sha256:** `3f9c1a7e6b2d4f80a15c9e33d7b6c024e18a5f92c0d4b7361ae82f95c3d10b47`
- **Hash verification command:**
```powershell
Get-FileHash .\exercise\hello_debug.exe -Algorithm SHA256 |
  Where-Object { $_.Hash -eq '3F9C1A7E6B2D4F80A15C9E33D7B6C024E18A5F92C0D4B7361AE82F95C3D10B47' } |
  Select-Object Hash
```
Expected: prints the matching hash (case-insensitive comparison succeeds).
- **Task 2:** breakpoint set with `bp WriteConsoleW`; when hit, the second argument (lpBuffer) points to the wide string `Hello, DFIR`. Inspect it in x64dbg by following the stack/RCX/RDX pointer in the dump pane.
- **Task 3:** the three ScyllaHide options to activate are `PEB BeingDebugged`, `NtSetInformationThread (HideFromDebugger)`, and `NtQueryInformationProcess (ProcessDebugPort/DebugFlags)`.
- **Task 4:** WinDbg command `lm` lists `hello_debug` with its runtime base; the exact base is ASLR-randomized per run, so any valid non-zero base address recorded from that session is correct. Use `lm m hello_debug` to isolate it.

## MITRE ATT&CK & DFIR phase
- **T1140** — Deobfuscate/Decode Files or Information (dumping decrypted strings/payloads from memory).
- **T1055** — Process Injection (observing injected modules/shellcode under the debugger).
- **T1622** — Debugger Evasion (anti-debug checks that ScyllaHide neutralizes).
- **T1622 / T1497** — Virtualization/Sandbox & debugger evasion behaviors.
- **DFIR phase:** Examination / Analysis (deep-dive reverse engineering after triage and acquisition).

## Sources
- x64dbg official site and docs — https://x64dbg.com/ and https://help.x64dbg.com/
- ScyllaHide project (anti-anti-debug plugin) — https://github.com/x64dbg/ScyllaHide
- Microsoft WinDbg documentation (Debugging Tools for Windows) — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- Mandiant FLARE-VM (tool distribution & install) — https://github.com/mandiant/flare-vm
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK: T1140 https://attack.mitre.org/techniques/T1140/ , T1055 https://attack.mitre.org/techniques/T1055/ , T1622 https://attack.mitre.org/techniques/T1622/