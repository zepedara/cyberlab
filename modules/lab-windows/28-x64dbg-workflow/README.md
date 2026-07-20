# 28 * x64dbg unpacking & debugging workflow -- LAB-WINDOWS

## Overview (plain language)
When malware authors want to hide what their program does, they often "pack" or "obfuscate" it — squishing or scrambling the real code so it only appears in memory after the program starts running. A debugger lets an analyst run that program one step at a time, pause it, peek at memory, and grab the real code once it is unpacked. x64dbg is a friendly, open-source debugger for Windows programs (both 32-bit and 64-bit). ScyllaHide is an add-on that hides the debugger so sneaky programs cannot tell they are being watched. WinDbg is Microsoft's official debugger, useful for deeper kernel and crash-dump work. Together they form the core "run it carefully and watch what happens" toolkit for reverse engineers.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | choco install x64dbg (FLARE-VM) | Open-source user-mode debugger for 32/64-bit Windows binaries; step, breakpoint, dump memory |
| ScyllaHide | bundled x64dbg plugin (FLARE-VM) | Anti-anti-debug plugin that masks debugger presence from evasive samples |
| WinDbg | FLARE-VM package | Microsoft debugger for user-mode, kernel-mode, and crash/memory-dump analysis |

## Learning objectives
- Launch a benign target under x64dbg and set breakpoints on common unpacking APIs.
- Enable ScyllaHide and explain which anti-debug checks it neutralizes.
- Identify a probable original entry point (OEP) after an unpacking stub finishes.
- Dump a running process image and rebuild its import table for static follow-up.
- Load a user-mode crash dump in WinDbg and read the faulting call stack.

## Environment check
```powershell
# Confirm the debuggers are present on FLARE-VM
Get-ChildItem "C:\Tools\x64dbg\release\x64\x64dbg.exe" | Select-Object Name, Length
Get-ChildItem "C:\Tools\x64dbg\release\x64\plugins\ScyllaHide.dp64" | Select-Object Name
where.exe windbg.exe
# Expected: x64dbg.exe and ScyllaHide.dp64 listed; windbg.exe path printed
```

## Guided walkthrough
1. Generate the benign packed sample (see Hands-on exercise) and confirm it exists.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\packed_hello.exe
# Expected: prints a SHA256 hex digest for the sample
```

2. Open x64dbg from the command line and load the target for debugging.
```powershell
& "C:\Tools\x64dbg\release\x64\x64dbg.exe" ".\exercise\packed_hello.exe"
# Expected: x64dbg GUI opens, paused at the system/entry breakpoint
```

3. In the x64dbg command bar, set breakpoints on APIs a packer typically calls to allocate and hand off to unpacked code, then run.
```
bp VirtualAlloc
bp VirtualProtect
run
```
Expected observable: execution pauses when the unpacking stub allocates RWX memory; the CPU pane shows the API call and register arguments.

4. Enable ScyllaHide before continuing so evasive checks are neutralized. In the menu choose **Plugins -> ScyllaHide -> Options**, tick the x64dbg profile, then continue. Expected: `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`/`NtQueryInformationProcess` checks now return "no debugger."

5. After the stub finishes, use the built-in Scylla dumper (**Plugins -> Scylla**) at the suspected OEP to dump the process and rebuild imports. Expected: a rebuilt `packed_hello_dump.exe` written to disk.

6. If a target crashes, capture and inspect the dump in WinDbg.
```powershell
& "windbg.exe" -z ".\exercise\hello.dmp"
# Then in the WinDbg command window:
#   !analyze -v
# Expected: faulting module, exception code, and reconstructed call stack
```

## Hands-on exercise
**Sample:** `exercise\packed_hello.exe` — a benign 64-bit console program that prints `Hello from OEP` and is compressed with UPX (inert, no network activity, no persistence). It is safe because it is generated locally from source you control and only calls `printf`.

Build it reproducibly on FLARE-VM (requires VC build tools + UPX, both in the catalog):
```powershell
# 1. Write benign source
Set-Content -Path .\exercise\hello.c -Value @'
#include <stdio.h>
int main(void){ printf("Hello from OEP\n"); return 0; }
'@
# 2. Compile
cl.exe /nologo /Fe:.\exercise\hello_plain.exe .\exercise\hello.c
# 3. Pack a copy with UPX to create the debugging target
Copy-Item .\exercise\hello_plain.exe .\exercise\packed_hello.exe
upx --best .\exercise\packed_hello.exe
```

**Task:** Load `packed_hello.exe` in x64dbg, enable ScyllaHide, break on `VirtualProtect`, reach the OEP, and dump/rebuild the unpacked image. Record the OEP relative address and confirm the dumped binary still prints `Hello from OEP`.

## SOC analyst perspective
A SOC analyst rarely debugs on a production endpoint, but the artifacts of unpacking directly shape detections. Manually unpacking a captured sample in x64dbg yields the *real* code, strings, and C2 indicators that packed static scans miss — those IOCs feed Suricata and YARA rules distributed via Security Onion. Understanding packer behavior (RWX allocation via `VirtualAlloc`/`VirtualProtect`, self-modifying memory) maps to MITRE ATT&CK T1027.002 (Software Packing) and T1055 (Process Injection); analysts can then hunt Sysmon Event ID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) in Security Onion to spot the same technique live. WinDbg dump triage (`!analyze -v`) turns a crashing endpoint into a story: faulting module and stack often reveal the injected or exploited component.

## Attacker perspective
Attackers pack and obfuscate payloads to defeat signature scanners and slow analysis (T1027 / T1027.002), and add anti-debug checks — `IsDebuggerPresent`, `NtQueryInformationProcess`, timing traps, and `NtSetInformationThread` thread-hiding (T1622 Debugger Evasion) — so the sample behaves differently or bails out when watched. ScyllaHide exists precisely to neutralize those checks, letting an analyst reach the original entry point anyway. Offensive tooling itself leaves artifacts: RWX memory regions, unbacked executable memory, decompressed strings in the process heap, and dumped images with rebuilt import tables. Defenders find these via memory scanning (pe-sieve/HollowsHunter), EDR memory-integrity alerts, and Sysmon process-access telemetry.

## Answer key
- Expected OEP: the unpacking stub jumps to the real `main`/CRT startup; in x64dbg it appears as a `jmp` into a lower-address code region after `VirtualProtect` returns. Note the relative virtual address shown in the CPU pane.
- Commands that produce findings:
```
bp VirtualProtect
run
# after the tail jump, use Plugins -> Scylla -> IAT Autosearch -> Get Imports -> Dump -> Fix Dump
```
- Verify the dumped binary is functionally the benign program:
```powershell
& .\exercise\packed_hello_dump.exe
# Expected output: Hello from OEP
```
- Sample integrity: compute the SHA256 of your locally built target and record it in the module log; because it is UPX-packed from your own source the digest is reproducible per build. Confirm it matches after generation:
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\packed_hello.exe | Format-List
# Expected: a single SHA256 hex digest; store this value as the sample's declared hash
```

## MITRE ATT&CK & DFIR phase
- **T1027 / T1027.002** — Obfuscated Files or Information: Software Packing.
- **T1055** — Process Injection (RWX allocation / hand-off patterns observed while debugging).
- **T1622** — Debugger Evasion (anti-debug checks neutralized by ScyllaHide).
- **DFIR phase:** Examination / Analysis (dynamic malware analysis and dump triage), feeding Reporting/Detection-engineering.

## Sources
- FLARE-VM package list and installation — https://github.com/mandiant/flare-vm
- x64dbg official documentation — https://help.x64dbg.com/
- ScyllaHide project (anti-anti-debug plugin) — https://github.com/x64dbg/ScyllaHide
- Microsoft WinDbg / Debugging Tools for Windows — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- SANS FOR610 Reverse-Engineering Malware course — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1027.002 Software Packing — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1622 Debugger Evasion — https://attack.mitre.org/techniques/T1622/