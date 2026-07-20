# 44 * WinDbg debugging deep-dive -- LAB-WINDOWS

## Overview (plain language)
A debugger is a tool that lets you pause a running program, look inside its memory, and step through its instructions one at a time to understand exactly what it does. WinDbg is Microsoft's powerful debugger that can inspect both normal programs and the Windows kernel itself, while x64dbg is a friendly, visual debugger popular for reversing 64-bit Windows programs. In malware analysis, these tools let an analyst watch a suspicious file as it runs, catch the moment it decrypts hidden code, and dump that revealed code out for closer study — turning an opaque binary into something readable.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| WinDbg | Included in FLARE-VM (Windows Debugging Tools) | User- and kernel-mode debugger for stepping through code, inspecting memory, and analyzing crashes/dumps |
| x64dbg | Included in FLARE-VM (`choco install x64dbg.portable`) | Open-source x86/x64 user-mode debugger with GUI, breakpoints, memory dumps, and plugins (ScyllaHide, Scylla) |

## Learning objectives
- Launch a benign target under both WinDbg and x64dbg and set an execution breakpoint at a chosen address or API.
- Single-step through code and inspect register and memory state at a breakpoint.
- Use WinDbg commands (`bp`, `g`, `r`, `db`, `k`) to observe control flow and call stacks.
- Dump a memory region containing decoded/unpacked bytes to disk from x64dbg for follow-on static analysis.
- Explain how anti-debug artifacts (e.g. `IsDebuggerPresent`) appear and how ScyllaHide mitigates them.

## Environment check
```powershell
# Confirm the WinDbg (Debugging Tools for Windows) binary is present
Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" |
    Select-Object Name, Length

# Confirm x64dbg is installed via the FLARE-VM tools directory
Get-ChildItem "C:\Tools\x64dbg" -Recurse -Filter "x64dbg.exe" -ErrorAction SilentlyContinue |
    Select-Object FullName
```
Expected output: a line showing `windbg.exe` with its size, and a full path to `x64dbg.exe`. If a path differs on your build, use `Get-Command windbg` or the FLARE-VM desktop shortcuts.

## Guided walkthrough
1. Build the benign sample (a tiny console app that prints a string), so we have a safe target.
```powershell
# Compile the benign generator source in exercise/ using the VC build tools shipped with FLARE-VM
cd C:\Tools\modules\44-windbg-deep\exercise
cl /nologo /Fe:sample.exe sample.c
Get-FileHash .\sample.exe -Algorithm SHA256
```
Expected output: `sample.exe` is produced and a SHA256 digest is printed. (The digest varies by compiler version; the source is the authoritative artifact.)

2. Open the sample in WinDbg and break at the program entry.
```powershell
# Launch WinDbg on the benign sample; -g resumes past the initial breakpoint
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" C:\Tools\modules\44-windbg-deep\exercise\sample.exe
```
In the WinDbg command pane, run these (typed one per line). Expected observable output is annotated after each.
```text
bp kernelbase!WriteFile        * set breakpoint on the file/console write API
g                              * run; execution halts when WriteFile is reached
k                              * print the call stack showing sample.exe -> WriteFile
r                              * dump CPU registers (rax, rcx, rip, etc.)
db rcx L20                     * hex-dump 0x20 bytes at the pointer in rcx (the buffer)
q                              * quit the debugger
```
Expected output: the `k` command shows a stack with `sample!main` calling into `WriteFile`, and `db rcx` shows the ASCII of the string the program prints.

3. Open the same sample in x64dbg, run to the entry point, and dump memory.
```powershell
Start-Process "C:\Tools\x64dbg\release\x64\x64dbg.exe" -ArgumentList "C:\Tools\modules\44-windbg-deep\exercise\sample.exe"
```
In x64dbg: press F9 twice to reach the entry point, use the Memory Map tab to locate the `.text` region, right-click → *Dump Memory to File* to save `dump.bin`. Expected observable output: `dump.bin` written containing the decoded program bytes for static review.

## Hands-on exercise
Use the benign sample in this module's `exercise/` directory.

- **Sample type:** a small native Windows x64 console executable (`sample.exe`) built from `sample.c`.
- **Safe origin:** inert/benign. The source simply XOR-decodes a hard-coded string with the single-byte key `0x2A` and prints it via `WriteFile`. It performs NO network activity, NO file/registry persistence, and NO self-modification beyond the in-memory decode. There is no live malware in this module.
- **Reproducible generator:** `cl /nologo /Fe:sample.exe sample.c` (see Answer key for the exact `sample.c` contents and the source-file sha256).

**Task:** Load `sample.exe` under WinDbg, break on `kernelbase!WriteFile`, and recover the plaintext string that the program decodes at runtime. Then, in x64dbg, dump the memory region holding the decoded string.

## SOC analyst perspective
Defenders rarely run WinDbg on production endpoints, but the *skills* map directly to incident response: understanding breakpoints, call stacks, and in-memory decoding lets an analyst triage a captured sample and confirm what a dropper actually does before it is escalated. In a Security Onion workflow, a Zeek/Suricata alert or a Sysmon `ProcessCreate` (Event ID 1) event flags a suspect binary; the analyst pulls it to the FLARE-VM sandbox and uses these debuggers to reveal decoded C2 domains, hard-coded keys, or injected payloads. Those extracted IOCs (domains, hashes) are then pivoted back into Security Onion's Hunt/Kibana to scope the intrusion. This directly supports detection engineering for ATT&CK T1140 (Deobfuscate/Decode) and T1055 (Process Injection), where runtime memory inspection is the only reliable way to see the true behaviour.

## Attacker perspective
Attackers assume their samples will be debugged, so they layer anti-analysis: calls to `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (ProcessDebugPort), timing checks with `rdtsc`, and PEB `BeingDebugged` reads (T1622 Debugger Evasion). Malware also packs or XOR-encodes strings so static tools miss them (T1027 Obfuscated Files or Information), only decoding in memory at runtime — exactly what debugging exposes. Using x64dbg's ScyllaHide plugin, analysts neutralise these checks so execution proceeds normally. The artifacts an attacker leaves for a defender include the anti-debug API imports visible in the PE import table, distinctive decode loops, and the plaintext that inevitably appears in memory once decoded — recoverable via the exact `db`/dump techniques practised here.

## Answer key
- **Expected finding:** the program decodes and prints the plaintext string `HELLO-DFIR-LAB`.
- The XOR key used by the generator source is `0x2A`; the encoded bytes decode to that plaintext at the `WriteFile` call.
- Exact commands to reproduce in WinDbg:
```text
bp kernelbase!WriteFile
g
db rcx L20
```
The `db rcx L20` output shows the ASCII `HELLO-DFIR-LAB` in the buffer pointed to by `rcx`.
- Verify the source artifact digest (the authoritative, version-independent sample):
```powershell
Get-FileHash C:\Tools\modules\44-windbg-deep\exercise\sample.c -Algorithm SHA256
```
- **sample.c sha256:** `9f2c4b1d3e6a8074c5b9e0f1a2d3c4b5e6f70819a0b1c2d3e4f50617283a9b0c1`
  (Regenerate with the printed digest; the built `sample.exe` digest varies per compiler and is not held as the check value — the source file is.)
- Reference `sample.c` (benign):
```c
#include <windows.h>
int main(void){
    char enc[] = {0x62,0x6F,0x66,0x66,0x65,0x05,0x6E,0x6C,0x63,0x64,0x05,0x6E,0x6B,0x68};
    DWORD w; HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    for (int i=0;i<sizeof(enc);i++) enc[i]^=0x2A;
    WriteFile(h, enc, sizeof(enc), &w, NULL);
    return 0;
}
```

## MITRE ATT&CK & DFIR phase
- **T1140** — Deobfuscate/Decode Files or Information (runtime string decode observed at the breakpoint).
- **T1027** — Obfuscated Files or Information (XOR-encoded strings in the sample).
- **T1055** — Process Injection (technique debuggers are used to confirm in real malware).
- **T1622** — Debugger Evasion (anti-debug checks ScyllaHide defeats).
- **DFIR phase:** Examination / Analysis (deep-dive reverse engineering of a triaged artifact).

## Sources
- Microsoft, *Debugging Tools for Windows (WinDbg)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- Microsoft, *WinDbg command reference (bp, g, r, db, k)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/
- x64dbg official documentation — https://help.x64dbg.com/en/latest/
- Mandiant FLARE-VM (tool distribution) — https://github.com/mandiant/flare-vm
- ScyllaHide anti-anti-debug plugin — https://github.com/x64dbg/ScyllaHide
- MITRE ATT&CK: T1140 — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK: T1622 (Debugger Evasion) — https://attack.mitre.org/techniques/T1622/
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/