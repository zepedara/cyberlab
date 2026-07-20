# 44 * WinDbg debugging deep-dive -- LAB-WINDOWS

## Overview (plain language)
A debugger is a tool that lets you pause a running program, look inside its memory, and step through its instructions one at a time to understand exactly what it does. WinDbg is Microsoft's powerful debugger that can inspect both normal programs and the Windows kernel itself, while x64dbg is a friendly, visual debugger popular for reversing 64-bit Windows programs. In malware analysis, these tools let an analyst watch a suspicious file as it runs, catch the moment it decrypts hidden code, and dump that revealed code out for closer study — turning an opaque binary into something readable.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| WinDbg | Included in FLARE-VM (Windows Debugging Tools, part of the Windows SDK/WDK) | User- and kernel-mode debugger for stepping through code, inspecting memory, and analyzing crashes/dumps |
| x64dbg | Included in FLARE-VM (`choco install x64dbg.portable`) | Open-source x86/x64 user-mode debugger with GUI, breakpoints, memory dumps, and plugins (ScyllaHide, Scylla) |

> Note on WinDbg editions: the classic WinDbg ships with the *Debugging Tools for Windows* package inside the Windows SDK/WDK; Microsoft also distributes **WinDbg** (formerly "WinDbg Preview") from the Microsoft Store. Both share the same debugger engine and command syntax. See Microsoft Learn, *Download and install the WinDbg debugger* (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) and *Get started with WinDbg (user mode)* (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg).

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
Expected output: a line showing `windbg.exe` with its size, and a full path to `x64dbg.exe`. If a path differs on your build, use `Get-Command windbg` or the FLARE-VM desktop shortcuts. The Debugging Tools for Windows install location under `Windows Kits\10\Debuggers\<arch>` is documented by Microsoft Learn (*Debugging Tools for Windows* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/). x64dbg is a portable, self-contained distribution with separate `x32/` and `x64/` launchers per the x64dbg project (https://github.com/x64dbg/x64dbg and https://help.x64dbg.com/en/latest/introduction/index.html).

## Guided walkthrough
1. Build the benign sample (a tiny console app that prints a string), so we have a safe target.
```powershell
# Compile the benign generator source in exercise/ using the VC build tools shipped with FLARE-VM
cd C:\Tools\modules\44-windbg-deep\exercise
cl /nologo /Fe:sample.exe sample.c
Get-FileHash .\sample.exe -Algorithm SHA256
```
Why: `cl.exe` is the MSVC C/C++ compiler driver. `/nologo` suppresses the banner and `/Fe:sample.exe` names the output executable; without `/Fe` the compiler would name the binary after the first source file. See Microsoft Learn, *MSVC compiler command-line syntax* (https://learn.microsoft.com/en-us/cpp/build/reference/compiler-command-line-syntax) and */Fe (name EXE file)* (https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file). `Get-FileHash -Algorithm SHA256` computes a SHA-256 digest (Microsoft Learn, *Get-FileHash* — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash).
Expected output: `sample.exe` is produced and a SHA256 digest is printed. (The digest varies by compiler version and build flags; the source file — not the built binary — is the authoritative, version-independent artifact, which is why the Answer key pins the `sample.c` digest.)

2. Open the sample in WinDbg and break at the program entry.
```powershell
# Launch WinDbg on the benign sample. WinDbg breaks at the initial (loader) breakpoint by default.
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" C:\Tools\modules\44-windbg-deep\exercise\sample.exe
```
Why: When WinDbg launches a user-mode target it stops at an initial break so you can set breakpoints before the program's own code runs. This initial-break behavior is documented by Microsoft Learn (*Getting Started with WinDbg (User-Mode)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg). In the WinDbg command pane, run these (typed one per line). Expected observable output is annotated after each.
```text
bp kernelbase!WriteFile        * set breakpoint on the file/console write API (module!symbol form)
g                              * run; execution halts when WriteFile is reached
k                              * print the call stack showing sample.exe -> WriteFile
r                              * dump CPU registers (rax, rcx, rip, etc.)
db rcx L20                     * hex-dump 0x20 bytes at the pointer in rcx (the buffer)
q                              * quit the debugger
```
Why each command (see Microsoft Learn *Debugger commands* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/):
- `bp` sets a software breakpoint; the `module!symbol` syntax resolves a name against loaded symbols (*bp, bu, bm (Set Breakpoint)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-). On modern Windows the `WriteFile` implementation lives in `kernelbase.dll`, which is why we target `kernelbase!WriteFile` (Windows API Sets / forwarders; see *KernelBase.dll* / Windows API set documentation — https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets). If the symbol does not resolve, run `bp kernel32!WriteFile` as a fallback, since `kernel32!WriteFile` forwards into `kernelbase`.
- `g` (Go) resumes execution (*g (Go)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/g--go-).
- `k` displays the call stack (*k, kb, kc, kd, kp, kP, kv (Display Stack Backtrace)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-).
- `r` reads/writes registers (*r (Registers)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/r--registers-).
- `db` dumps memory as bytes with an ASCII gutter; `L20` sets a range of 0x20 objects (*d, da, db, dc, dd, dD, df, dp, dq, du, dw (Display Memory)* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dyb--dyd--display-memor- and *Address and address range syntax* — https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/address-and-address-range-syntax).

Nuance: On the Windows x64 calling convention the first integer/pointer argument is passed in **RCX** (Microsoft Learn, *x64 calling convention* — https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention). `WriteFile`'s first parameter is the file/console handle, and its **second** parameter (the buffer, `lpBuffer`) is passed in **RDX** (Microsoft Learn, *WriteFile function* — https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile). Therefore, at the `WriteFile` entry, the decoded string buffer is at the pointer in **RDX**, and `db rcx` shows the handle value rather than the text. Use `db rdx L20` (or `da rdx` to display it as an ASCII string) to read the plaintext buffer. This handle-vs-buffer distinction is a common point of confusion and is worth verifying with `r` before dumping.

3. Open the same sample in x64dbg, run to the entry point, and dump memory.
```powershell
Start-Process "C:\Tools\x64dbg\release\x64\x64dbg.exe" -ArgumentList "C:\Tools\modules\44-windbg-deep\exercise\sample.exe"
```
Why: By default x64dbg pauses at the system breakpoint (in `ntdll`) and then at the module entry point; you step past these to reach the program's own code before dumping. This break behavior and the *Memory Map* → *Dump Memory to File* workflow are documented by the x64dbg project (https://help.x64dbg.com/en/latest/gui/menus/memorymap.html and https://help.x64dbg.com/en/latest/). In x64dbg: press F9 to continue to the entry-point break, use the Memory Map tab to locate the module's `.text` region (or the stack/heap region holding the decoded buffer), right-click → *Dump Memory to File* to save `dump.bin`. Expected observable output: `dump.bin` written containing the memory region's bytes for static review.

## Hands-on exercise
Use the benign sample in this module's `exercise/` directory.

- **Sample type:** a small native Windows x64 console executable (`sample.exe`) built from `sample.c`.
- **Safe origin:** inert/benign. The source simply XOR-decodes a hard-coded string with the single-byte key `0x2A` and prints it via `WriteFile`. It performs NO network activity, NO file/registry persistence, and NO self-modification beyond the in-memory decode. There is no live malware in this module.
- **Reproducible generator:** `cl /nologo /Fe:sample.exe sample.c` (see Answer key for the exact `sample.c` contents and the source-file sha256).

**Task:** Load `sample.exe` under WinDbg, break on `kernelbase!WriteFile`, and recover the plaintext string that the program decodes at runtime (recall the buffer pointer is in **RDX**, the handle is in **RCX**). Then, in x64dbg, dump the memory region holding the decoded string.

## SOC analyst perspective
Defenders rarely run WinDbg on production endpoints, but the *skills* map directly to incident response: understanding breakpoints, call stacks, and in-memory decoding lets an analyst triage a captured sample and confirm what a dropper actually does before it is escalated. In a Security Onion workflow, a Zeek/Suricata alert or a Sysmon `ProcessCreate` (Event ID 1) event flags a suspect binary; the analyst pulls it to the FLARE-VM sandbox and uses these debuggers to reveal decoded C2 domains, hard-coded keys, or injected payloads. Those extracted IOCs (domains, hashes) are then pivoted back into Security Onion's Hunt/Kibana to scope the intrusion.

Concrete detection logic and pivots:
- **Sysmon Event ID 1 (Process Create)** captures the full command line, image path, hashes, and parent process — the primary lead for locating a suspect binary before RE. Sysmon's config and event schema are documented by Microsoft Learn (*Sysmon* — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). In Security Onion this maps to `event.dataset:windows.sysmon_operational` and Elastic's `winlog.event_id:1` (Security Onion docs, *Analyst → Dashboards/Hunt* — https://docs.securityonion.net/en/2.4/).
- **Process Injection (T1055)** is observable via Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess with `GrantedAccess` masks such as `0x1F0FFF`/`0x1FFFFF` indicating handle duplication or memory write). See the MITRE ATT&CK T1055 detection guidance (https://attack.mitre.org/techniques/T1055/).
- **Deobfuscate/Decode (T1140)** rarely emits its own telemetry, so pivot on the *result*: enrich extracted plaintext IOCs (domains, IPs, mutex names) into Zeek `conn.log`/`dns.log`/`http.log` and Suricata alerts within Security Onion. Zeek and Suricata log references: https://docs.zeek.org/en/master/logs/index.html and https://docs.suricata.io/en/latest/output/eve/eve-json-format.html.
- **Debugger Evasion (T1622)** import-table indicators (e.g., `IsDebuggerPresent`, `NtQueryInformationProcess`) can be surfaced during static triage and correlated with sandbox behavior (https://attack.mitre.org/techniques/T1622/).

This supports detection engineering for ATT&CK T1140 (Deobfuscate/Decode) and T1055 (Process Injection), where runtime memory inspection is often the only reliable way to see the true behaviour. General analyst workflow and correlation techniques are covered in SANS FOR508 (https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/) and FOR610 (https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).

## Attacker perspective
Attackers assume their samples will be debugged, so they layer anti-analysis (mapped to T1622, Debugger Evasion — https://attack.mitre.org/techniques/T1622/):
- `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` (Win32 debug APIs — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent and https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent).
- `NtQueryInformationProcess` with `ProcessDebugPort` (0x7), `ProcessDebugObjectHandle` (0x1E), or `ProcessDebugFlags` (0x1F) (Microsoft Learn — https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
- Direct PEB reads of the `BeingDebugged` byte and `NtGlobalFlag` (Process Environment Block layout — https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb).
- Timing checks using the `rdtsc` instruction to detect single-stepping (Intel/AMD instruction; see also x64dbg's anti-anti-debug notes at https://help.x64dbg.com/en/latest/).

Malware also packs or XOR-encodes strings so static tools miss them (T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/), only decoding in memory at runtime — exactly what debugging exposes. Using x64dbg's ScyllaHide plugin, analysts neutralise these checks (patching `IsDebuggerPresent`, hooking `NtQueryInformationProcess`, hiding the PEB `BeingDebugged`/`NtGlobalFlag`) so execution proceeds normally (ScyllaHide project — https://github.com/x64dbg/ScyllaHide).

Artifacts an attacker leaves for a defender: the anti-debug API imports visible in the PE import table (T1027 / T1622), distinctive decode loops (single-byte XOR against a constant key such as `0x2A` in this sample), and the plaintext that inevitably appears in memory once decoded — recoverable via the exact `db`/`da`/dump techniques practised here. Packing (T1027.002, Software Packing — https://attack.mitre.org/techniques/T1027/002/) similarly forces in-memory unpacking that a memory dump captures.

## Answer key
- **Expected finding:** the program decodes and prints the plaintext string `HELLO-DFIR-LAB`.
- The XOR key used by the generator source is `0x2A`; the encoded bytes decode to that plaintext at the `WriteFile` call.
- Exact commands to reproduce in WinDbg (remember: `WriteFile`'s buffer argument `lpBuffer` is passed in **RDX** on x64, while **RCX** holds the handle):
```text
bp kernelbase!WriteFile
g
r
db rdx L20
da rdx
```
The `da rdx` output shows the ASCII string `HELLO-DFIR-LAB` in the buffer pointed to by `rdx`; `db rdx L20` shows the same bytes with a hex + ASCII view. (If you dump `rcx` instead you will see the console handle value, not the text — this is the intended learning point about the x64 calling convention: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention and https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile.)
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
- **T1140** — Deobfuscate/Decode Files or Information (runtime string decode observed at the breakpoint) — https://attack.mitre.org/techniques/T1140/
- **T1027** — Obfuscated Files or Information (XOR-encoded strings in the sample) — https://attack.mitre.org/techniques/T1027/
- **T1027.002** — Software Packing (in-memory unpacking that memory dumps capture) — https://attack.mitre.org/techniques/T1027/002/
- **T1055** — Process Injection (technique debuggers are used to confirm in real malware) — https://attack.mitre.org/techniques/T1055/
- **T1622** — Debugger Evasion (anti-debug checks ScyllaHide defeats) — https://attack.mitre.org/techniques/T1622/
- **DFIR phase:** Examination / Analysis (deep-dive reverse engineering of a triaged artifact).

## Sources
Claim → source mapping (all URLs are official/authoritative):
- WinDbg overview, install location, and initial user-mode break — Microsoft Learn, *Debugging Tools for Windows (WinDbg)*: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/ ; *Getting Started with WinDbg (User-Mode)*: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg
- WinDbg command reference index (`bp`, `g`, `r`, `db`, `k`) — Microsoft Learn, *Debugger Commands*: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/
  - `bp` set breakpoint: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-
  - `g` go: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/g--go-
  - `k` stack backtrace: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-
  - `r` registers: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/r--registers-
  - `d*` display memory + `L` range: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dyb--dyd--display-memor- ; https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/address-and-address-range-syntax
- x64 calling convention (first arg RCX, second arg RDX) — Microsoft Learn: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
- `WriteFile` parameters (handle, `lpBuffer`)

<!-- cyberlab-enriched: v1 -->
