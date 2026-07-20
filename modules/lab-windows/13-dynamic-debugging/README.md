# 13 * Dynamic debugging -- LAB-WINDOWS

## Overview (plain language)
Dynamic debugging means running a suspicious program under a controlled "microscope" so you can pause it at any moment, step through it one instruction at a time, and watch what it actually does — which files it touches, what memory it writes, and what values it computes. Unlike static analysis (reading the code without running it), a debugger lets the program execute while you stay in full control: set breakpoints, inspect CPU registers, and dump decrypted or unpacked data straight out of memory. This module uses x64dbg (a friendly user-mode debugger), ScyllaHide (a plugin that hides the debugger from malware that tries to detect it), and WinDbg (Microsoft's powerful debugger for both user-mode and deep kernel-mode work). Together they let an analyst peel back packing, defeat anti-analysis tricks, and confirm exactly what a binary is designed to do. x64dbg is an open-source x64/x32 debugger for Windows (see https://x64dbg.com/); WinDbg is part of Microsoft's Debugging Tools for Windows (see https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | `choco install x64dbg` (bundled in FLARE-VM) | Open-source 32/64-bit user-mode debugger for stepping, breakpoints, and memory dumping (https://x64dbg.com/) |
| ScyllaHide | Ships as an x64dbg plugin in FLARE-VM | Anti-anti-debug plugin that hides the debugger from common detection APIs (https://github.com/x64dbg/ScyllaHide) |
| WinDbg | `choco install windbg` (bundled in FLARE-VM) | Microsoft user-mode/kernel-mode debugger for deep OS-level and crash-dump analysis (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) |

Note: FLARE-VM installs these tools via its Chocolatey-based package set; consult the FLARE-VM repository for the authoritative tool list and install layout (https://github.com/mandiant/flare-vm).

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

Note on filenames: x64dbg's 64-bit plugins use the `.dp64` extension and 32-bit plugins use `.dp32` (see the x64dbg plugin SDK/docs at https://help.x64dbg.com/en/latest/developers/plugins/index.html). ScyllaHide's x64dbg plugin build is documented in its repository (https://github.com/x64dbg/ScyllaHide); if the DLL name differs in your build, enumerate the `plugins` folder to confirm the exact file present.

## Guided walkthrough
1. Confirm the sample's identity before opening it in a debugger. Hashing first guarantees you are debugging the exact binary named in the Answer key and gives you an immutable identifier to record in case notes and IOC trackers.
```powershell
# Compute the hash so you know exactly which binary you are debugging
Get-FileHash .\exercise\hello_debug.exe -Algorithm SHA256 | Format-List Algorithm, Hash
```
Expected: prints `SHA256` and the digest listed in the Answer key. `Get-FileHash` is a built-in PowerShell cmdlet that defaults to SHA256 (documented at https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash).

2. Open x64dbg and load the sample (GUI). From the FLARE-VM Start menu launch **x64dbg**, then `File > Open` and select `exercise\hello_debug.exe`. By default x64dbg first breaks at the system breakpoint (inside `ntdll`), which is the loader's initialization point before your program's own code runs — this lets you configure breakpoints before any target code executes. Press **F9** (Run) to continue to the module entry point. The system/entry breakpoint behavior and default event settings are configurable under **Options > Preferences** (see https://help.x64dbg.com/en/latest/gui/menus/options/Preferences.html).

3. Set a breakpoint on a common output API using the x64dbg command bar (bottom of the window). We break on `WriteConsoleW` because a console program must call it (via the Windows API) to display Unicode text, so it is a reliable choke point to catch the greeting and read its arguments straight from the stack/registers. Type the command and press Enter:
```text
bp WriteConsoleW
```
Expected: the log pane reports that a breakpoint at the resolved address of `WriteConsoleW` was set. `bp` sets a software (INT3) breakpoint; x64dbg resolves the exported API name to its runtime address (see the command reference at https://help.x64dbg.com/en/latest/commands/breakpoints/bp.html). Press **F9**; execution halts when the program writes its greeting. On x64 Windows the calling convention passes the first four integer/pointer arguments in RCX, RDX, R8, R9 (see https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention), so `WriteConsoleW`'s second parameter `lpBuffer` (the wide string) is in RDX at the call boundary — follow RDX in the dump pane to read it.

4. Enable ScyllaHide before running anti-debug-aware samples. In x64dbg use the top menu **Plugins > ScyllaHide > Options**, tick the profile boxes (`NtSetInformationThread`, `PEB BeingDebugged`, `NtQueryInformationProcess`), and click the profile save/apply control. ScyllaHide hooks these routines so the target's anti-debug probes return "no debugger present." The specific hooks and options are documented in the ScyllaHide repository and usage docs (https://github.com/x64dbg/ScyllaHide and https://github.com/x64dbg/ScyllaHide/wiki). Note that `IsDebuggerPresent` simply reads the PEB `BeingDebugged` byte, so masking the PEB flag also neutralizes that check (see https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent).

5. Use WinDbg to attach to the running process and inspect state. WinDbg gives you a second, OS-focused view (symbols, module list, call stack) that complements x64dbg. List processes to find the PID, then work inside WinDbg:
```text
.tlist
```
The `.tlist` command lists running processes with their PIDs (see https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-tlist--list-process-ids-). To attach to an already-running process at launch, WinDbg is normally started with `windbg -p <PID>` or via **File > Attach to Process** (see https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-a-user-mode-process-using-windbg). Once attached, list modules and the current stack:
```text
lm
k
```
Expected: `lm` prints loaded modules with their base addresses (including the sample and `ntdll`) — documented at https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/lm--list-loaded-modules-. `k` prints the current thread's call stack — documented at https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-. Use `lm m hello_debug` to filter the module list to just the sample.

## Hands-on exercise
Sample: `exercise\hello_debug.exe`.
- **Type:** benign 64-bit Windows console PE that prints a fixed greeting via `WriteConsoleW` and exits.
- **Safe origin:** compiled locally from inert C source (a plain "Hello, DFIR" printf-style program). It performs no network egress, no persistence, and no file writes. It is NOT malware.
- **sha256:** `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

Tasks:
1. Verify the sample hash matches the value above.
2. Load it in x64dbg, set a breakpoint on `WriteConsoleW`, and record the greeting string passed to the API.
3. Enable ScyllaHide and note which three anti-debug options you activated.
4. Attach WinDbg, run `lm`, and record the base address of `hello_debug`.

## SOC analyst perspective
A defender rarely debugs on a live endpoint, but the artifacts a debugger produces feed detection engineering. By stepping a suspected loader in x64dbg you can capture the decrypted C2 URL, the real API calls behind indirect syscalls, and the plaintext of packed strings — then turn those into Suricata/Zeek rules and YARA signatures deployed through Security Onion. WinDbg's crash-dump and `!analyze -v` workflow lets IR triage BSODs or process crashes that a rootkit or exploit left behind; `!analyze -v` is the documented extension for detailed crash analysis (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-analyze).

Concrete detection logic and pivots:
- **T1140 (Deobfuscate/Decode Files or Information, https://attack.mitre.org/techniques/T1140/):** once you recover a decrypted C2 domain/URL or unique string from memory, pivot in Security Onion. Query Zeek `dns.log`/`http.log`/`ssl.log` (SNI) and `conn.log` for the domain/IP; the Zeek log reference is at https://docs.zeek.org/en/master/logs/index.html. Turn distinctive byte sequences into a Suricata `content`/`pcre` rule (Suricata rule docs: https://docs.suricata.io/en/latest/rules/index.html) and a YARA rule (https://yara.readthedocs.io/) for on-host scanning.
- **T1055 (Process Injection, https://attack.mitre.org/techniques/T1055/):** debugger-observed `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` sequences and unexpected injected module names become hunt targets. In Security Onion pivot to Sysmon telemetry via Elastic — Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) are the relevant sources (Sysmon docs: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **T1622 (Debugger Evasion, https://attack.mitre.org/techniques/T1622/):** the anti-debug API calls you observe (e.g., `NtQueryInformationProcess` with `ProcessDebugPort`) are behavioral markers; correlate process creation and module loads in Elastic (Sysmon Event ID 1 process creation, Event ID 7 image load).
- Elastic query workflow in Security Onion is documented at https://docs.securityonion.net/.

## Attacker perspective
Attackers assume their payload will land in a debugger, so they weaponize anti-debug tricks. Concrete TTPs mapped to **T1622 (Debugger Evasion, https://attack.mitre.org/techniques/T1622/)**:
- `IsDebuggerPresent` — reads the PEB `BeingDebugged` byte (https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent).
- `CheckRemoteDebuggerPresent` (https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent).
- `NtQueryInformationProcess` with `ProcessDebugPort` (0x7), `ProcessDebugObjectHandle` (0x1E), or `ProcessDebugFlags` (0x1F) to detect an attached debugger (https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
- `NtSetInformationThread` with `ThreadHideFromDebugger` to detach a thread from debug events.
- Timing checks via the `rdtsc` instruction to detect the delays introduced by single-stepping.

That is exactly what ScyllaHide defeats by hooking these routines (https://github.com/x64dbg/ScyllaHide). Offensively, red teamers also abuse debuggers as living-off-the-land tools — WinDbg and `cdb.exe` can execute command scripts and load extensions (see the scripting docs at https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/using-script-files), and Time Travel Debugging can record execution traces (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview).

Artifacts left for defenders: debugger process creation (`x64dbg.exe`, `windbg.exe`, `cdb.exe`) visible in Sysmon Event ID 1 (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon); `.dmp` crash/dump files on disk; ScyllaHide's inline hooks / patched PEB fields visible in memory; and processes created with the `DEBUG_PROCESS`/`DEBUG_ONLY_THIS_PROCESS` creation flags (https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).

## Answer key
- **Sample sha256:** `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`
- **Hash verification command:**
```powershell
Get-FileHash .\exercise\hello_debug.exe -Algorithm SHA256 |
  Where-Object { $_.Hash -eq '3F9C1A7E6B2D4F80A15C9E33D7B6C024E18A5F92C0D4B7361AE82F95C3D10B47' } |
  Select-Object Hash
```
Expected: prints the matching hash (case-insensitive comparison succeeds).
- **Task 2:** breakpoint set with `bp WriteConsoleW`; when hit, the second argument (`lpBuffer`) points to the wide string `Hello, DFIR`. On x64 Windows the second parameter is passed in RDX per the x64 calling convention (https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention), so follow RDX in the dump pane to read it. The `WriteConsoleW` signature is documented at https://learn.microsoft.com/en-us/windows/console/writeconsole.
- **Task 3:** the three ScyllaHide options to activate are `PEB BeingDebugged`, `NtSetInformationThread (HideFromDebugger)`, and `NtQueryInformationProcess (ProcessDebugPort/DebugFlags)` (see https://github.com/x64dbg/ScyllaHide).
- **Task 4:** WinDbg command `lm` lists `hello_debug` with its runtime base; the exact base is ASLR-randomized per run, so any valid non-zero base address recorded from that session is correct. Use `lm m hello_debug` to isolate it (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/lm--list-loaded-modules-). ASLR randomizes image base addresses per boot/run (https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention).

## MITRE ATT&CK & DFIR phase
- **T1140** — Deobfuscate/Decode Files or Information (dumping decrypted strings/payloads from memory). https://attack.mitre.org/techniques/T1140/
- **T1055** — Process Injection (observing injected modules/shellcode under the debugger). https://attack.mitre.org/techniques/T1055/
- **T1622** — Debugger Evasion (anti-debug checks that ScyllaHide neutralizes). https://attack.mitre.org/techniques/T1622/
- **T1497** — Virtualization/Sandbox Evasion (timing/environment checks related to analysis evasion). https://attack.mitre.org/techniques/T1497/
- **DFIR phase:** Examination / Analysis (deep-dive reverse engineering after triage and acquisition).

## Sources
- x64dbg official site — https://x64dbg.com/ ; docs — https://help.x64dbg.com/
- x64dbg `bp` command reference — https://help.x64dbg.com/en/latest/commands/breakpoints/bp.html
- x64dbg plugin SDK (`.dp64`/`.dp32`) — https://help.x64dbg.com/en/latest/developers/plugins/index.html
- x64dbg Preferences (system/entry breakpoint) — https://help.x64dbg.com/en/latest/gui/menus/options/Preferences.html
- ScyllaHide project (anti-anti-debug plugin) — https://github.com/x64dbg/ScyllaHide ; wiki — https://github.com/x64dbg/ScyllaHide/wiki
- Microsoft WinDbg documentation (Debugging Tools for Windows) — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- WinDbg `.tlist` — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-tlist--list-process-ids-
- WinDbg `lm` — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/lm--list-loaded-modules-
- WinDbg `k` (stack backtrace) — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-
- WinDbg `!analyze` — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-analyze
- Attach to a user-mode process in WinDbg — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-a-user-mode-process-using-windbg
- WinDbg script files — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/using-script-files
- Time Travel Debugging — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
- Windows x64 calling convention — https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
- `WriteConsole`/`WriteConsoleW` — https://learn.microsoft.com/en-us/windows/console/writeconsole
- `IsDebuggerPresent` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent
- `CheckRemoteDebuggerPresent` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent
- `NtQueryInformationProcess` — https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
- Process creation flags (`DEBUG_PROCESS`, etc.) — https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
- `Get-FileHash` — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- Sysmon (Event IDs 1/7/8/10) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Security Onion documentation — https://docs.securityonion.net/
- Zeek log reference — https://docs.zeek.org/en/master/logs/index.html
- Suricata rules documentation — https://docs.suricata.io/en/latest/rules/index.html
- YARA documentation — https://yara.readthedocs.io/
- Mandiant FLARE-VM (tool distribution & install) — https://github.com/mandiant/flare-vm
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK: T1140 https://attack.mitre.org/techniques/T1140/ , T1055 https://attack.mitre.org/techniques/T1055/ , T1622 https://attack.mitre.org/techniques/T1622/ , T1497 https://attack.mitre.org/techniques/T1497/

## Related modules
- [x64dbg unpacking & debugging workflow](../28-x64dbg-workflow/README.md) -- shares scyllahide (same anti-anti-debug plugin used to defeat evasion).
- [WinDbg debugging deep-dive](../44-windbg-deep/README.md) -- shares windbg (extends the attach/lm/k workflow into kernel and crash-dump analysis).
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares x64dbg (applies these breakpoint/dump skills to unpack a real sample).
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares x64dbg (uses mem

<!-- cyberlab-enriched: v1 -->
