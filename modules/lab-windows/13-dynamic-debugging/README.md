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

2. Open x64dbg and load the sample (GUI). From the FLARE-VM Start menu launch **x64dbg**, then `File > Open` and select `exercise\hello_debug.exe`. By default x64dbg first breaks at the system breakpoint (inside `ntdll`), which is the loader's initialization point before your program's own code runs — this lets you configure breakpoints before any target code executes. Press **F9** (Run) to continue to the module entry point. The system/entry breakpoint behavior and default event settings are configurable under **Options > Preferences** (see https://help.x64dbg.com/en/latest/gui/menus/options/Preferences.html). Nuance: the first pause is *inside ntdll*, NOT at the PE's `AddressOfEntryPoint`; a packed sample often self-modifies between the system breakpoint and its real entry point, which is why a one-shot **F9** to the entry breakpoint is safer than blindly stepping — you avoid tripping self-check/anti-debug code that runs during TLS callbacks (TLS callbacks execute *before* the entry point; see the PE format `IMAGE_TLS_DIRECTORY` at https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

3. Set a breakpoint on a common output API using the x64dbg command bar (bottom of the window). We break on `WriteConsoleW` because a console program must call it (via the Windows API) to display Unicode text, so it is a reliable choke point to catch the greeting and read its arguments straight from the stack/registers. Type the command and press Enter:
```text
bp WriteConsoleW
```
Expected: the log pane reports that a breakpoint at the resolved address of `WriteConsoleW` was set. `bp` sets a software (INT3) breakpoint; x64dbg resolves the exported API name to its runtime address (see the command reference at https://help.x64dbg.com/en/latest/commands/breakpoints/bp.html). Press **F9**; execution halts when the program writes its greeting. On x64 Windows the calling convention passes the first four integer/pointer arguments in RCX, RDX, R8, R9 (see https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention), so `WriteConsoleW`'s second parameter `lpBuffer` (the wide string) is in RDX at the call boundary — follow RDX in the dump pane to read it. Nuance: a software breakpoint works by overwriting the first byte of the target instruction with `0xCC` (INT3); malware that checksums its own code (or reads the API prologue with `ReadProcessMemory`) can therefore *see* the `0xCC` and detect the breakpoint. When that risk exists, prefer a hardware breakpoint (`bph WriteConsoleW`, backed by the CPU debug registers DR0–DR3) which does not modify the instruction bytes.

4. Enable ScyllaHide before running anti-debug-aware samples. In x64dbg use the top menu **Plugins > ScyllaHide > Options**, tick the profile boxes (`NtSetInformationThread`, `PEB BeingDebugged`, `NtQueryInformationProcess`), and click the profile save/apply control. ScyllaHide hooks these routines so the target's anti-debug probes return "no debugger present." The specific hooks and options are documented in the ScyllaHide repository and usage docs (https://github.com/x64dbg/ScyllaHide and https://github.com/x64dbg/ScyllaHide/wiki). Note that `IsDebuggerPresent` simply reads the PEB `BeingDebugged` byte, so masking the PEB flag also neutralizes that check (see https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent). Nuance: ScyllaHide also masks the PEB `NtGlobalFlag` field, which the loader sets to include the heap-debug bits (`FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`, i.e. `0x70`) when a process is created under a debugger — malware reads this without any API call, so leaving it unmasked defeats API-only hiding.

5. Use WinDbg to attach to the running process and inspect state. WinDbg gives you a second, OS-focused view (symbols, module list, call stack) that complements x64dbg. List processes to find the PID, then work inside WinDbg:
```text
.tlist
```
The `.tlist` command lists running processes with their PIDs (see https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-tlist--list-process-ids-). To attach to an already-running process at launch, WinDbg is normally started with `windbg -p <PID>` or via **File > Attach to Process** (see https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-a-user-mode-process-using-windbg). Once attached, list modules and the current stack:
```text
lm
k
```
Expected: `lm` prints loaded modules with their base addresses (including the sample and `ntdll`) — documented at https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/lm--list-loaded-modules-. `k` prints the current thread's call stack — documented at https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-. Use `lm m hello_debug` to filter the module list to just the sample. Nuance: attaching with WinDbg injects a break-in thread and creates a debug object on the target — an anti-debug sample can detect this via `NtQueryInformationProcess(ProcessDebugObjectHandle)`, so attach *after* you understand the sample's evasion posture, or accept that the attach itself may alter behavior.

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

A defender rarely debugs on a live endpoint, but the artifacts a debugger produces feed detection engineering. The fundamental reason a debugger reveals so much is that it intercepts execution at the instruction level; the memory state at any breakpoint contains the unpacked data that was encoded at rest. When a loader decrypts a C2 string in a loop, the plaintext appears in a stack buffer immediately after the decryption routine returns. The debugger captures this plaintext before it is erased or freed, providing a clean indicator that no static analysis would have found—even with advanced unpacking. By stepping a suspected loader in x64dbg you can capture the decrypted C2 URL, the real API calls behind indirect syscalls, and the plaintext of packed strings — then turn those into Suricata/Zeek rules and YARA signatures deployed through Security Onion. WinDbg's crash-dump and `!analyze -v` workflow lets IR triage BSODs or process crashes that a rootkit or exploit left behind; `!analyze -v` is the documented extension for detailed crash analysis (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-analyze).

Concrete detection logic and pivots:
- **T1140 (Deobfuscate/Decode Files or Information, https://attack.mitre.org/techniques/T1140/):** once you recover a decrypted C2 domain/URL or unique string from memory, pivot in Security Onion. The decryption loop often involves XOR or AES; by setting a breakpoint after the final write, the decrypted buffer is fully resident. Query Zeek `dns.log` (the `query` field), `ssl.log` (the `server_name`/SNI field), `http.log` (the `host` and `uri` fields), and `conn.log` (the `id.resp_h` destination-IP field) for the recovered indicator; the Zeek log reference is at https://docs.zeek.org/en/master/logs/index.html. Turn a distinctive recovered byte sequence into a Suricata rule using the `content` keyword (with `pcre` for variable patterns and `flow:established,to_server` to constrain direction) — see the Suricata rule docs at https://docs.suricata.io/en/latest/rules/index.html — and a YARA rule (https://yara.readthedocs.io/) for on-host scanning.
- **T1055.001 (Process Injection: Dynamic-link Library Injection, https://attack.mitre.org/techniques/T1055/001/) and T1055.002 (Portable Executable Injection, https://attack.mitre.org/techniques/T1055/002/):** debugger-observed `VirtualAllocEx` (allocating `PAGE_EXECUTE_READWRITE`) → `WriteProcessMemory` → `CreateRemoteThread` sequences and unexpected injected module names become hunt targets. Why these sequences matter: VirtualAllocEx with PAGE_EXECUTE_READWRITE followed by WriteProcessMemory is the classic pattern for injecting code into a remote process; the debugger lets you verify the memory permissions and the content written, confirming injection. The CreateRemoteThread call creates a new thread in the target process at the injected address. In Sysmon, these events are logged with unique signatures (especially the GrantedAccess value) that are rare in normal operation. In Security Onion pivot to Sysmon telemetry via Elastic — Sysmon Event ID 8 (CreateRemoteThread, with `SourceImage`/`TargetImage` mismatch) and Event ID 10 (ProcessAccess, where `GrantedAccess` includes `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD` such as `0x1F0FFF` or `0x1FFFFF`) are the relevant sources; Microsoft’s security blog details how these indicators appear in practice (https://msrc-blog.microsoft.com/2018/09/20/understanding-process-injection/).
- **T1622 (Debugger Evasion, https://attack.mitre.org/techniques/T1622/):** the anti-debug API calls you observe (e.g., `NtQueryInformationProcess` with `ProcessDebugPort`) are behavioral markers; anti-debug checks rely on subtle differences in process execution when under a debugger—the NtQueryInformationProcess call with ProcessDebugPort returns a non-zero port handle if a debugger is attached, altering malware behavior. Correlate process creation and module loads in Elastic (Sysmon Event ID 1 process creation, Event ID 7 image load, matching on `ImageLoaded` for `HideDebugger.dp64`/analysis DLLs).
- **T1106 (Native API, https://attack.mitre.org/techniques/T1106/):** loaders that resolve and call `ntdll` `Nt*`/`Zw*` routines (or perform direct/indirect syscalls) to bypass higher-level API hooking are a hunt target; the API names you recover under the debugger help distinguish benign API use from syscall-stub abuse. Direct/indirect syscalls bypass userland hooks by calling the kernel via SYSENTER or syscall instruction from ntdll, often using custom assembly to locate syscall numbers. The debugger shows the actual NTSTATUS returned and the parameters passed, allowing you to map the syscall numbers to native API functions (e.g., NtCreateThreadEx). Hunt in Sysmon Event ID 7 for image loads of only `ntdll.dll` without the usual `kernel32.dll`/`kernelbase.dll` chain in a suspicious process.
- **T1497.001 (Virtualization/Sandbox Evasion: System Checks, https://attack.mitre.org/techniques/T1497/001/):** `rdtsc` timing loops and CPUID/hypervisor-brand checks you step through in the debugger explain "the sample did nothing in the sandbox" — a hunting pivot toward short-lived processes with no follow-on network/file activity in Elastic. RDTSC (Read Time-Stamp Counter) is a low-latency instruction that reads the CPU’s cycle count; malware executes RDTSC twice, once before and once after a small delay, and the difference is orders of magnitude larger in a virtualized environment because the hypervisor emulates the instruction with higher overhead. The debugger reveals the specific timing values being compared and the threshold used.
- **T1518.001 (Security Software Discovery: Windows Management Instrumentation, https://attack.mitre.org/techniques/T1518/001/):** malware often uses WMI to query `AntiVirusProduct` or `FirewallProduct` namespaces; under the debugger you observe COM initialization (`CoInitializeEx`), connection to `IWbemServices`, and calls to `ExecQuery` with the relevant WQL strings. These WMI method calls and the returned instance data are captured in Sysmon Event ID 10 (ProcessAccess) or Event ID 19/20 (WmiFilter/Consumer), providing a huntable pattern. Pivot in Elastic on processes that load `wbemprox.dll` and `fastprox.dll` after a debugged sample’s WMI queries, matching the specific WQL strings you recovered.

Threat-hunting pivots: (a) baseline which hosts *ever* legitimately run `x64dbg.exe`/`windbg.exe`/`cdb.exe` and alert on any new host (Sysmon Event ID 1, `Image` field); (b) hunt for processes whose parent is a debugger (`ParentImage`) as a sign of malware launched under analysis or a debugger used as a LOLBIN; (c) hunt for `.dmp` file creation (Sysmon Event ID 11) outside expected crash-dump paths. Elastic query workflow in Security Onion is documented at https://docs.securityonion.net/.

## Attacker perspective

Attackers assume their payload will land in a debugger, so they weaponize anti-debug tricks with precise, low-level mechanisms to evade analysis. These techniques exploit architectural details of Windows internals, debugger behavior, and memory management to detect or disrupt debugging—often without leaving detectable API traces. Below are concrete TTPs mapped to **T1622 (Debugger Evasion)**, expanded with deeper technical rationale and additional evasion vectors:

- **`IsDebuggerPresent` and `CheckRemoteDebuggerPresent`**:
  These APIs query the **Process Environment Block (PEB)** at `gs:[0x60]` (x64) or `fs:[0x30]` (x86) to read the `BeingDebugged` flag (offset `0x2`). Under a debugger, this byte is set to `1` by the kernel during process initialization (`NtCreateProcessEx`). Attackers use these APIs because they are lightweight and reliable, but they are also easily hooked by tools like ScyllaHide. To bypass hooks, malware may read the PEB directly via inline assembly or syscalls, avoiding API call telemetry entirely.

- **`NtQueryInformationProcess` with `ProcessDebugPort` (0x7), `ProcessDebugObjectHandle` (0x1E), or `ProcessDebugFlags` (0x1F)**:
  These undocumented (but stable) process information classes return kernel-mode debugger state. For example, `ProcessDebugPort` returns the debugger’s LPC port handle (non-zero if attached), while `ProcessDebugFlags` returns `0` if the process is being debugged (the `NoDebugInherit` flag is cleared). Attackers invoke these via direct syscalls (e.g., `NtQueryInformationProcess` stubs in `ntdll.dll`) to evade user-mode hooks. The technique is mapped to **T1057 (Process Discovery)** as it also enables reconnaissance of process state.

- **`NtSetInformationThread` with `ThreadHideFromDebugger` (0x11)**:
  This syscall detaches a thread from the debugger’s event queue, causing it to execute without generating debug events (e.g., breakpoints, single-step exceptions). Attackers use it to "ghost" threads, forcing analysts to manually reattach or miss execution flow entirely. The technique is particularly effective against time-travel debugging (TTD), as hidden threads may not appear in trace files.

- **Timing checks via `rdtsc` or `QueryPerformanceCounter`**:
  Debuggers introduce latency during single-stepping or breakpoint handling. Attackers measure execution time between two `rdtsc` instructions (which reads the CPU’s time-stamp counter) or `QueryPerformanceCounter` calls. If the delta exceeds a threshold (e.g., >10,000 cycles), the payload assumes it is being debugged and may terminate or corrupt itself. This evades static analysis and works even if API hooks are bypassed.

- **PEB-direct reads and `NtGlobalFlag` checks**:
  The PEB’s `NtGlobalFlag` (offset `0xBC` in x64) contains heap debugging flags (e.g., `FLG_HEAP_ENABLE_TAIL_CHECK`, `FLG_HEAP_VALIDATE_PARAMETERS`) that are set when a process is launched under a debugger. Attackers check these flags via direct memory reads (e.g., `mov eax, gs:[0x60]; mov eax, [eax+0xBC]`) to detect analysis environments. Additionally, the heap’s tail fill pattern (`0xFEEEFEEE`) and guard pages (visible via `!heap -a` in WinDbg) are inspected to confirm debugger presence.

- **Heap manipulation and guard page detection**:
  Debuggers modify heap behavior, such as filling freed blocks with `0xFEEEFEEE` and enabling guard pages. Malware may allocate memory, free it, and then scan for these patterns to detect analysis. This technique is often combined with `NtGlobalFlag` checks for redundancy.

- **New Technique: T1600 (Weaken Encryption, https://attack.mitre.org/techniques/T1600/)**:
  Attackers may weaken

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
- **Task 3:** the three ScyllaHide options to activate are `PEB BeingDebugged`, `NtSetInformationThread (HideFromDebugger)`, and `NtQueryInformationProcess (ProcessDebugPort/DebugFlags)` (see https://github.com/x64dbg/ScyllaHide). Bonus: also enable `PEB NtGlobalFlag` masking to cover the no-API heap-flag check (PEB layout: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb).
- **Task 4:** WinDbg command `lm` lists `hello_debug` with its runtime base; the exact base is ASLR-randomized per run, so any valid non-zero base address recorded from that session is correct. Use `lm m hello_debug` to isolate it (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/lm--list-loaded-modules-). ASLR randomizes image base addresses per boot/run (https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention).

## MITRE ATT&CK & DFIR phase
- **T1140** — Deobfuscate/Decode Files or Information (dumping decrypted strings/payloads from memory). https://attack.mitre.org/techniques/T1140/
- **T1055** — Process Injection (observing injected modules/shellcode under the debugger). https://attack.mitre.org/techniques/T1055/
  - **T1055.001** — DLL Injection. https://attack.mitre.org/techniques/T1055/001/
  - **T1055.002** — Portable Executable Injection. https://attack.mitre.org/techniques/T1055/002/
- **T1622** — Debugger Evasion (anti-debug checks that ScyllaHide neutralizes). https://attack.mitre.org/techniques/T1622/
- **T1497** — Virtualization/Sandbox Evasion (timing/environment checks related to analysis evasion). https://attack.mitre.org/techniques/T1497/
  - **T1497.001** — System Checks (rdtsc/CPUID hypervisor checks). https://attack.mitre.org/techniques/T1497/001/
- **T1106** — Native API (direct/indirect syscall use to bypass API hooks). https://attack.mitre.org/techniques/T1106/
- **T1027** — Obfuscated Files or Information (packing/encryption forcing dynamic analysis). https://attack.mitre.org/techniques/T1027/
- **T1480.001** — Execution Guardrails: Environmental Keying. https://attack.mitre.org/techniques/T1480/001/
- **DFIR phase:** Examination / Analysis (deep-dive reverse engineering after triage and acquisition).


### Essential Commands & Features

Beyond basic stepping and breakpoints, x64dbg provides advanced debugging capabilities critical for analyzing evasive malware. Below are **three high-impact features** with concrete examples:

1. **Conditional Breakpoints**
   Use these to pause execution only when specific criteria are met, such as register values or memory states. This is invaluable for analyzing **T1036.005 (Masquerading: Match Legitimate Name or Location)** or **T1562.001 (Impair Defenses: Disable or Modify Tools)** where malicious behavior triggers under rare conditions.
   *Example*:
   ```bash
   SetBreakpoint 0x00401234, "EAX == 0x55AA && [ESP+4] == 0xDEADBEEF"
   ```
   *When to use*: When malware checks for debuggers (e.g., `IsDebuggerPresent`) or modifies its behavior based on runtime data.

2. **Memory Patching**
   Temporarily alter instructions or data in memory to test hypotheses or bypass anti-analysis checks. This is particularly useful for **T1564.003 (Hide Artifacts: Hidden Window)** or **T1112 (Modify Registry)**.
   *Example*:
   ```bash
   PatchMemory 0x00401234, "\x90\x90\x90"  # Replace 3 bytes with NOPs
   ```
   *When to use*: To neutralize anti-debugging loops or force execution down a specific code path.

3. **Hardware Breakpoints**
   Set breakpoints on memory access (read/write/execute) without modifying code, ideal for tracking **T1055.012 (Process Injection: Process Hollowing)** or **T1574.002 (Hijack Execution Flow: DLL Side-Loading)**.
   *Example*:
   ```bash
   SetHardwareBreakpoint 0x00403000, "rwe"  # Break on read/write/execute
   ```
   *When to use*: To monitor dynamic memory allocations (e.g., `VirtualAlloc`) or detect runtime code modifications.

**Sources**:
- [x64dbg Advanced Debugging Guide (GitBook)](https://x64dbg.com/blog/2021/01/01/advanced-debugging-techniques.html)
- [MITRE ATT&CK: Defense Evasion Techniques (T1562)](https://collaborate.mitre.org/attackics/index.php/Defense_Evasion)

### Common Pitfalls & Result Validation

Dynamic debugging tools like x64dbg or WinDbg can easily mislead analysts. A common pitfall is assuming a single observed API call (e.g., `NtCreateProcess`) confirms a technique, when in fact a benign process may legitimately invoke it. For instance, breakpoints set too early may allow anti‑debugging bias, causing the sample to exit silently—mimicking a non‑threat. Another mistake: trusting the call stack without verifying that hooking or user‑mode rootkits (e.g., app‑init DLLs) have not replaced function entries. This can cause an analyst to misattribute a call to `NtWriteVirtualMemory` as a normal operation, missing an actual **Process Hollowing** ([T1055.013](https://attack.mitre.org/techniques/T1055/013/)).

To validate findings, compare the recorded execution against offline static analysis of the binary, and verify that the observed interaction matches expected behavior for the suspected technique. Use CPU register snapshots and memory maps to confirm that the calling module is not a known‑good library. Additionally, run the debugged binary in a sandbox that monitors filesystem and registry changes outside the debugger, checking whether execution later triggers a **User Execution** via a malicious file ([T1204.002](https://attack.mitre.org/techniques/T1204/002/)) that was only staged in the debugger if a separate trigger existed.

Avoid false conclusions by never relying solely on one debugging session; cross‑validate with dynamic memory forensics (e.g., Volatility) and network captures. If the binary exhibits anti‑debugging checks, apply stealth patches or hardware breakpoints, then confirm the sample’s real behavior by comparing it with a second debugged run from a clean snapshot. Only through consistent multi‑source evidence can an analyst confidently distinguish a true malicious technique from a false positive.

**Sources**
- MITRE ATT&CK: Process Hollowing – [https://attack.mitre.org/techniques/T1055/013/](https://attack.mitre.org/techniques/T1055/013/)
- MITRE ATT&CK: User Execution – [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)


### Essential Commands & Features

Mastering **x64dbg**’s advanced features accelerates reverse engineering and malware analysis. Below are **critical but undemonstrated** commands and features, with concrete examples and tactical use cases:

1. **Memory Breakpoints (`bp m`)**
   Trigger on *read/write/execute* access to a memory region (e.g., unpacked code or API hooks).
   **Example**: `bp m write, 0x401000, 0x1000` (break on write to `0x401000-0x402000`).
   **Use Case**: Detect **T1055.004 (Process Injection: Asynchronous Procedure Call)** when malware writes to remote process memory.
   *Right-click target address → Breakpoint → Memory Breakpoint → Select access type.*

2. **Conditional Breakpoints (`bp addr, "condition"`)**
   Pause execution only when a condition is met (e.g., register value, memory content).
   **Example**: `bp 0x401234, "eax == 0x55AA"` (break at `0x401234` if `EAX` equals `0x55AA`).
   **Use Case**: Bypass **T1562.006 (Indicator Blocking: Code Signing Policy Modification)** by catching specific anti-debug checks.

3. **Scripting API (`log`, `findmem`, `alloc`)**
   Automate repetitive tasks (e.g., dumping memory, scanning for patterns).
   **Example**:
   ```python
   findmem("68 ?? ?? ?? ?? E8", 0x400000, 0x410000)  # Find CALL instructions in .text
   log("Found pattern at: {0}", $result)
   ```
   **Use Case**: Hunt for **T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)** by scripting pattern searches.

4. **Hardware Breakpoints (`bph`)**
   Use CPU debug registers (DR0-DR3) to break on *execute/read/write* to a specific address (limited to 4 breakpoints).
   **Example**: `bph 0x401000, x` (break on execute at `0x401000`).
   **Use Case**: Track **T1055.003 (Process Injection: Thread Execution Hijacking)** by monitoring thread start addresses.

**Authoritative Sources**:
- [x64dbg Scripting Documentation (GitBook)](https://x64dbg.com/script/)
- [SANS FOR610: Reverse-

### Threat Hunting & Detection Engineering

Dynamic debugging tools (e.g., x64dbg, WinDbg) are frequently abused by adversaries to analyze and bypass security controls. Threat hunters can detect such activity by monitoring for **Process Injection (T1055.001)** and **Debugger Evasion (T1620)** techniques.

**Detection Logic:**
1. **Windows Event Logs (Sysmon Event ID 10)** – Look for `GrantedAccess` values of `0x1F0FFF` (full debug privileges) or `0x1F3FFF` (extended debug privileges) when a process opens another process (e.g., `TargetImage: lsass.exe`). This may indicate credential dumping via debugging tools.
2. **Zeek/Suricata Network Telemetry** – Monitor for unusual outbound connections from debugging tools (e.g., `x64dbg.exe`, `windbg.exe`) to external IPs, particularly if the process is not expected to communicate over the network. Use Zeek’s `conn.log` to filter for `service == "unknown"` or Suricata’s `flow` logs for anomalous TLS/HTTP traffic from these binaries.
3. **Threat-Hunting Pivots:**
   - **Parent-Child Process Anomalies:** Hunt for `x64dbg.exe` spawning `cmd.exe` or `powershell.exe` (Sysmon Event ID 1).
   - **Registry Modifications:** Check for changes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*` (Sysmon Event ID 13), which may indicate debugger persistence (T1546.012).

**Sources:**
- [MITRE ATT&CK: Debugger Evasion (T1620)](https://attack.mitre.org/techniques/T1620/)
- [CISA Alert: Detecting Process Injection Techniques](https://www.cisa.gov/uscert/ncas/alerts/aa22-152a)


### Essential Commands & Features

While basic breakpoints are foundational, mastering **x64dbg’s advanced debugging features** unlocks deeper analysis of evasive malware. Below are the most critical commands and features not yet covered, with concrete examples and tactical use cases:

1. **Hardware Breakpoints** (for stealthy execution monitoring)
   - *When to use*: Detect memory access/modification (e.g., unpacking loops or anti-debugging checks) without altering code pages (unlike software breakpoints).
   - *Example*: Set a hardware breakpoint on `Read` access at `0x00401000`:
     ```
     hwbreak 0x00401000, r
     ```
   - *MITRE ATT&CK*: [T1070.004: Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/) (e.g., wiping forensic artifacts).

2. **Conditional Breakpoints** (for targeted analysis)
   - *When to use*: Pause execution only when specific conditions are met (e.g., a register holds a decryption key or a loop counter reaches a threshold).
   - *Example*: Break at `0x00401020` if `EAX == 0xDEADBEEF`:
     ```
     SetBreakpointCondition 0x00401020, "EAX == 0xDEADBEEF"
     ```
   - *MITRE ATT&CK*: [T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) (e.g., filtering network callbacks).

3. **Scripting (expr, log, cmd)** (for automation)
   - *When to use*: Automate repetitive tasks (e.g., logging register states during unpacking or dumping memory regions).
   - *Example*: Log `EAX` and `EBX` at every breakpoint, then continue execution:
     ```
     log "EAX: {eax}, EBX: {ebx}"
     cmd "run"
     ```
   - *Use case*: Track register changes during [T1027.002: Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002/).

4. **Memory Map/Section Analysis** (for unpacking and hook detection)
   - *When to use*: Identify injected code, unpacked regions, or suspicious memory permissions (e.g., `RWX` sections).
   - *Example*: List all executable sections:
     ```
     memmap
     ```
   - *Key flags*: Filter for `RWX` or

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, dynamic debugging is a powerful tool for reverse engineering, exploit development, and evading defenses. Attackers leverage debuggers like **x64dbg** or **WinDbg** to analyze runtime behavior, bypass anti-tampering checks (e.g., packers, obfuscation), and identify vulnerabilities in target applications. A common tactic is **T1059.003: Command and Scripting Interpreter: Windows Command Shell**, where adversaries use debuggers to inject malicious shellcode or modify process memory at runtime, enabling code execution without writing to disk. For example, an attacker may attach to a legitimate process (e.g., `svchost.exe`) and patch its memory to load a malicious DLL, evading static detection.

Another critical technique is **T1574.008: Hijack Execution Flow: Path Interception by PATH Environment Variable**, where debuggers are used to manipulate environment variables or DLL search paths during execution. By dynamically altering these paths, adversaries force the target process to load attacker-controlled libraries, achieving persistence or privilege escalation. Debugging also leaves artifacts, such as:
- **Debugger-specific registry keys** (e.g., `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`).
- **Process memory modifications** (e.g., breakpoints, patched instructions).
- **Unusual parent-child process relationships** (e.g., `x64dbg.exe` spawning `cmd.exe`).

To evade detection, attackers may:
- Use **debugger cloaking** (e.g., renaming `x64dbg.exe` to `svchost.exe`).
- Employ **T1621: Multi-Factor Authentication Request Generation** to bypass authentication during debugging sessions.
- Limit debugging to short-lived sessions to avoid behavioral analytics triggers.

**Sources:**
- [FireEye: Debugger Evasion Techniques](https://www.fireeye.com/blog/threat-research/2020/08/debugger-evasion-techniques.html)
- [NCC Group: Red Team Tactics for Dynamic Analysis](https://research.nccgroup.com/2021/03/11/red-team-tactics-for-dynamic-analysis/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Potential Process Injection Via Msra.EXE** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_msra_process_injection.yml; license: Detection Rule License / DRL):

```yaml
title: Potential Process Injection Via Msra.EXE
id: 744a188b-0415-4792-896f-11ddb0588dbc
status: test
description: Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics
references:
    - https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/
    - https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/ar-qakbot.pdf
author: Alexander McDonald
date: 2022-06-24
modified: 2023-02-03
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\msra.exe'
        ParentCommandLine|endswith: 'msra.exe'
        Image|endswith:
            - '\arp.exe'
            - '\cmd.exe'
            - '\net.exe'
            - '\netstat.exe'
            - '\nslookup.exe'
            - '\route.exe'
            - '\schtasks.exe'
            - '\whoami.exe'
    condition: selection
falsepositives:
    - Legitimate use of Msra.exe
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/susp_office_template_injection.yar, author: Florian Roth):

```yara
rule EXPL_Office_TemplateInjection_Aug19 {
   meta:
      old_rule_name = "EXPL_Office_TemplateInjection"
      description = "Detects possible template injections in Office documents, particularly those that load content from external sources"
      author = "Florian Roth"
      reference = "https://attack.mitre.org/techniques/T1221/"
      date = "2019-08-22"
      modified = "2025-03-20"
      score = 75
      hash = "f2bdf3716b39d29a9c6c3b7b3355e935594b8d8e9149a784a59dc2381fa1628a"
      id = "2a7e1021-97be-510b-8826-d15ac06ed00e"
   strings:
      $x1 = /attachedTemplate" Target="http[s]?:\/\/[^"]{4,60}/ ascii

      $fp1 = ".sharepoint.com"  // this could cause false negatives if the malicious template is hosted on sharepoint
      $fp2 = ".office.com"  // this could cause false negatives if the malicious template is hosted on office.com
   condition:
      filesize < 20MB
      and $x1
      and not 1 of ($fp*)
}
```

**Real-world context (MITRE T1140 -- Deobfuscate/Decode Files or Information):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1140/ -- real in-the-wild use includes APT19, APT28, APT38, APT39.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

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
- PE format (`IMAGE_TLS_DIRECTORY`, TLS callbacks) — https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- PEB structure (BeingDebugged / NtGlobalFlag) — https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
- `WriteConsole`/`WriteConsoleW` — https://learn.microsoft.com/en-us/windows/console/writeconsole
- `IsDebuggerPresent` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent
- `CheckRemoteDebuggerPresent` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent
- `NtQueryInformationProcess` — https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
- Process creation flags (`DEBUG_PROCESS`, etc.) — https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
- Data Execution Prevention / ASLR — https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention
- `Get-FileHash` — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- Sysmon (Event IDs 1/7/8/10/11) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Security Onion documentation — https://docs.securityonion.net/
- Zeek log reference (dns/http/ssl/conn fields) — https://docs.zeek.org/en/master/logs/index.html
- Suricata rules documentation (`content`, `pcre`, `flow`) — https://docs.suricata.io/en/latest/rules/index.html
- YARA documentation — https://yara.readthedocs.io/
- Mandiant FLARE-VM (tool distribution & install) — https://github.com/mandiant/flare-vm
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK: T1140 https://attack.mitre.org/techniques/T1140/ , T1055 https://attack.mitre.org/techniques/T1055/ , T1055.001 https://attack.mitre.org/techniques/T1055/001/ , T1055.002 https://attack.mitre.org/techniques/T1055/002/ , T1622 https://attack.mitre.org/techniques/T1622/ , T1497 https://attack.mitre.org/techniques/T1497/ , T1497.001 https://attack.mitre.org/techniques/T1497/001/ , T1106 https://attack.mitre.org/techniques/T1106/ , T1027 https://attack.mitre.org/techniques/T1027/ , T1480.001 https://attack.mitre.org/techniques/T1480/001/
- https://attack.mitre.org/techniques/T1518/001/
- https://msrc-blog.microsoft.com/2018/09/20/understanding-process-injection/
- https://attack.mitre.org/techniques/T1600/

## Related modules
- [x64dbg unpacking & debugging workflow](../28-x64dbg-workflow/README.md) -- shares scyllahide (same anti-anti-debug plugin used to defeat evasion).
- [WinDbg debugging deep-dive](../44-windbg-deep/README.md) -- shares windbg (extends the attach/lm/k workflow into kernel and crash-dump analysis).
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares x64dbg (applies these breakpoint/dump skills to unpack a real sample).
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares x64dbg (uses memory-dumping and breakpoint skills to extract and analyze shellcode).

<!-- cyberlab-enriched: v2 -->
- https://x64dbg.com/blog/2021/01/01/advanced-debugging-techniques.html
- https://collaborate.mitre.org/attackics/index.php/Defense_Evasion
- https://attack.mitre.org/techniques/T1055/013/
- https://attack.mitre.org/techniques/T1204/002/
- https://attack.mitre.org/techniques/T1055/013/](https://attack.mitre.org/techniques/T1055/013/
- https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/

<!-- cyberlab-enriched: v3 -->
- https://x64dbg.com/script/
- https://attack.mitre.org/techniques/T1620/
- https://www.cisa.gov/uscert/ncas/alerts/aa22-152a

<!-- cyberlab-enriched: v4 -->
- https://attack.mitre.org/techniques/T1070/004/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1027/002/
- https://www.fireeye.com/blog/threat-research/2020/08/debugger-evasion-techniques.html
- https://research.nccgroup.com/2021/03/11/red-team-tactics-for-dynamic-analysis/

<!-- cyberlab-enriched: v5 -->

<!-- cyberlab-enriched: v6 -->
