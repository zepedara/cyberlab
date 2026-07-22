# 28 * x64dbg unpacking & debugging workflow -- LAB-WINDOWS

## Overview (plain language)
When malware authors want to hide what their program does, they often "pack" or "obfuscate" it — squishing or scrambling the real code so it only appears in memory after the program starts running. A debugger lets an analyst run that program one step at a time, pause it, peek at memory, and grab the real code once it is unpacked. x64dbg is a friendly, open-source debugger for Windows programs (both 32-bit and 64-bit). ScyllaHide is an add-on that hides the debugger so sneaky programs cannot tell they are being watched. WinDbg is Microsoft's official debugger, useful for deeper kernel and crash-dump work. Together they form the core "run it carefully and watch what happens" toolkit for reverse engineers.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | `choco install x64dbg` (FLARE-VM) | Open-source user-mode debugger for 32/64-bit Windows binaries; step, breakpoint, dump memory. See project site https://x64dbg.com/ and docs https://help.x64dbg.com/ |
| ScyllaHide | bundled x64dbg plugin (FLARE-VM) | Anti-anti-debug plugin that masks debugger presence from evasive samples. See https://github.com/x64dbg/ScyllaHide |
| WinDbg | FLARE-VM package | Microsoft debugger for user-mode, kernel-mode, and crash/memory-dump analysis. See https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/ |

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
# Note: exact install paths depend on the FLARE-VM/Chocolatey layout; if the path
# differs, locate the binaries with:  Get-Command x64dbg -ErrorAction SilentlyContinue
```
> The 64-bit ScyllaHide plugin uses the `.dp64` extension and the 32-bit build uses `.dp32`; x64dbg loads plugins matching its bitness from the `plugins` folder next to the debugger executable (ScyllaHide README, https://github.com/x64dbg/ScyllaHide).

## Guided walkthrough
1. Generate the benign packed sample (see Hands-on exercise) and confirm it exists.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\packed_hello.exe
# Expected: prints a SHA256 hex digest for the sample
```
*Why:* `Get-FileHash` (a built-in PowerShell cmdlet, default algorithm SHA256) fingerprints the exact bytes you will debug so the OEP/RVA notes you record are tied to one build. See https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash

2. Open x64dbg from the command line and load the target for debugging.
```powershell
& "C:\Tools\x64dbg\release\x64\x64dbg.exe" ".\exercise\packed_hello.exe"
# Expected: x64dbg GUI opens, paused at the system/entry breakpoint
```
*Why:* By default x64dbg pauses at the **system breakpoint** (inside ntdll, before the program's entry point) and can also stop at the module **Entry Breakpoint**; both are configurable under Options → Preferences → Events. Starting paused lets you arm breakpoints before any packer code runs. See https://help.x64dbg.com/en/latest/gui/menus/options/Preferences.html

3. In the x64dbg command bar, set breakpoints on APIs a packer typically calls to allocate and hand off to unpacked code, then run.
```
bp VirtualAlloc
bp VirtualProtect
run
```
*Why:* Packers commonly reserve/commit memory for the decompressed image (`VirtualAlloc`) and then flip page protections to executable before the tail jump (`VirtualProtect`). Breaking on these APIs catches the moment unpacked bytes are prepared. `VirtualAlloc` allocates/commits pages in the calling process's address space; `VirtualProtect` changes protection (e.g. to `PAGE_EXECUTE_READWRITE`, value `0x40`) on committed pages — the new protection is passed in the third argument, so inspect the register holding it (on x64 that is `r8d`). See https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc and https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
Expected observable: execution pauses when the unpacking stub allocates/re-protects memory; the CPU pane shows the API call and, following the x64 calling convention (`rcx, rdx, r8, r9`), the register arguments. Note: for a simple UPX stub you may reach the OEP by other means (see step 5) even if these particular APIs are not hit — UPX decompresses in place and jumps to the OEP via a tail jump.

4. Enable ScyllaHide before continuing so evasive checks are neutralized. In the menu choose **Plugins -> ScyllaHide -> Options**, tick the x64dbg profile, then continue. ScyllaHide hooks the checks a sample uses to detect a debugger — including hiding the PEB `BeingDebugged` flag (which `IsDebuggerPresent` reads), spoofing `NtQueryInformationProcess` classes such as `ProcessDebugPort` (0x07), `ProcessDebugObjectHandle` (0x1E), or `ProcessDebugFlags` (0x1F), and neutralizing `CheckRemoteDebuggerPresent` and `NtSetInformationThread(ThreadHideFromDebugger)`. Expected: those checks now report "no debugger present." See the option descriptions in https://github.com/x64dbg/ScyllaHide and the Microsoft documentation for `NtQueryInformationProcess` classes: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess

5. After the stub finishes, use the built-in Scylla dumper (**Plugins -> Scylla**) at the suspected OEP to dump the process and rebuild imports. In Scylla: run **IAT Autosearch**, then **Get Imports**, then **Dump**, then **Fix Dump** on the dumped file. Expected: a rebuilt `packed_hello_dump.exe` written to disk. *Why:* the running process has a resolved Import Address Table (IAT) in memory but the raw dump's IAT pointers must be rebuilt into an importable form so the dumped PE loads statically; Scylla reconstructs the import directory and fixes the dump. See the Scylla project https://github.com/NtQuery/Scylla and the x64dbg docs https://help.x64dbg.com/

6. If a target crashes, capture and inspect the dump in WinDbg.
```powershell
& "windbg.exe" -z ".\exercise\hello.dmp"
# Then in the WinDbg command window:
#   !analyze -v
# Expected: faulting module, exception code, and reconstructed call stack
```
*Why:* the `-z` switch opens a crash/dump file for post-mortem debugging, and the `!analyze -v` extension performs verbose automated analysis (fault bucket, exception record, and call stack). See https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options and https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-analyze

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
> `cl.exe` is the MSVC compiler driver; `/Fe` names the output executable and `/nologo` suppresses the banner (https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file). `upx --best` selects the best available compression ratio; UPX is a reversible in-place packer and `upx -d` can restore the original for comparison (https://upx.github.io/ and https://github.com/upx/upx).

**Task:** Load `packed_hello.exe` in x64dbg, enable ScyllaHide, break on `VirtualProtect`, reach the OEP, and dump/rebuild the unpacked image. Record the OEP relative address and confirm the dumped binary still prints `Hello from OEP`.

## SOC analyst perspective
A SOC analyst rarely debugs on a production endpoint, but the artifacts of unpacking directly shape detections. Manually unpacking a captured sample in x64dbg yields the *real* code, strings, and C2 indicators that packed static scans miss — those IOCs feed Suricata and YARA rules distributed via Security Onion.

Concrete mapping and detection logic:
- **Software packing — T1027.002 (parent T1027).** UPX-packed PEs carry telltale `UPX0`/`UPX1` section names and high section entropy; hunt on-disk with YARA/entropy scanning and pivot to VirusTotal-style packer identification. UPX itself is legitimate, so treat packing as an enrichment signal, not a verdict. (https://attack.mitre.org/techniques/T1027/002/)
- **Process injection / RWX hand-off — T1055.** Live, the same "allocate then re-protect executable" pattern maps to Sysmon telemetry. In Security Onion, pivot in Elastic/Kibana on Sysmon **Event ID 8** (CreateRemoteThread) and **Event ID 10** (ProcessAccess with dangerous access masks such as `0x1F0FFF`/`PROCESS_ALL_ACCESS` or `0x1FFFFF`). (https://attack.mitre.org/techniques/T1055/ ; Sysmon event reference https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Suricata/Zeek pivots.** Once unpacking exposes C2 hosts/URIs, convert them into Suricata rules and correlate with Zeek `conn.log`, `dns.log`, and `http.log` in Security Onion; the Zeek `files.log`/file extraction and PE analyzer can flag executable transfers. (Security Onion docs https://docs.securityonion.net/ ; Zeek logs https://docs.zeek.org/en/master/logs/index.html ; Suricata rules https://docs.suricata.io/en/latest/rules/index.html)
- **Dump triage.** WinDbg `!analyze -v` on a crashing endpoint turns a fault into a story: faulting module, exception code, and stack often reveal the injected or exploited component. (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-analyze)
- **Detection Engineering:** The unpacking process leaves forensic artifacts. Monitor for the creation of memory regions with `PAGE_EXECUTE_READWRITE` protection (value `0x40`) via Sysmon **Event ID 10** (`ProcessAccess` with `CallTrace` containing `VirtualProtect`). Additionally, hunt for processes with high entropy in their `.text` section using EDR telemetry or Windows Event Tracing (ETW) for `Microsoft-Windows-Threat-Intelligence` provider events (Event ID 7: `ImageLoad`). A sudden change in a process's working set size after a `VirtualAlloc` call can also indicate unpacking activity. Correlate these with **T1055.001 (Dynamic-link Library Injection)** and **T1055 (Process Injection)**. (MITRE ATT&CK T1055.001: https://attack.mitre.org/techniques/T1055/001/)
- **Threat Hunting Pivots:** In Security Onion, use Zeek's `pe.log` to identify packed binaries by analyzing `section_entropy` fields. A `section_entropy` value above 7.0 for the `.text` or code section is a strong indicator of packing (SANS FOR610). Combine this with Suricata alerts for outbound connections (`event_type:alert`) from processes that recently allocated large RWX memory regions. Query Elasticsearch for Sysmon Event ID 1 (`ProcessCreate`) where the `Image` ends with a known packer name (e.g., `upx.exe`) or the `CommandLine` contains packing flags, mapping to **T1204.002 (Malicious File)**. (MITRE ATT&CK T1204.002: https://attack.mitre.org/techniques/T1204/002/)

## Attacker perspective
Attackers pack and obfuscate payloads to defeat signature scanners and slow analysis (**T1027 / T1027.002**), and add anti-debug checks so the sample behaves differently or bails out when watched (**T1622 Debugger Evasion**). Concrete TTPs and the checks ScyllaHide neutralizes:
- **PEB inspection:** reading `BeingDebugged` (via `IsDebuggerPresent`) or the `NtGlobalFlag` field.
- **Syscall queries:** `NtQueryInformationProcess` with `ProcessDebugPort` (0x07), `ProcessDebugObjectHandle` (0x1E), or `ProcessDebugFlags` (0x1F). (https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
- **Thread hiding:** `NtSetInformationThread(ThreadHideFromDebugger)` to detach debug events.
- **Remote check / timing traps:** `CheckRemoteDebuggerPresent` and `rdtsc`/`GetTickCount` timing deltas.

These map to MITRE ATT&CK T1622 (https://attack.mitre.org/techniques/T1622/). Artifacts the technique leaves for defenders: RWX / unbacked executable memory regions, decompressed strings and reconstructed IAT visible in the live process, and dumped images whose section layout differs from the on-disk packed file. Evasion continues after unpacking — e.g. process hollowing / injection to run from a benign host process (T1055). Defenders find these via memory scanning (pe-sieve / HollowsHunter, https://github.com/hasherezade/pe-sieve), EDR memory-integrity alerts, and Sysmon process-access telemetry (EID 8/10).

**Additional TTPs and Artifacts:**
- **Reflective DLL Loading (T1620):** To avoid writing a DLL to disk, attackers may reflectively load a DLL directly from memory. This technique bypasses traditional DLL load monitoring (Windows Event ID 7: `ImageLoad`). The artifact is an executable memory region that lacks a corresponding file on disk, detectable by tools like pe-sieve. (MITRE ATT&CK T1620: https://attack.mitre.org/techniques/T1620/)
- **Process Hollowing (T1055.012):** A subset of process injection where a legitimate process is created in a suspended state, its memory is unmapped/hollowed out, and replaced with malicious code. This leaves artifacts in the process's memory sections (VAD - Virtual Address Descriptor) showing private committed memory with execute permissions that do not map to the original image file. Detection can focus on Sysmon Event ID 10 (`ProcessAccess`) with `CallTrace` including `NtUnmapViewOfSection` or `NtMapViewOfSection`. (MITRE ATT&CK T1055.012: https://attack.mitre.org/techniques/T1055/012/)
- **Obfuscation via API Hashing (T1027.010):** Malware may resolve API addresses at runtime using hashed DLL and function names to evade string-based detection. During debugging, this appears as a series of `LoadLibrary` and `GetProcAddress` calls with numeric arguments. The artifact is a lack of clear import strings in the static binary but resolved API calls in the live process's IAT after unpacking. (MITRE ATT&CK T1027.010: https://attack.mitre.org/techniques/T1027/010/)

## Answer key
- Expected OEP: the unpacking stub jumps to the real `main`/CRT startup; in x64dbg it appears as a `jmp` into a lower-address code region after the UPX stub finishes (for UPX the tail jump lands on the original entry point). Note the relative virtual address (RVA) shown in the CPU pane. A reliable way to catch a UPX tail jump is to set a hardware/memory breakpoint on the packed section or single-step the final `jmp`.
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
- Cross-check by unpacking with UPX directly (UPX is reversible) and comparing behavior:
```powershell
upx -d .\exercise\packed_hello.exe -o .\exercise\unpacked_ref.exe
& .\exercise\unpacked_ref.exe
# Expected output: Hello from OEP  (confirms your x64dbg dump matches the reference)
```
- Sample integrity: compute the SHA256 of your locally built target and record it in the module log; because it is UPX-packed from your own source the digest is reproducible per build. Confirm it matches after generation:
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\packed_hello.exe | Format-List
# Expected: a single SHA256 hex digest; store this value as the sample's declared hash
```

## MITRE ATT&CK & DFIR phase
- **T1027 / T1027.002** — Obfuscated Files or Information: Software Packing. https://attack.mitre.org/techniques/T1027/002/
- **T1055** — Process Injection (RWX allocation / hand-off patterns observed while debugging). https://attack.mitre.org/techniques/T1055/
- **T1055.001** — Process Injection: Dynamic-link Library Injection. https://attack.mitre.org/techniques/T1055/001/
- **T1055.012** — Process Injection: Process Hollowing. https://attack.mitre.org/techniques/T1055/012/
- **T1204.002** — User Execution: Malicious File. https://attack.mitre.org/techniques/T1204/002/
- **T1620** — Reflective Code Loading. https://attack.mitre.org/techniques/T1620/
- **T1622** — Debugger Evasion (anti-debug checks neutralized by ScyllaHide). https://attack.mitre.org/techniques/T1622/
- **T1027.010** — Obfuscated Files or Information: Command Obfuscation (API Hashing). https://attack.mitre.org/techniques/T1027/010/
- **DFIR phase:** Examination / Analysis (dynamic malware analysis and dump triage), feeding Reporting/Detection-engineering. See NIST SP 800-86 phases (Collection, Examination, Analysis, Reporting) https://csrc.nist.gov/pubs/sp/800/86/final


### Essential Commands & Features

Mastering **conditional breakpoints**, **memory map analysis**, and **hardware breakpoints** in x64dbg unlocks advanced unpacking and evasion detection. Below are the most critical undemonstrated commands and features, with concrete examples and tactical use cases:

---

#### **1. Conditional Breakpoints (Unpacking & Anti-Debug Evasion)**
**When to use**: Bypass anti-debug checks (e.g., `IsDebuggerPresent`) or trigger breakpoints only when specific unpacking conditions are met (e.g., OEP detection).
**Example**: Break when `EAX == 0x55555555` (common OEP marker) at `0x00401234`:
```bash
bp 0x00401234, "eax == 0x55555555"
```
**MITRE ATT&CK**: [T1647: Plist Modification](https://attack.mitre.org/techniques/T1647/) (macOS evasion via conditional logic).

---

#### **2. Memory Map & Section Analysis (Unpacked Code Extraction)**
**When to use**: Identify newly allocated memory sections (e.g., `.rdata` or `.text` post-unpack) or dump decrypted payloads.
**Key Commands**:
- **List sections**: `memmap` (view memory regions) or `dumpmem <addr> <size> <file>` (extract memory).
- **Highlight executable regions**: Right-click in *Memory Map* → *Find Pattern* → `MZ` (PE header).
**Example**: Dump 0x1000 bytes from `0x00600000` to `unpacked.bin`:
```bash
dumpmem 0x00600000, 0x1000, "unpacked.bin"
```
**MITRE ATT&CK**: [T1074.001: Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/) (exfiltrate unpacked payloads).

---

#### **3. Hardware Breakpoints (Anti-Tampering & Unpacking)**
**When to use**: Monitor read/write/execute access to specific memory addresses (e.g., IAT reconstruction or anti-tamper hooks).
**Example**: Break on execute at `0x00403000` (hardware breakpoint):
```bash
bphws 0x00403000, "x"
```
**Flags**:
- `r` (read), `w` (write), `x` (execute), or `rw` (read

### Threat Hunting & Detection Engineering
To enhance threat hunting and detection engineering in the context of x64dbg workflow, focus on identifying techniques that involve modifying system binaries or executing malicious code in memory. For instance, **T1497: Virtualization/Sandbox Evasion** and **T1610: Windows Management Instrumentation**, are techniques that can be detected through careful analysis of system and application logs. Monitoring Windows Event IDs such as 4688 (Process Creation) for unusual command line arguments or parent-child process relationships can help in detecting these techniques. Additionally, analyzing network traffic with tools like Zeek or Suricata for signs of WMI (Windows Management Instrumentation) abuse, such as unusual WMI query patterns, can aid in threat hunting. Pivoting on these findings, investigators can look into system calls, API hooks, or other indicators of compromise that suggest evasion or WMI exploitation. For more detailed information on threat hunting and detection techniques, visit the [Cybok Knowledge Base](https://www.cybok.org/) or [NCSC-NL Open Source](https://github.com/NCSC-NL/open-source).


### Essential Commands & Features

Master these **undemonstrated** x64dbg capabilities to accelerate reverse-engineering and malware analysis:

1. **Conditional Breakpoints**
   Use when execution hits a loop or API call *only under specific conditions* (e.g., `EAX == 0xDEADBEEF`). Right-click a breakpoint → *Edit* → enter expression, e.g., `[EAX]==0xDEADBEEF`. Critical for analyzing **T1059.003 (Command and Scripting Interpreter: Windows Command Shell)** where adversaries obfuscate payloads via environment variables.
   ```bash
   ; Example: Break if WriteProcessMemory is called with target PID 1234
   [@arg3]==1234
   ```

2. **Scripting API**
   Automate repetitive tasks (e.g., dumping unpacked code) via Python or x64dbg’s native `.scr` scripts. Load scripts via *File → Script* or `scriptload("C:\path\dump_memory.scr")`. Vital for **T1562.001 (Impair Defenses: Disable or Modify Tools)** where malware disables AV before execution.
   ```python
   # Python example: Dump .text section to file
   from x64dbg import *
   dbg.memdump(0x401000, 0x1000, "C:\\dump.bin")
   ```

3. **Memory Map/Section Analysis**
   Inspect memory regions (*View → Memory Map*) to identify injected code or unpacked sections. Right-click a region → *Follow in Dump* to analyze raw bytes. Key for detecting **T1055.002 (Process Injection: Portable Executable Injection)**.
   ```bash
   ; CLI: List all executable sections
   mem.findall("PAGE_EXECUTE_READWRITE")
   ```

4. **Hardware Breakpoints**
   Set on *read/write/execute* of specific addresses (e.g., `DR0`–`DR3`). Right-click instruction → *Breakpoint → Hardware, on Execution*. Ideal for tracking **T1106 (Native API)** calls without software breakpoint artifacts.
   ```bash
   ; Set hardware BP on read of 0x403000
   bphws 0x403000, "r"
   ```

**Sources**:
- [x64dbg Scripting Documentation (GitBook)](https://x64dbg.com/script/)
- [MITRE ATT&CK: T1059.003](https://attack.mitre.org/techniques/T1059/003/) | [T1562.00

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, **x64dbg** is a powerful tool for dynamic binary analysis, enabling attackers to reverse engineer, modify, and weaponize legitimate software or malware. A common tactic involves **process injection (T1055.004: Asynchronous Procedure Call)** to execute malicious code within a trusted process, evading detection by blending into legitimate behavior. Attackers may use x64dbg to identify injection points, patch memory, or bypass security controls (e.g., ASLR, DEP) by analyzing runtime behavior. Another key technique is **obfuscated files or information (T1027.009: Embedded Payloads)**, where adversaries embed malicious payloads within benign executables, using x64dbg to debug and refine evasion tactics (e.g., API unhooking, string encryption).

**Artifacts left behind** include:
- Modified memory regions (e.g., `.text` section patches).
- Unusual process handles or threads (e.g., `CreateRemoteThread` calls).
- Debugger-specific registry keys (e.g., `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`).
- Logs of API calls (e.g., `VirtualAllocEx`, `WriteProcessMemory`).

**Evasion considerations** include:
- Anti-debugging checks (e.g., `IsDebuggerPresent`, `NtQueryInformationProcess`).
- Timing-based evasion (e.g., `rdtsc` instruction analysis).
- Disabling ETW or AMSI via runtime patches.

For further reading:
- [FireEye: Process Injection Techniques](https://www.fireeye.com/blog/threat-research/2020/03/six-facts-about-address-space-layout-randomization-on-windows.html)
- [CrowdStrike: Adversary Tradecraft and TTPs](https://www.crowdstrike.com/blog/tech-center/process-injection/)


### Essential Commands & Features

#### **x64dbg: Conditional Breakpoints**
Conditional breakpoints halt execution only when a specified expression evaluates to true, critical for analyzing **T1574.002 (Hijack Execution Flow: DLL Side-Loading)** or **T1137.001 (Office Application Startup: Office Template Macros)**. For example, to break when `EAX == 0xDEADBEEF` at `0x401000`:
1. Right-click the instruction at `0x401000` → *Breakpoint* → *Set Conditional*.
2. Enter `EAX == 0xDEADBEEF` and click *OK*.
3. Run the program; execution pauses only when the condition is met.

#### **x64dbg: Scripting API**
Automate repetitive tasks (e.g., dumping memory regions during **T1003.001 (OS Credential Dumping: LSASS Memory)**) using Python or the built-in scripting engine. Example to log all calls to `WriteProcessMemory`:
```python
from x64dbg import *
def callback():
    log(f"WriteProcessMemory called at {hex(eip)}")
    return 0
script.registerFunction(callback, "kernel32.dll", "WriteProcessMemory")
```

#### **x64dbg: Memory Map/Section Analysis**
Inspect memory regions for injected code (e.g., **T1055.003 (Process Injection: Thread Execution Hijacking)**). In the *Memory Map* tab:
1. Right-click a region → *Follow in Dump* to view raw bytes.
2. Use *Search* → *Memory* → *Pattern* to scan for shellcode (e.g., `\x90\x90\xCC`).

#### **WinDbg: `!analyze -v`**
Automate crash dump analysis to identify root causes (e.g., **T1499.004 (Endpoint Denial of Service: Application Exhaustion Flood)**). Run:
```
!analyze -v
```
This outputs detailed bugcheck data, stack traces, and module information.

#### **WinDbg: `.dump` and `.wr`**
Capture process memory (`.dump /ma C:\dump.dmp`) for offline analysis of **T1055.012 (Process Injection: Process Hollowing)**. Use `.wr` to write a memory range to a file:
```
.wr 0x400000 L?0x1000 C:\mem.bin
```

**Sources:**
- [x64dbg Scripting Documentation](https://help.x64dbg.com/en/latest/introduction/Script

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Microsoft Workflow Compiler Execution** (source: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_microsoft_workflow_compiler_execution.yml; license: Detection Rule License / DRL):

```yaml
title: Microsoft Workflow Compiler Execution
id: 419dbf2b-8a9b-4bea-bf99-7544b050ec8d
status: test
description: |
    Detects the execution of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
    - https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/
author: Nik Seetharaman, frack113
date: 2019-01-16
modified: 2023-02-03
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
    - attack.t1218
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Microsoft.Workflow.Compiler.exe'
        - OriginalFileName: 'Microsoft.Workflow.Compiler.exe'
    condition: selection
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: medium
```

**Real-world context (MITRE T1027.002 -- Obfuscated Files or Information: Software Packing):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1027/002/ -- real in-the-wild use includes Sandworm, APT29, APT3, APT38, APT39, APT41.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `28_x64dbg_workflow_benign_sample.txt` |
| sample sha256 | `f6e8eb45d009f97d0610007ab72b0751c7b19c9029de09ca51e766631722479c` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 28-x64dbg-workflow -- for detection-rule testing only
' |
### Essential Commands & Features

Mastering **conditional breakpoints** and **memory search** in x64dbg accelerates API tracing and Original Entry Point (OEP) discovery—critical for analyzing packed malware (e.g., **T1027.001: Software Packing**) or detecting process injection (e.g., **T1055.002: Portable Executable Injection**).

#### Conditional Breakpoints
Use `SetBPX` with conditions to filter noise. For example, break only if `EAX` holds a specific API address (e.g., `VirtualAlloc`):
```bash
SetBPX kernel32.VirtualAlloc, "EAX == 0x7FFE0000"
```
**When to use**: Isolate calls with suspicious parameters (e.g., `flProtect=0x40` for `PAGE_EXECUTE_READWRITE`).

#### Memory Search
Leverage the **Memory Map** (`Alt+M`) to search for patterns (e.g., shellcode signatures) or dump regions:
1. Right-click a memory region → **Find Pattern** (`Ctrl+B`).
2. Search for `C3` (RET) to locate function epilogues, aiding OEP recovery in stripped binaries.
3. Use **Find References** (`Ctrl+R`) on API addresses (e.g., `CreateRemoteThread`) to trace cross-references.

**Pro Tip**: Combine with **Trace Into** (`F7`) and **Log Breakpoint** (`Shift+F2`) to record execution flow without manual stepping.

**Sources**:
- [x64dbg Official Wiki: Breakpoints](https://wiki.x64dbg.com/en/latest/commands/breakpoints/index.html)
- [SANS FOR610: Memory Forensics & Malware Analysis](https://www.sans.org/blog/for610-memory-forensics-and-malware-analysis/)

### Common Pitfalls & Result Validation

Analysts frequently misinterpret x64dbg outputs, leading to false conclusions. A common pitfall is **overlooking anti-debugging techniques** (e.g., **T1621: Debugger Evasion**), where malware detects breakpoints or single-stepping via `IsDebuggerPresent()` or `NtQueryInformationProcess`. This can cause the sample to alter behavior or crash, invalidating analysis. Always validate by checking for suspicious API calls or conditional jumps that depend on debug-related flags. Another mistake is **assuming static disassembly matches runtime execution**, particularly with **T1648: Serverless Execution**, where code may unpack or decrypt payloads dynamically. Relying solely on static views (e.g., the *Disassembly* tab) without cross-referencing the *Memory Map* or *Dump* can miss critical artifacts.

To validate findings:
1. **Cross-check breakpoints**: Use hardware breakpoints (`Shift+F2`) instead of software breakpoints (`F2`) to evade detection.
2. **Monitor memory changes**: Compare the *Memory Map* before/after suspicious calls to detect injected code or unpacked payloads.
3. **Reproduce behavior**: Restart the session and re-execute to confirm consistency, especially after crashes or unexpected exits.

Avoid false positives by documenting all steps and correlating x64dbg outputs with external tools (e.g., Process Hacker for memory forensics). For authoritative guidance, refer to:
- [CERT-EU’s Malware Analysis Guide (Anti-Debugging)](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Malware_Analysis.pdf)
- [FLARE VM Documentation (Debugging Pitfalls)](https://github.com/mandiant/flare-vm)

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1027 (Obfuscated Files or Information)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1027/
- **Threat actors documented using it:** Sandworm (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → authoritative source mapping (all URLs are real, official/vendor/authoritative pages):

- FLARE-VM package list and installation → https://github.com/mandiant/flare-vm
- x64dbg project site and official documentation (breakpoints `bp`, `run`, system/entry breakpoint behavior, Scylla plugin) → https://x64dbg.com/ and https://help.x64dbg.com/
- x64dbg Preferences/Events (system breakpoint & entry breakpoint options) → https://help.x64dbg.com/en/latest/gui/menus/options/Preferences.html
- ScyllaHide project — plugin extensions (`.dp64`/`.dp32`), anti-anti-debug option coverage (PEB `BeingDebugged`, `NtQueryInformationProcess`, `NtSetInformationThread`, `CheckRemoteDebuggerPresent`) → https://github.com/x64dbg/ScyllaHide
- Scylla import reconstruction / dumping (IAT Autosearch, Get Imports, Dump, Fix Dump) → https://github.com/NtQuery/Scylla
- Microsoft WinDbg / Debugging Tools for Windows → https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- WinDbg command-line options (`-z` to open a dump) → https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options
- WinDbg `!analyze -v` extension → https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-analyze
- Windows `VirtualAlloc` (allocate/commit pages) → https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
- Windows `VirtualProtect` (change page protection; `PAGE_EXECUTE_READWRITE` = 0x40) → https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
- `NtQueryInformationProcess` (ProcessDebugPort/Flags/ObjectHandle classes) → https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
- `Get-FileHash` (SHA256 default) → https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- MSVC `cl.exe` `/Fe` and `/nologo` flags → https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file and https://learn.microsoft.com/en-us/cpp/build/reference/nologo-suppress-startup-banner
- UPX packer (`--best`, `-d` decompress, in-place reversible packing, `UPX0`/`UPX1` sections) → https://upx.github.io/ and https://github.com/upx/upx
- Sysmon events (EID 8 CreateRemoteThread, EID 10 ProcessAccess) → https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Security Onion documentation (Suricata/Zeek/Elastic pivots) → https://docs.securityonion.net/
- Zeek log reference (`conn.log`, `dns.log`, `http.log`, `files.log`, `pe.log`) → https://docs.zeek.org/en/master/logs/index.html
- Suricata rules documentation → https://docs.suricata.io/en/latest/rules/index.html
- pe-sieve / HollowsHunter (memory scanning for injected/unbacked code) → https://github.com/hasherezade/pe-sieve
- SANS FOR610 Reverse-Engineering Malware course (entropy thresholds for packing) → https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- NIST SP 800-86 (DFIR process phases) → https://csrc.nist.gov/pubs/sp/800/86/final
- MITRE ATT&CK T1027 Obfuscated Files or Information → https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 Software Packing → https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1027.010 Command Obfuscation → https://attack.mitre.org/techniques/T1027/010/
- MITRE ATT&CK T1055 Process Injection → https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.001 Dynamic-link Library Injection → https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1055.012 Process Hollowing → https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK T1204.002 Malicious File → https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1620 Reflective Code Loading → https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1622 Debugger Evasion → https://attack.mitre.org/techniques/T1622/

## Related modules
- [Dynamic debugging](../13-dynamic-debugging/README.md) -- shares scyllahide for anti-anti-debug during live analysis.
- [WinDbg debugging deep-dive](../44-windbg-deep/README.md) -- shares windbg for deeper user/kernel and dump triage.
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares x64dbg in an end-to-end unpacking case.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares x64dbg for extracting and analyzing shellcode.

<!-- cyberlab-enriched: v2 -->
- https://attack.mitre.org/techniques/T1647/
- https://attack.mitre.org/techniques/T1074/001/
- https://www.cybok.org/
- https://github.com/NCSC-NL/open-source

<!-- cyberlab-enriched: v3 -->
- https://x64dbg.com/script/
- https://attack.mitre.org/techniques/T1059/003/
- https://www.fireeye.com/blog/threat-research/2020/03/six-facts-about-address-space-layout-randomization-on-windows.html
- https://www.crowdstrike.com/blog/tech-center/process-injection/

<!-- cyberlab-enriched: v4 -->
- https://help.x64dbg.com/en/latest/introduction/Script
- https://attack.mitre.org/techniques/T1070/"
- https://attack.mitre.org/techniques/T1070/

<!-- cyberlab-enriched: v5 -->
- https://wiki.x64dbg.com/en/latest/commands/breakpoints/index.html
- https://www.sans.org/blog/for610-memory-forensics-and-malware-analysis/
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Malware_Analysis.pdf

<!-- cyberlab-enriched: v6 -->
