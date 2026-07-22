# 54 * Scenario: shellcode extraction & analysis -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a small chunk of raw machine instructions that attackers inject into a program to make it run their code — it is not a normal `.exe`, just bytes. Because it has no friendly file structure, you cannot just double-click it. Instead, analysts use two kinds of tools: an *emulator* like **scdbg**, which pretends to be a tiny Windows CPU and "runs" the bytes in a safe, fake environment while logging every Windows API the shellcode tries to call, and a *debugger* like **x64dbg**, which lets you load the bytes into memory and step through them instruction by instruction on a real (but controlled) machine. Together they answer: what does this blob actually *do* — download a file, spawn a shell, decode a stage-two payload? This module walks you through extracting shellcode from a benign carrier and analyzing its behavior without ever letting it touch the internet.

> Note on scope: `scdbg` is built on the **libemu** x86 CPU/Win32 emulation library and emulates **32-bit** shellcode only. It does not emulate 64-bit shellcode, so this module deliberately uses a 32-bit sample and the 32-bit debugger (`x32dbg`). (See scdbg project page: http://sandsprite.com/blogs/index.php?uid=7&pid=152 and the libemu docs: https://github.com/buffer/libemu)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | Pre-installed on FLARE-VM (`scdbg.exe`) | Emulates 32-bit shellcode via libemu and logs Windows API calls it attempts, without native execution |
| x64dbg | Pre-installed on FLARE-VM (`x64dbg` / `x32dbg` / `x64dbg`) | Interactive open-source user-mode debugger to step through shellcode loaded into memory |

Tool references: scdbg is distributed by sandsprite (http://sandsprite.com/blogs/index.php?uid=7&pid=152) and is packaged in FLARE-VM (https://github.com/mandiant/flare-vm) and REMnux (https://docs.remnux.org/discover-the-tools/analyze+code/emulate+code). x64dbg is an open-source x64/x32 debugger (https://x64dbg.com/ and https://github.com/x64dbg/x64dbg).

### Essential Commands & Features (scdbg)
The `scdbg` tool provides the following command-line flags (verified against official documentation http://sandsprite.com/blogs/index.php?uid=7&pid=152 and REMnux guide https://docs.remnux.org/discover-the-tools/analyze+malicious+files/shellcode#scdbg):

- **`/f <file>`** – Load a file as raw shellcode. Example: `scdbg /f sample.bin`
- **`/foff <offset>`** – Start emulation at a byte offset within the file. Useful for skipping headers or decoder stubs. Example: `scdbg /f sample.bin /foff 0x200`
- **`/s <maxsteps>`** – Cap the number of emulated instructions to avoid infinite loops. Example: `scdbg /f sample.bin /s 2000000`
- **`/findsc`** – Scan the file for likely shellcode entry points and report them. Example: `scdbg /f sample.bin /findsc`
- **`/?`** – Show usage help.

There is no interactive mode, no breakpoint API flag, and no memory dump flag in the published version of scdbg. Emulation output is driven solely by the libemu engine.

## Learning objectives
- Extract a raw shellcode blob from a benign carrier file into a standalone `.bin`.
- Emulate the blob with `scdbg` and enumerate the Windows API calls it resolves and invokes.
- Identify the shellcode's likely intent (e.g., API hashing, `WinExec`, download) from emulation output.
- Load and single-step the same blob in x64dbg to confirm the emulated behavior at the instruction level.

## Environment check
```powershell
# Prove both tools resolve on LAB-WINDOWS (FLARE-VM).
# scdbg prints its usage/options banner when run with no valid input or /?.
scdbg.exe /? 

# x64dbg ships as x64dbg.exe / x32dbg.exe; confirm the launcher is present.
Get-Command x32dbg.exe, x64dbg.exe -ErrorAction SilentlyContinue |
  Select-Object Name, Source
```
Expected output: `scdbg.exe /?` prints an options list — documented flags include `/f <file>` (load file as shellcode), `/foff <offset>` (start file offset), `/s <maxsteps>` (max step count), and `/findsc` (scan for likely shellcode entry points). See the scdbg usage reference (http://sandsprite.com/blogs/index.php?uid=7&pid=152). `Get-Command` prints one or two rows showing the resolved paths of the debugger executables. If a name is missing, launch it from the FLARE-VM Start-menu shortcut to confirm installation.

## Guided walkthrough
1. Generate a benign, inert 32-bit shellcode sample (a tiny stub that only calls `WinExec("calc.exe")` via PEB-walk API resolution — see Hands-on for the exact generator). Place it in `exercise/`.
```powershell
# Confirm the sample exists and note its size/hash before analysis.
# Hashing first establishes a chain-of-custody baseline: the same bytes
# must be what you emulate and later debug, so record it before touching it.
Get-FileHash .\exercise\sample_shellcode.bin -Algorithm SHA256
```
Expected: prints a SHA256 hash matching the value in the Answer key. `Get-FileHash` is a built-in PowerShell cmdlet whose default algorithm is SHA256, made explicit here for clarity (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash).

2. Emulate the blob with `scdbg`. The emulator loads the bytes at a virtual base, runs them under libemu's emulated CPU, and logs each resolved/called API. WHY: emulation is the safest first pass — no native instruction ever executes on your host, so even hostile shellcode cannot spawn a real process or reach the network.
```powershell
# /f loads the file as raw shellcode; scdbg begins emulation at offset 0
# unless told otherwise (see /foff and /findsc below).
scdbg.exe /f .\exercise\sample_shellcode.bin
```
Expected: a call trace showing API resolution and invocation such as `LoadLibraryA`, `GetProcAddress`, and a terminal `WinExec(calc.exe)` line, followed by a `Stepcount` summary. NUANCE: the trace prints APIs *in the order the shellcode resolves and calls them*, so the sequence itself reveals intent (resolve → look up → execute). This is emulation only — no real process is spawned.

3. Re-run scdbg with an explicit start offset and a step cap if auto-start misses the real entry (common when a blob is prefixed by a decoder or junk bytes). WHY: `/foff` lets you point the emulator at the true first instruction, and `/s` bounds runtime so a decode loop cannot hang the emulator.
```powershell
# /foff sets a file offset for the entry point; /s <n> caps the step count.
scdbg.exe /f .\exercise\sample_shellcode.bin /foff 0 /s 2000000
```
Expected: same API trace; `/s` prevents runaway loops from hanging the emulator. If you do not know the entry, `scdbg.exe /f .\exercise\sample_shellcode.bin /findsc` scans for likely entry offsets and lets you pick one. (Flag semantics: http://sandsprite.com/blogs/index.php?uid=7&pid=152)

4. Load the blob in x64dbg for instruction-level confirmation. WHY: emulation can be incomplete (unsupported APIs, anti-emulation checks), so stepping the real bytes in a controlled debugger verifies the finding. In the GUI: `File > Open` a small loader stub that maps the raw bytes and transfers control (raw `.bin` has no PE header, so it cannot be opened as a process directly), or paste the bytes into a scratch process's memory (`RWX` region) and set the instruction pointer (`EIP`) to their start. Set a breakpoint on `kernel32.WinExec` and run.
```powershell
# Launch the 32-bit debugger (x32dbg) because the sample is 32-bit x86;
# the rest is GUI-driven.
x32dbg.exe
```
Expected: execution halts at the `WinExec` breakpoint; the stack shows a pointer to the `calc.exe` string (the first stacked argument), confirming scdbg's finding. Setting breakpoints on API symbols and inspecting the call stack are core x64dbg features (https://help.x64dbg.com/en/latest/gui/index.html).

## Hands-on exercise
Analyze the sample in this module's `exercise/` directory.

- **Sample type:** raw 32-bit x86 shellcode blob, `exercise/sample_shellcode.bin`.
- **Safe origin:** benign/inert. It is generated locally by the reproducible NASM command below. It contains only API-hashing stubs that resolve and call `WinExec` against the string `calc.exe`; it performs **no network egress** and does not persist. Run analysis under scdbg emulation first (never a real native run against untrusted bytes).
- **Reproducible generator** (uses NASM; produces the exact bytes hashed in the Answer key):
```powershell
# Build the benign shellcode from source in exercise/ using NASM (FLARE-VM).
# -f bin emits a flat raw binary with no headers/relocations — exactly what
# position-independent shellcode is (https://www.nasm.us/xdoc/2.16.01/html/nasmdoc7.html).
nasm -f bin .\exercise\sample_shellcode.asm -o .\exercise\sample_shellcode.bin
Get-FileHash .\exercise\sample_shellcode.bin -Algorithm SHA256
```
Where `exercise/sample_shellcode.asm` is a WinExec("calc.exe") stub using PEB-walk API resolution.

**Tasks:**
1. Report the sample's SHA256.
2. List every Windows API `scdbg` observes being resolved/called.
3. State the shellcode's intent in one sentence.
4. Confirm the `WinExec` argument string in x64dbg.

### Common Pitfalls & Result Validation
Analysts often make mistakes by not properly validating findings, leading to false conclusions. For shellcode analysis, common pitfalls include:
- Mistaking API hashing (T1027.007) for plain string references — scdbg resolves the hashes automatically, but the raw shellcode string dump shows only hash constants, not function names.
- Misinterpreting emulation output when the shellcode contains anti-emulation checks (e.g., timing loops, unsupported API probes). In such cases, scdbg may report no API calls or a truncated trace. Always confirm with x64dbg single-stepping.
- Incorrectly identifying the ATT&CK technique (e.g., conflating Process Injection (T1055) with User Execution (T1204) when the shellcode is launched by a document macro). Analyze the full execution chain.

To validate results: cross-reference the scdbg API trace with the x64dbg disassembly, ensure the called addresses match the expected hashing algorithm, and verify the argument string in memory. For authoritative guidance, see SANS FOR610 (reverse-engineering malware) and MITRE ATT&CK technique pages.

## SOC analyst perspective
In an incident, shellcode rarely arrives as a neat file — it is carved from packet captures, office-document macros, or memory dumps of an injected process. A defender uses `scdbg` to triage such carved blobs quickly: the API trace reveals C2 URLs, spawned processes, or staging behavior without running live malware.

Detection logic and Security Onion pivots:
- **Delivery on the wire.** Suricata (Emerging Threats ruleset) flags many injectors/loaders and exploit stagers; in Security Onion, pivot from the Suricata `alert` to the matching Zeek `conn.log`/`http.log`/`files.log` to identify and carve the transferred object (https://docs.securityonion.net/en/2.4/suricata.html, https://docs.securityonion.net/en/2.4/zeek.html). Zeek's file-extraction framework can dump HTTP/SMB objects for offline scdbg analysis.
- **Map the scdbg trace to ATT&CK.** A blob that resolves APIs via PEB walk and calls `WinExec`/`CreateProcess` maps to **Native API (T1106)** and **Command and Scripting Interpreter / process launch** behavior; injected shellcode maps to **Process Injection (T1055)**; a stager that pulls a follow-on payload maps to **Ingress Tool Transfer (T1105)**; hashed/obfuscated API names map to **Obfuscated Files or Information (T1027)** and specifically **T1027.007 Dynamic API Resolution**.
- **Host telemetry (Elastic in Security Onion).** Hunt Sysmon Event ID 8 (`CreateRemoteThread`) and Event ID 10 (`ProcessAccess` with suspicious `GrantedAccess` like `0x1F0FFF`/`0x1FFFFF`) for injection; Event ID 1 (`ProcessCreate`) with anomalous parent-child pairs (e.g., `winword.exe` → `calc.exe`/`cmd.exe`) surfaces the spawned process the scdbg trace predicted (Sysmon reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **Additional detection engineering logic:**
  - Windows Event ID 4688 (Process Creation) with `CommandLine` containing known shellcode loaders (e.g., `rundll32.exe`, `regsvr32.exe`, `mshta.exe`) — correlate with MITRE technique **T1218 System Binary Proxy** (https://attack.mitre.org/techniques/T1218/). Example: `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";` is a common shellcode delivery vector.
  - Sysmon Event ID 7 (Image loaded) for DLLs loaded by a process that are not typically seen (e.g., `mscorlib.dll` in `notepad.exe`), indicating potential process injection.
  - Network telemetry: Zeek `conn.log` fields `service` (e.g., HTTP, SSL) and `uid` paired with `files.log` `mime_type` `application/octet-stream` can identify raw binary transfers. Suricata keyword `file.data` in a rule can match the first bytes of known shellcode stubs (https://docs.suricata.io/en/latest/rules/file-keywords.html).
- **Threat-hunting pivots:**
  - Hunt for memory regions allocated with `PAGE_EXECUTE_READWRITE` (RWX) in process memory – query Elastic for `process.name:` and `memory.protection: "PAGE_EXECUTE_READWRITE"`. This is a strong indicator of potential shellcode injection.
  - Hunt for processes that have loaded `kernel32.dll` but have no static import table for `WinExec` or `CreateProcess` — anomalous for typical executables, suggesting runtime API resolution.
  - Correlate scdbg API traces with known APT groups: e.g., a shellcode stub that uses ROR-13 hash algorithm is characteristic of Cobalt Strike (https://www.cobaltstrike.com/).
- **Turn findings into signatures.** Feed the resolved API sequence, decoded strings, and any callback host into new YARA/Suricata rules; x64dbg confirms exact behavior when emulation is incomplete.

### Threat Hunting & Detection Engineering (Advanced)
Once shellcode behavior is profiled in **scdbg** or **x64dbg**, pivot to threat hunting using concrete log sources and detection logic:

- **Windows Event Logs (Sysmon Event ID 8: `CreateRemoteThread`)** – Hunt for `TargetImage` processes (e.g., `explorer.exe`, `svchost.exe`) with `SourceImage` binaries in temp/user-writeable paths (e.g., `%APPDATA%`, `%TEMP%`). Filter for `StartAddress` values outside known module ranges (e.g., `0x00000000`–`0x7FFFFFFF`). Technique: **T1055.001 Process Injection: Dynamic-link Library Injection** (https://attack.mitre.org/techniques/T1055/001/).

- **EDR/XDR Telemetry (Process Creation + Module Loads)** – Correlate `process creation` events (Event ID 1) with anomalous `LoadImage` calls (Event ID 7) for unsigned DLLs or shellcode-like memory regions (e.g., `Protection: PAGE_EXECUTE_READWRITE`). Prioritize parent-child mismatches (e.g., `powershell.exe` spawning `rundll32.exe`). Technique: **T1569.002 System Services: Service Execution** (https://attack.mitre.org/techniques/T1569/002/).

- **Network Telemetry (Zeek/Suricata)** – Hunt for HTTP responses with `Content-Type: application/octet-stream` and no `Content-Disposition` header, paired with subsequent `CreateRemoteThread` events. Pivot on `destination.port: 443` and `user_agent` anomalies (e.g., `curl`/`wget` impersonation). Use Suricata `file.magic` to match shellcode patterns (e.g., `MZ` header if the shellcode contains a PE). Further reading: CISA Alert AA22-152A (https://www.cisa.gov/uscert/ncas/alerts/aa22-152a) and Elastic Security Labs (https://www.elastic.co/security-labs/detecting-process-injection-techniques).

## Attacker perspective
Attackers favor position-independent shellcode because it runs anywhere in memory and sidesteps disk-based AV that keys on PE structure.

Concrete TTPs, artifacts, and evasion:
- **API resolution without imports.** The stub walks the Process Environment Block (`fs:[0x30]` on x86) to reach the loaded-module list and locate `kernel32.dll`, then parses its export table — no `IAT`, no `LoadLibrary` string on disk. This is **Dynamic API Resolution (T1027.007)**. (PEB/TEB structures: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- **API hashing.** Function names are compared as precomputed hashes (e.g., ROR-13), so a naive `strings` finds no `WinExec`/`GetProcAddress` — general **Obfuscated Files or Information (T1027)**.
- **Payload actions.** Stagers commonly resolve `WinExec`, `CreateProcessA`, or download-and-exec calls (`URLDownloadToFileA`/`WinHttp*`), mapping to **Native API (T1106)** and **Ingress Tool Transfer (T1105)**.
- **Injection.** When delivered by a loader, the shellcode is written into a remote process and executed via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` — **Process Injection (T1055)**.
- **Artifacts left behind (what defenders exploit).** The injected region is frequently allocated `PAGE_EXECUTE_READWRITE` (`RWX`), which is anomalous for legitimate code; the resolved API sequence is visible to an API monitor and to scdbg's emulation; spawned child processes show anomalous parentage in Sysmon EID 1; and decoded strings/network callbacks surface once emulated or single-stepped. Evasion attempts (anti-emulation timing checks, unsupported-API stalls, environmental keying) may defeat scdbg but are exactly why x64dbg single-stepping is the confirming step.

### Adversary Emulation & Red-Team Perspective
From an adversary's perspective, the shellcode execution path can be exploited to achieve code execution without touching disk. Common TTPs:

- **User Execution (T1204)** – The shellcode is dropped via spearphishing attachment (macro/download) and the user is tricked into launching it (e.g., double-clicking a document that triggers a payload). Reference: https://attack.mitre.org/techniques/T1204/
- **System Binary Proxy (T1218)** – The shellcode is executed via built-in Windows binaries like `rundll32.exe`, `mshta.exe`, or `regsvr32.exe` to bypass application whitelisting. Reference: https://attack.mitre.org/techniques/T1218/
- **Process Injection (T1055.001)** – Shellcode is injected into a legitimate process (e.g., `explorer.exe`) to hide in plain sight. Reference: https://attack.mitre.org/techniques/T1055/001/
- **Obfuscated Files or Information (T1027.007)** – Dynamic API resolution via hashing is the norm for shellcode, making strings analysis fruitless.

Evasion techniques:
- Use of `syscall` instructions instead of `call` to avoid user-mode hooks.
- Environment keying (T1497) – check for hash of domain, registry key, or hardware ID to only execute on the intended target.
- Anti-debugging (T1622) – use of `IsDebuggerPresent`, `NtQueryInformationProcess`, or timing loops to detect analysis.

Artifacts left behind:
- Anomalous memory allocations (RWX) in the target process.
- Child processes with unexpected parentage (e.g., `WINWORD.EXE` spawning `rundll32.exe`).
- Network connections to unknown IPs during or after shellcode execution (if it downloads a stage-two).

For further reading on adversary emulation, see CISA Red Team (https://www.cisa.gov/red-team) and CIS Red Team (https://www.cisecurity.org/white-papers/cis-red-team-operations/).

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
- **x64dbg confirmation** (task 4): break on `kernel32.WinExec`; the first stacked argument points to the ASCII string `calc.exe`.

## MITRE ATT&CK & DFIR phase
- **T1055 — Process Injection** (shellcode is the injectable payload). https://attack.mitre.org/techniques/T1055/
- **T1055.001 — Process Injection: Dynamic-link Library Injection** (when shellcode is injected via DLL). https://attack.mitre.org/techniques/T1055/001/
- **T1106 — Native API** (direct Windows API invocation, e.g., `WinExec`). https://attack.mitre.org/techniques/T1106/
- **T1027 — Obfuscated Files or Information** (API hashing). https://attack.mitre.org/techniques/T1027/
- **T1027.007 — Obfuscated Files or Information: Dynamic API Resolution** (PEB-walk / hashed export lookup). https://attack.mitre.org/techniques/T1027/007/
- **T1105 — Ingress Tool Transfer** (staging variants that download follow-on payloads). https://attack.mitre.org/techniques/T1105/
- **T1204 — User Execution** (shellcode execution requires user interaction). https://attack.mitre.org/techniques/T1204/
- **T1218 — System Binary Proxy** (shellcode delivered via signed Microsoft binaries like `rundll32.exe`). https://attack.mitre.org/techniques/T1218/
- **T1569.002 — System Services: Service Execution** (shellcode can be executed as a service). https://attack.mitre.org/techniques/T1569/002/
- **DFIR phase:** Examination / Analysis (reverse engineering and behavioral triage of extracted artifacts).


### Essential Commands & Features

When analyzing shellcode with **scdbg**, advanced emulation features can reveal hidden behaviors. Below are the most useful undemonstrated commands for file/registry emulation and custom DLL injection:

- **`-fopen`**: Emulates file operations (e.g., `CreateFile`, `ReadFile`). Use when shellcode interacts with files to log access attempts.
  **Example**: `scdbg -fopen shellcode.bin`
  *Why?* Detects **T1564.004 (Hide Artifacts: NTFS File Attributes)** by revealing attempts to manipulate file metadata.

- **`-snap`**: Takes a memory snapshot at a specified instruction count (e.g., `-snap 1000`). Useful for isolating execution phases.
  **Example**: `scdbg -snap 500 -f shellcode.bin`
  *Why?* Helps analyze **T1134.001 (Access Token Manipulation: Token Impersonation/Theft)** by capturing token changes mid-execution.

- **`-dll`**: Injects a custom DLL into the emulated process (e.g., `-dll myhook.dll`). Critical for testing DLL-side-loading attacks.
  **Example**: `scdbg -dll malicious.dll -f shellcode.bin`
  *Why?* Uncovers **T1574.002 (Hijack Execution Flow: DLL Side-Loading)** by forcing emulation of attacker-controlled libraries.

- **`-i`**: Enables interactive mode to step through execution. Use when automated analysis misses context.
  **Example**: `scdbg -i -f shellcode.bin`
  *Why?* Exposes **T1070.006 (Indicator Removal: Timestomp)** by allowing manual inspection of timestamp manipulation.

**Sources**:
- [scdbg Official Documentation (Sandsprite)](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [MITRE ATT&CK: Defense Evasion Techniques](https://www.fireeye.com/current-threats/mitre-attack.html) (FireEye)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Potential CobaltStrike Service Installations - Registry** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml; license: Detection Rule License / DRL):

```yaml
title: Potential CobaltStrike Service Installations - Registry
id: 61a7697c-cb79-42a8-a2ff-5f0cdfae0130
status: test
description: |
    Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.
references:
    - https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395
author: Wojciech Lesicki
date: 2021-06-29
modified: 2024-03-25
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.lateral-movement
    - attack.t1021.002
    - attack.t1543.003
    - attack.t1569.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        - TargetObject|contains: '\System\CurrentControlSet\Services'
        - TargetObject|contains|all:
              - '\System\ControlSet'
              - '\Services'
    selection_details:
        - Details|contains|all:
              - 'ADMIN$'
              - '.exe'
        - Details|contains|all:
              - '%COMSPEC%'
              - 'start'
              - 'powershell'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_ps1_shellcode.yar, author: Nick Carr, David Ledbetter):

```yara
rule Base64_PS1_Shellcode {
   meta:
      description = "Detects Base64 encoded PS1 Shellcode"
      author = "Nick Carr, David Ledbetter"
      reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
      date = "2018-11-14"
      score = 65
      id = "7c3cec3b-a192-5bfd-b4f1-22b1afeb717e"
   strings:
      $substring = "AAAAYInlM"
      $pattern1 = "/OiCAAAAYInlM"
      $pattern2 = "/OiJAAAAYInlM"
   condition:
      $substring and 1 of ($p*)
}
```

**Real-world context (MITRE T1027.007 -- Obfuscated Files or Information: Dynamic API Resolution):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1027/007/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

To maximize `scdbg`'s analytical power, leverage these undemonstrated but critical commands for deeper shellcode inspection:

1. **File/Registry Emulation**
   - `-fopen <file>`: Emulate file operations (e.g., `scdbg -f shellcode.bin -fopen C:\temp\malware.exe`). Use when analyzing shellcode that reads/writes files (e.g., **T1005: Data from Local System**).
   - `-snap <regkey>`: Simulate registry interactions (e.g., `scdbg -f shellcode.bin -snap HKCU\Software\Microsoft\Windows\CurrentVersion\Run`). Critical for detecting persistence mechanisms (e.g., **T1547.001: Registry Run Keys / Startup Folder**).

2. **Offset Analysis**
   - `-foff <hex>`: Skip shellcode headers to analyze embedded payloads (e.g., `scdbg -f shellcode.bin -foff 0x400`). Useful for obfuscated samples where shellcode starts at non-zero offsets.

3. **Raw API Logging**
   - `-r`: Generate a raw API call log (e.g., `scdbg -f shellcode.bin -r > api_log.txt`). Essential for dissecting complex behaviors like **T1102: Web Service** (C2 callbacks) or **T1559.001: Inter-Process Communication (Dynamic Data Exchange)**.

**Example Workflow**:
```bash
scdbg -f embedded_shellcode.bin -foff 0x200 -fopen C:\Windows\Temp\evil.dll -r
```
This skips 512 bytes of padding, emulates file access, and logs API calls for post-analysis.

**Sources**:
- [SCDBG Official Documentation (Sandsprite)](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [REMnux Tools Guide: SCDBG](https://docs.remnux.org/discover-the-tools/analyze+malicious+documents#scdbg)

### Threat Hunting & Detection Engineering

Once shellcode executes, defenders must hunt for **T1056.001 Input Capture: Keylogging** and **T1543.003 Create or Modify System Process: Windows Service**. Begin by querying **Windows Security Event ID 4697** (Service Creation) for anomalous binaries (`ImagePath` field) that lack valid signatures or reside in non-standard directories (e.g., `C:\PerfLogs\`). Pivot to **Sysmon Event ID 1** (Process Creation) to inspect parent-child relationships; shellcode often spawns `svchost.exe` or `rundll32.exe` with unusual command-line arguments (e.g., `-k UnistackSvcGroup`).

For network-based detection, leverage **Zeek’s `conn.log`** to hunt for **T1056.001** keylogger exfiltration. Filter for small, periodic outbound connections (e.g., `duration < 0.1s` and `orig_bytes < 500`) to uncommon ports (e.g., `id.resp_p == 4444`). Cross-reference with **Suricata’s `alert` logs** for signatures detecting raw keystroke data (e.g., `ET TROJAN Keylogger Data Exfiltration`).

Hunt for **T1543.003** by correlating **Windows Event ID 7045** (Service Installation) with **Sysmon Event ID 13** (Registry Modification) to detect persistence via `HKLM\SYSTEM\CurrentControlSet\Services\`. Focus on `ImagePath` values containing obfuscated PowerShell or encoded commands.

**Sources:**
- [MITRE ATT&CK: T1056.001](https://attack.mitre.org/techniques/T1056/001/)
- [Microsoft Docs: Windows Security Log Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-service-operations) (Note: Prefer [CIS Benchmarks for Event ID 4697](https://www.cisecurity.org/benchmark/microsoft_windows_server/))

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1055 (Process Injection)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1055/
- **Threat actors documented using it:** Sandworm, APT32, APT37, APT38 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **scdbg emulates 32-bit shellcode via libemu; flags `/f`, `/foff`, `/s`, `/findsc`:** scdbg project/usage page — http://sandsprite.com/blogs/index.php?uid=7&pid=152 ; libemu library — https://github.com/buffer/libemu
- **scdbg packaged in FLARE-VM:** https://github.com/mandiant/flare-vm
- **scdbg packaged in REMnux / shellcode emulation workflow:** https://docs.remnux.org/discover-the-tools/analyze+code/emulate+code ; also https://docs.remnux.org/discover-the-tools/analyze+malicious+files/shellcode#scdbg
- **x64dbg is an open-source x64/x32 user-mode debugger; breakpoints & call-stack GUI:** https://x64dbg.com/ ; https://github.com/x64dbg/x64dbg ; https://help.x64dbg.com/en/latest/ ; https://help.x64dbg.com/en/latest/gui/index.html
- **`Get-FileHash` cmdlet, default SHA256:** https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- **NASM `-f bin` flat/raw binary output:** https://www.nasm.us/docs.php ; https://www.nasm.us/xdoc/2.16.01/html/nasmdoc7.html
- **PEB/TEB structures used by PEB-walk resolution (`fs:[0x30]`, module list):** https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
- **Sysmon event IDs for injection/process telemetry (EID 1, 7, 8, 10):** https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Windows Security Event ID 4688 (Process Creation):** https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- **Security Onion Suricata + Zeek pivots and file extraction:** https://docs.securityonion.net/en/2.4/suricata.html ; https://docs.securityonion.net/en/2.4/zeek.html
- **Suricata file keyword documentation:** https://docs.suricata.io/en/latest/rules/file-keywords.html
- **MITRE ATT&CK T1055 Process Injection:** https://attack.mitre.org/techniques/T1055/
- **MITRE ATT&CK T1055.001 Process Injection: DLL Injection:** https://attack.mitre.org/techniques/T1055/001/
- **MITRE ATT&CK T1106 Native API:** https://attack.mitre.org/techniques/T1106/
- **MITRE ATT&CK T1027 Obfuscated Files or Information:** https://attack.mitre.org/techniques/T1027/
- **MITRE ATT&CK T1027.007 Dynamic API Resolution:** https://attack.mitre.org/techniques/T1027/007/
- **MITRE ATT&CK T1105 Ingress Tool Transfer:** https://attack.mitre.org/techniques/T1105/
- **MITRE ATT&CK T1204 User Execution:** https://attack.mitre.org/techniques/T1204/
- **MITRE ATT&CK T1218 System Binary Proxy:** https://attack.mitre.org/techniques/T1218/
- **MITRE ATT&CK T1569.002 System Services: Service Execution:** https://attack.mitre.org/techniques/T1569/002/
- **MITRE ATT&CK T1497 Virtualization/Sandbox Evasion:** https://attack.mitre.org/techniques/T1497/
- **MITRE ATT&CK T1622 Debugger Evasion:** https://attack.mitre.org/techniques/T1622/
- **CISA Alert AA22-152A: Detecting Post-Compromise Threat Activity:** https://www.cisa.gov/uscert/ncas/alerts/aa22-152a
- **Elastic Security Labs: Detecting Process Injection Techniques:** https://www.elastic.co/security-labs/detecting-process-injection-techniques
- **SANS FOR610 Reverse-Engineering Malware (shellcode analysis coverage):** https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- **CISA Red Team guidance:** https://www.cisa.gov/red-team
- **CIS Red Team operations:** https://www.cisecurity.org/white-papers/cis-red-team-operations/
- **Cobalt Strike documentation (ROR-13 hash algorithm):** https://www.cobaltstrike.com/

<!-- cyberlab-enriched: v1 -->
- https://attack.mitre.org/techniques/T1055/001/
- https://attack.mitre.org/techniques/T1569/002/
- https://www.cisa.gov/uscert/ncas/alerts/aa22-152a
- https://www.elastic.co/security-labs/detecting-process-injection-techniques
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1625 (deprecated; replaced by T1218 and T1059)
- https://www.cisa.gov/red-team
- https://www.cisecurity.org/white-papers/cis-red-team-operations/

<!-- cyberlab-enriched: v2 -->
- https://docs.remnux.org/discover-the-tools/analyze+malicious+files/shellcode#scdbg
- https://attack.mitre.org/techniques/T1588
- https://attack.mitre.org/techniques/T1595
- https://us-cert.cisa.gov
- https://www.nist.gov

## Related modules
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares x64dbg for stepping unpacked/injected code.
- [Dynamic debugging](../13-dynamic-debugging/README.md) -- shares x64dbg fundamentals (breakpoints, stepping, stack inspection).
- [Shellcode analysis](../17-shellcode-analysis/README.md) -- shares scdbg for emulating and triaging raw shellcode.
- [x64dbg unpacking & debugging workflow](../28-x64dbg-workflow/README.md) -- shares x64dbg workflow for confirming emulator findings.

<!-- cyberlab-enriched: v4 -->
- https://www.fireeye.com/current-threats/mitre-attack.html
- https://attack.mitre.org/techniques/T1055/"
- https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/

<!-- cyberlab-enriched: v5 -->
- https://docs.remnux.org/discover-the-tools/analyze+malicious+documents#scdbg
- https://attack.mitre.org/techniques/T1056/001/
- https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-service-operations
- https://www.cisecurity.org/benchmark/microsoft_windows_server/

<!-- cyberlab-enriched: v6 -->
