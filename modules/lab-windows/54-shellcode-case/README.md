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

## SOC analyst perspective
In an incident, shellcode rarely arrives as a neat file — it is carved from packet captures, office-document macros, or memory dumps of an injected process. A defender uses `scdbg` to triage such carved blobs quickly: the API trace reveals C2 URLs, spawned processes, or staging behavior without running live malware.

Detection logic and Security Onion pivots:
- **Delivery on the wire.** Suricata (Emerging Threats ruleset) flags many injectors/loaders and exploit stagers; in Security Onion, pivot from the Suricata `alert` to the matching Zeek `conn.log`/`http.log`/`files.log` to identify and carve the transferred object (https://docs.securityonion.net/en/2.4/suricata.html, https://docs.securityonion.net/en/2.4/zeek.html). Zeek's file-extraction framework can dump HTTP/SMB objects for offline scdbg analysis.
- **Map the scdbg trace to ATT&CK.** A blob that resolves APIs via PEB walk and calls `WinExec`/`CreateProcess` maps to **Native API (T1106)** and **Command and Scripting Interpreter / process launch** behavior; injected shellcode maps to **Process Injection (T1055)**; a stager that pulls a follow-on payload maps to **Ingress Tool Transfer (T1105)**; hashed/obfuscated API names map to **Obfuscated Files or Information (T1027)** and specifically **T1027.007 Dynamic API Resolution**.
- **Host telemetry (Elastic in Security Onion).** Hunt Sysmon Event ID 8 (`CreateRemoteThread`) and Event ID 10 (`ProcessAccess` with suspicious `GrantedAccess` like `0x1F0FFF`/`0x1FFFFF`) for injection; Event ID 1 (`ProcessCreate`) with anomalous parent-child pairs (e.g., `winword.exe` → `calc.exe`/`cmd.exe`) surfaces the spawned process the scdbg trace predicted (Sysmon reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **Turn findings into signatures.** Feed the resolved API sequence, decoded strings, and any callback host into new YARA/Suricata rules; x64dbg confirms exact behavior when emulation is incomplete.

## Attacker perspective
Attackers favor position-independent shellcode because it runs anywhere in memory and sidesteps disk-based AV that keys on PE structure.

Concrete TTPs, artifacts, and evasion:
- **API resolution without imports.** The stub walks the Process Environment Block (`fs:[0x30]` on x86) to reach the loaded-module list and locate `kernel32.dll`, then parses its export table — no `IAT`, no `LoadLibrary` string on disk. This is **Dynamic API Resolution (T1027.007)**. (PEB/TEB structures: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- **API hashing.** Function names are compared as precomputed hashes (e.g., ROR-13), so a naive `strings` finds no `WinExec`/`GetProcAddress` — general **Obfuscated Files or Information (T1027)**.
- **Payload actions.** Stagers commonly resolve `WinExec`, `CreateProcessA`, or download-and-exec calls (`URLDownloadToFileA`/`WinHttp*`), mapping to **Native API (T1106)** and **Ingress Tool Transfer (T1105)**.
- **Injection.** When delivered by a loader, the shellcode is written into a remote process and executed via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` — **Process Injection (T1055)**.
- **Artifacts left behind (what defenders exploit).** The injected region is frequently allocated `PAGE_EXECUTE_READWRITE` (`RWX`), which is anomalous for legitimate code; the resolved API sequence is visible to an API monitor and to scdbg's emulation; spawned child processes show anomalous parentage in Sysmon EID 1; and decoded strings/network callbacks surface once emulated or single-stepped. Evasion attempts (anti-emulation timing checks, unsupported-API stalls, environmental keying) may defeat scdbg but are exactly why x64dbg single-stepping is the confirming step.

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
- **T1106 — Native API** (direct Windows API invocation, e.g., `WinExec`). https://attack.mitre.org/techniques/T1106/
- **T1027 — Obfuscated Files or Information** (API hashing). https://attack.mitre.org/techniques/T1027/
- **T1027.007 — Obfuscated Files or Information: Dynamic API Resolution** (PEB-walk / hashed export lookup). https://attack.mitre.org/techniques/T1027/007/
- **T1105 — Ingress Tool Transfer** (staging variants that download follow-on payloads). https://attack.mitre.org/techniques/T1105/
- **DFIR phase:** Examination / Analysis (reverse engineering and behavioral triage of extracted artifacts).

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **scdbg emulates 32-bit shellcode via libemu; flags `/f`, `/foff`, `/s`, `/findsc`:** scdbg project/usage page — http://sandsprite.com/blogs/index.php?uid=7&pid=152 ; libemu library — https://github.com/buffer/libemu
- **scdbg packaged in FLARE-VM:** https://github.com/mandiant/flare-vm
- **scdbg packaged in REMnux / shellcode emulation workflow:** https://docs.remnux.org/discover-the-tools/analyze+code/emulate+code
- **x64dbg is an open-source x64/x32 user-mode debugger; breakpoints & call-stack GUI:** https://x64dbg.com/ ; https://github.com/x64dbg/x64dbg ; https://help.x64dbg.com/en/latest/ ; https://help.x64dbg.com/en/latest/gui/index.html
- **`Get-FileHash` cmdlet, default SHA256:** https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- **NASM `-f bin` flat/raw binary output:** https://www.nasm.us/docs.php ; https://www.nasm.us/xdoc/2.16.01/html/nasmdoc7.html
- **PEB/TEB structures used by PEB-walk resolution (`fs:[0x30]`, module list):** https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
- **Sysmon event IDs for injection/process telemetry (EID 1, 8, 10):** https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Security Onion Suricata + Zeek pivots and file extraction:** https://docs.securityonion.net/en/2.4/suricata.html ; https://docs.securityonion.net/en/2.4/zeek.html
- **MITRE ATT&CK T1055 Process Injection:** https://attack.mitre.org/techniques/T1055/
- **MITRE ATT&CK T1106 Native API:** https://attack.mitre.org/techniques/T1106/
- **MITRE ATT&CK T1027 Obfuscated Files or Information:** https://attack.mitre.org/techniques/T1027/
- **MITRE ATT&CK T1027.007 Dynamic API Resolution:** https://attack.mitre.org/techniques/T1027/007/
- **MITRE ATT&CK T1105 Ingress Tool Transfer:** https://attack.mitre.org/techniques/T1105/
- **SANS FOR610 Reverse-Engineering Malware (shellcode analysis coverage):** https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares x64dbg for stepping unpacked/injected code.
- [Dynamic debugging](../13-dynamic-debugging/README.md) -- shares x64dbg fundamentals (breakpoints, stepping, stack inspection).
- [Shellcode analysis](../17-shellcode-analysis/README.md) -- shares scdbg for emulating and triaging raw shellcode.
- [x64dbg unpacking & debugging workflow](../28-x64dbg-workflow/README.md) -- shares x64dbg workflow for confirming emulator findings.

<!-- cyberlab-enriched: v1 -->
