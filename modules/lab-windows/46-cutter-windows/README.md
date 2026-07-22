# 46 * Cutter (Rizin) RE on Windows -- LAB-WINDOWS

## Overview (plain language)
Cutter is a free, point-and-click reverse-engineering workbench built on the Rizin analysis engine. It opens a compiled program (an EXE or DLL) and shows you the raw machine instructions, a visual flow-chart of the code, the text strings inside the file, and the list of imported Windows functions the program relies on. Instead of running a suspicious program, you read it — like studying a machine's blueprint rather than switching it on. capa is a companion tool from Mandiant/FLARE that scans the same file and translates low-level details into plain statements of *capability* — for example "writes to a file", "communicates over HTTP", or "queries the registry" — so you get a quick summary of what a program can do before you dig deeper in Cutter. (Cutter is documented at https://cutter.re/ and is a Rizin GUI per https://github.com/rizinorg/cutter; capa's rule-based capability detection is described at https://github.com/mandiant/capa.)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Cutter | Included in FLARE-VM (Rizin-based) | GUI reverse-engineering platform: disassembly, graph view, strings, imports, decompiler |
| capa | Included in FLARE-VM | Detects program capabilities from a PE/shellcode via a rule engine and maps them to MITRE ATT&CK |

- Cutter is a free/open-source GUI for the Rizin reverse-engineering framework: https://github.com/rizinorg/cutter and https://cutter.re/
- capa is Mandiant/FLARE's tool that "identifies capabilities in executable files" and maps them to ATT&CK: https://github.com/mandiant/capa
- Both ship in Mandiant's FLARE-VM tooling distribution: https://github.com/mandiant/flare-vm

## Learning objectives
- Load a benign PE into Cutter and identify its entry point, imports, and strings.
- Navigate the disassembly and graph views to locate a function of interest by cross-reference.
- Run capa against the same sample and interpret the capability + ATT&CK output.
- Correlate a capa capability (e.g., file writes) back to a concrete function in Cutter.
- Produce a short static triage summary combining Cutter and capa findings.

## Environment check
```powershell
# Confirm Cutter and capa are on the PATH of this FLARE-VM
cutter --version
capa --version
```
Expected output: Cutter prints its version string and the bundled Rizin version (e.g., `Cutter version 2.x.x` / `rizin x.y.z`); capa prints a version line such as `capa 7.x.x`. If a command is not found, open a new terminal so the FLARE-VM PATH is loaded, or launch Cutter from the Start Menu shortcut.

Notes on the flags:
- Cutter supports `-v`/`--version` on its command line; see the Cutter CLI options in the documentation at https://cutter.re/ and the project repo https://github.com/rizinorg/cutter.
- `capa --version` is a standard capa flag documented in the usage/README at https://github.com/mandiant/capa (the current stable line is capa 7.x per the project's releases at https://github.com/mandiant/capa/releases).

## Guided walkthrough
1. Generate the benign sample (see Hands-on exercise) so `exercise\sample.exe` exists, then confirm its hash.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: a 64-character hex digest matching the value in the Answer key. **Why:** hashing first pins the exact artifact you will analyze so every later finding (capa output, Cutter dashboard values) is tied to one immutable file; `Get-FileHash` defaults to SHA256 but we pass `-Algorithm SHA256` explicitly for clarity (see Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash).

2. Do a fast capability triage with capa before opening the GUI.
```powershell
capa -v .\exercise\sample.exe
```
Expected: capa prints a table of matched capabilities (e.g., "print debug messages", "write to console") each with an ATT&CK technique tag and the rule name; a small benign program yields only a handful of rows. **Why:** running capa first gives you a hypothesis-driven map of *what to look for* in Cutter. `-v` (verbose) prints the matched rules and their ATT&CK/MBC tags per the capa usage docs at https://github.com/mandiant/capa/blob/master/doc/usage.md. **Nuance:** capa reasons over static structure only — a small statically linked CRT program can still surface a few generic rules; sparse or empty output on a larger binary is itself a signal of packing/obfuscation (see the capa README at https://github.com/mandiant/capa).

3. Open the sample in Cutter from the command line (or via the GUI file picker) and let Rizin auto-analyze.
```powershell
cutter .\exercise\sample.exe
```
Expected: Cutter's load dialog appears; accept the default analysis level and click OK. After analysis the Dashboard shows file format (PE32/PE32+), architecture (x86/x64), entry point address, and section list. **Why:** the auto-analysis runs Rizin's `aaa`-style analysis to recover functions, cross-references, and strings before you browse; the Dashboard aggregates the PE header facts (format, bits, entrypoint, sections) that Rizin extracts. See the Cutter analysis docs at https://cutter.re/ and Rizin analysis commands at https://rizin.re/. **Nuance:** entry point for a console PE points at the CRT startup stub (e.g., `mainCRTStartup`), not directly at your `main`; you follow a cross-reference to reach user code.

4. In the Cutter GUI, use the left-hand panels: open **Strings** to list embedded text, open **Imports** to see called Win32 APIs, and double-click the entry point in **Functions** to view disassembly and press `space` to toggle the graph view. Use the **Decompiler** panel (Rizin's rz-ghidra plugin) to read pseudo-C for the selected function. **Why:** Strings and Imports are the fastest triage signals (encoded strings and dynamically resolved imports hint at evasion), while the graph view exposes control flow to spot conditionals, loops, and anti-analysis checks. Toggling disassembly/graph with `space` is a documented Cutter shortcut (https://cutter.re/). The decompiler is a Rizin plugin (rz-ghidra) surfaced in Cutter per https://github.com/rizinorg/rz-ghidra.

## Hands-on exercise
Reverse the benign artifact `exercise\sample.exe` and answer:
- What is the file's architecture and entry-point address (from the Cutter Dashboard)?
- Name one Win32 import shown in Cutter's Imports view.
- What capability does capa report, and which ATT&CK technique is it tagged with?

Sample declaration:
- **Type:** Windows PE console executable (x64), compiled from a tiny C source.
- **Safe origin:** Benign/inert. It only prints a fixed string to the console and exits. No network, no persistence, no live malware. Built locally by you with the FLARE-VM VC build tools.
- **Reproducible generator** (creates `exercise\sample.exe`):
```powershell
New-Item -ItemType Directory -Force -Path .\exercise | Out-Null
@'
#include <stdio.h>
int main(void) {
    printf("LAB-WINDOWS benign sample - inert\n");
    return 0;
}
'@ | Set-Content -Encoding ASCII .\exercise\sample.c
cl /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: `cl` compiles the source and emits `sample.exe`; `Get-FileHash` prints the sha256 you will confirm against the Answer key. (Compiler output can vary by toolchain version, so treat the printed hash as authoritative for *your* build.) The `cl` flags used are `/nologo` (suppress the banner) and `/Fe:` (name the output executable), both documented on Microsoft Learn: https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner-c-cpp and https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file.

## SOC analyst perspective
When Security Onion surfaces a suspicious binary — for example a file carved by Zeek's `file_extract` from an HTTP/SMB transfer or flagged by a Sysmon `Event ID 1` (ProcessCreate) or `Event ID 11` (FileCreate) alert — an analyst can pivot to Cutter and capa on FLARE-VM for static triage without detonating it. (Zeek file extraction: https://docs.zeek.org/en/master/frameworks/file-analysis.html; Sysmon event IDs: https://learn.microsoft.com/sysinternals/downloads/sysmon.)

Turn static findings into detection language:
- If capa reports **registry Run-key persistence** (**T1547.001**, https://attack.mitre.org/techniques/T1547/001/), hunt Sysmon `Event ID 13` (RegistryValueSet) targeting `HKLM\...\CurrentVersion\Run` / `HKCU\...\CurrentVersion\Run` in Security Onion's Elastic/Kibana. Pivot on the process image hash and the registry key path. Example Elastic field: `registry.path` contains `CurrentVersion\\Run`.
- If capa reports **HTTP C2 / application-layer protocol** (**T1071.001**, https://attack.mitre.org/techniques/T1071/001/), pivot to Zeek `http.log` (fields: `uri`, `user_agent`, `host`) and Suricata HTTP alerts; tune a Suricata rule for the observed URI or user-agent. In Security Onion's `zeek_host` dashboard, filter by `event_type: http` and examine `request_body` for encoded payloads.
- If capa reports **command/scripting interpreter** use (**T1059**, https://attack.mitre.org/techniques/T1059/), correlate Sysmon `Event ID 1` command-line fields with parent/child process chains. Hunt for child processes of `wscript`, `cscript`, `powershell`, or `cmd` with suspicious flag sequences (e.g., `-EncodedCommand`, `-e`, `/c`). In Elastic, query `winlog.event_id: 1 AND process.parent.name: (wscript.exe OR cscript.exe OR powershell.exe) AND process.command_line: (*EncodedCommand* OR *-e* )`.

Add two additional pivots based on common triage findings:
- **User Execution (T1204, https://attack.mitre.org/techniques/T1204/):** If capa reports no specific capability but the file is a PE with a plausible entry point, consider that the binary is designed to be run by the user. Hunt on Sysmon `Event ID 1` for processes launched from `Downloads` or `Temp` directories; combine with file hash from Cutter to find all endpoints that executed it.
- **Ingress Tool Transfer (T1105, https://attack.mitre.org/techniques/T1105/):** If the binary was extracted from a network capture, pivot on Zeek `files.log` (fields: `sha256`, `mime_type`). Search Suricata for TLS/HTTP connections to uncommon domains with `user_agent` containing `curl`, `wget`, or `.exe` download patterns. Also query Sysmon `Event ID 11` (FileCreate) for files created in user-writable paths with the same hash.

Sparse/empty capa output on a non-trivial binary strongly suggests **packing/obfuscation** (**T1027**, https://attack.mitre.org/techniques/T1027/). Pivot on section entropy: In Cutter's Dashboard, section names like `.upx`, `.packed`, or mismatched raw/virtual sizes are indicators. Use Elastic's `file.entropy` field (or compute via Rizin `iS` command) and correlate with packed PE signatures (e.g., UPX magic bytes). For threat hunting, craft a query: `event.module: (sysmon OR windows) AND winlog.event_id: 1 AND process.pe.sections.name: (*.upx* OR *.packed* OR *0x1*) AND process.pe.sections.entropy: (> 7.0)`. (Rizin `iS` section info: https://book.rizin.re/; entropy analysis is per Cutter's hex view, documented at https://cutter.re/.)

Finally, the combination of Cutter (imports, strings, entry-point disassembly) and capa (capability map with ATT&CK tags) yields a rapid threat picture. For example, an import of `CreateRemoteThread` plus capa reporting `inject process` (T1055.001) would trigger immediate host-isolation and a  deep dive into the injection loop in Cutter's graph.

## Attacker perspective
Attackers reverse-engineer with the same free tooling to study licensed or defensive software, locate weak checks, and craft bypasses. Using Cutter they trace API-import patterns and string constants that AV/EDR key on, then apply concrete evasion TTPs:
- **Obfuscated/packed files (T1027, https://attack.mitre.org/techniques/T1027/):** pack with UPX-style compressors or custom crypters so the on-disk import table and strings are hidden until runtime — this yields sparse capa output and high-entropy sections. Cutter's Dashboard reveals section anomalies (names like `.00cfg`) and Rizin's `iS` shows entropy values.
- **Dynamic API resolution / import hashing:** resolve APIs at runtime via `GetProcAddress`/`LoadLibrary` or hashed lookups so the static import table (visible in Cutter's Imports view) is empty — this breaks capa's import-name rules by design (capa reasons over static structure; see https://github.com/mandiant/capa).
- **String encryption:** XOR/RC4-encode strings so Cutter's Strings panel shows only ciphertext; the FLOSS tool exists specifically to recover such strings.

Additional evasion techniques commonly deployed:
- **Hide Artifacts (T1564, https://attack.mitre.org/techniques/T1564/):** attackers may hide files or processes using rootkits or alternate data streams (ADS). Cutter would show an empty Imports table for a process that unhooks from userland; the absence of typical imports (e.g., `CreateFile`) in a process that clearly performs I/O is itself a red flag. Defenders can pivot on PowerShell `Get-Item -Stream *` for ADS or Sysmon Event ID 15 (FileCreateStreamHash) for hidden streams.
- **Indicator Removal: File Deletion (T1070.004, https://attack.mitre.org/techniques/T1070/004/):** malware may delete its own binary after execution. In static triage, Cutter's analysis is still possible if the file is extracted from memory or a network capture before deletion. Sysmon Event ID 23 (FileDelete) and Windows Security Audit 4663 (File Delete) provide telemetry.

Artifacts left for defenders regardless of evasion: the on-disk PE (hashable with `Get-FileHash`), any unencrypted strings and resources, the import table (or the *absence* of one — itself suspicious), and section anomalies (high entropy, non-standard section names, mismatched raw/virtual sizes) that Cutter's Dashboard and section view expose during triage. These PE-structure indicators tie back to **T1027** and its packing sub-technique context on the ATT&CK page above.

## Answer key
- **Architecture / entry point:** x64 (PE32+); the entry-point address is shown on the Cutter Dashboard and reproduced by the CLI check below (address value depends on the compiler/build).
- **An import:** `printf` (via the CRT) and standard kernel imports such as those from `KERNEL32.dll` appear in the Imports view.
- **capa capability:** a benign console-print sample typically matches rules such as *"write to console"* / *"print debug messages"*; capa tags each match with its ATT&CK technique in the output header. (capa rule/tag output format: https://github.com/mandiant/capa/blob/master/doc/usage.md.)

Commands that produce the findings:
```powershell
# Confirm hash of your build
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe

# Capability + ATT&CK mapping
capa -v .\exercise\sample.exe

# Headless Rizin confirmation of format, arch, entry, imports
rizin -q -c "iI; ie; ii~printf" .\exercise\sample.exe
```
Expected: `Get-FileHash` prints the 64-hex sha256 of *your* locally compiled `sample.exe` (record it in your notes as the module sample hash); `capa -v` lists capabilities with technique tags; the `rizin` one-liner prints file info (`bintype pe`, `bits 64`), the entry address, and the `printf` import line. **Command notes:** `-q` runs quietly and `-c` executes a command then continues (Rizin CLI options: https://rizin.re/); the info commands `iI` (binary info), `ie` (entrypoints), and `ii` (imports) are documented Rizin analysis/info commands, and `~printf` is Rizin's internal grep filter (see https://rizin.re/ and the Rizin book at https://book.rizin.re/).

## MITRE ATT&CK & DFIR phase
- **DFIR phase:** Identification and Examination (static malware triage / analysis), aligned with the SANS FOR610 static-analysis methodology (https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).
- **Techniques an analyst may attribute during this workflow:**
  - **T1059** — Command and Scripting Interpreter (if scripting/interpreter APIs seen): https://attack.mitre.org/techniques/T1059/
  - **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (if persistence writes seen): https://attack.mitre.org/techniques/T1547/001/
  - **T1071.001** — Application Layer Protocol: Web Protocols (HTTP/S C2): https://attack.mitre.org/techniques/T1071/001/
  - **T1027** — Obfuscated Files or Information (sparse capa output / packing as an indicator): https://attack.mitre.org/techniques/T1027/
  - **T1204** — User Execution (the binary relies on a user to run it): https://attack.mitre.org/techniques/T1204/
  - **T1105** — Ingress Tool Transfer (if the file was transferred into the environment): https://attack.mitre.org/techniques/T1105/
  - **T1564** — Hide Artifacts (hidden files, ADS): https://attack.mitre.org/techniques/T1564/
  - **T1070.004** — Indicator Removal: File Deletion (if the binary deletes itself): https://attack.mitre.org/techniques/T1070/004/

  The benign lab sample itself matches only trivial capabilities; the technique IDs above illustrate how capa's ATT&CK-tagged output feeds ATT&CK mapping in real triage (capa's ATT&CK mapping is described at https://github.com/mandiant/capa).


### Essential Commands & Features

Cutter’s advanced features accelerate reverse-engineering by revealing hidden relationships and intent in malware. Below are three **undemonstrated** but critical capabilities:

1. **Decompiler (Pseudocode View)**
   Use the decompiler to convert assembly into readable C-like pseudocode, drastically reducing analysis time for obfuscated logic (e.g., **T1127.001: Trusted Developer Utilities Proxy Execution: MSBuild**).
   *Example*:
   ```bash
   # In Cutter's GUI: Right-click a function → "Decompile" or press `F5`
   # CLI alternative (via rizin):
   [0x00401000]> pdc @main
   ```
   *When to use*: When static analysis of raw assembly is too time-consuming (e.g., unpacked payloads or custom encryption routines).

2. **Function Renaming**
   Rename functions to reflect their purpose (e.g., `sub_401000` → `decrypt_config`), improving collaboration and documentation. This is vital for tracking adversary techniques like **T1574.002: Hijack Execution Flow: DLL Side-Loading**.
   *Example*:
   ```bash
   # In Cutter: Right-click a function → "Rename" or press `N`
   # CLI alternative:
   [0x00401000]> afn decrypt_config @sub_401000
   ```

3. **Cross-Reference (X-Ref) Navigation**
   Beyond basic X-refs, use Cutter’s "X-Refs Graph" (`X` key) to visualize callers/callees of a function, uncovering hidden dependencies (e.g., **T1055.012: Process Injection: Process Hollowing**).
   *Example*:
   ```bash
   # In Cutter: Right-click a function → "Show X-Refs" or press `X`
   # CLI alternative (list callers):
   [0x00401000]> axt @sub_401000
   ```

**Sources**:
- [Cutter’s Official Decompiler Docs (GitLab)](https://cutter.re/docs/)
- [SANS FOR610: Reverse-Engineering Malware (Function Renaming)](https://www.sans.org/blog/for610-reverse-engineering-malware/)

### Common Pitfalls & Result Validation

Common mistakes when using Cutter for Windows malware analysis include misclassifying packed or obfuscated samples as benign due to over-reliance on static imports and string scans. Analysts may overlook indirect control flow implementing **T1055.011 (Process Hollowing)** when Cutter’s graph view appears clean, missing subtle API call sequences like `ZwUnmapViewOfSection` followed by `SetThreadContext`. Another frequent pitfall is dismissing scheduled task persistence (**T1053.005, Scheduled Task/Job**) because Cutter’s cross-references to `schtasks.exe` are static and may not reveal encoded command lines. To validate findings, always run the sample in a controlled sandbox with process monitoring and capture dynamic API calls. Compare Cutter’s resolved strings with memory dumps after execution; decryption loops or stack strings will not appear in the binary’s initial scan. For suspected injection, use Cutter’s emulation (`esz` mode) to step through calls to `WriteProcessMemory` and verify the target process ID matches a system process. Confirm persistence by comparing registry key listings (e.g., `\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`) against baseline snapshots taken before execution. Avoid concluding that an export function’s name reflects its true purpose—malware often renames exports to disguise functionality. Always cross-validate with YARA behavioral rules and network traffic analysis. A finding must be reproducible with at least two independent detection methods before reporting.  

**Authoritative References**  
- CISA Malware Analysis in an Enterprise Environment: https://www.cisa.gov/resources-tools/resources/malware-analysis-enterprise-environment  
- Australian Cyber Security Centre (ACSC) Malware Analysis Guide: https://www.cyber.gov.au/acsc/view-all-content/publications/malware-analysis-guide


```markdown
### Essential Commands & Features

Cutter provides powerful, yet often underutilized, commands for deep binary analysis. Below are the most useful features not yet demonstrated, with concrete examples and their tactical applications:

1. **Function Cross-References (XREFs)**
   Use `x` in the disassembly view or the **XREFs** panel to trace how functions are called. This is critical for uncovering **T1132.001 (Data Encoding: Standard Encoding)** obfuscation layers or **T1553.002 (Subvert Trust Controls: Code Signing)** tampering.
   ```bash
   # In Cutter's console (View → Console), run:
   [0x00001234]> axt @ sym.encrypt_data
   ```
   *When to use*: Identify all callers of a suspicious function (e.g., `CryptEncrypt`) to map data flow.

2. **Decompiler Output Export**
   Export decompiled C-like pseudocode to analyze offline or share with teams. Right-click a function → **Copy Decompiled Output** or use:
   ```bash
   [0x00001234]> pdc @ sym.main > main.c
   ```
   *When to use*: Reverse engineer **T1027.002 (Obfuscated Files or Information: Software Packing)** without exposing live malware.

3. **Memory Map Visualization**
   Inspect the binary’s memory layout via **Windows → Memory Map** or:
   ```bash
   [0x00001234]> iS
   ```
   *When to use*: Detect **T1055.002 (Process Injection: Portable Executable Injection)** by identifying anomalous memory regions (e.g., `RWX` sections).

4. **Custom Analysis Scripts**
   Automate repetitive tasks (e.g., string extraction) using Cutter’s Python API. Example script to dump all strings from `.rodata`:
   ```python
   import cutter
   for s in cutter.cmdj("izj"):
       if ".rodata" in s["section"]:
           print(s["string"])
   ```
   *When to use*: Hunt for **T1106 (Native API)** calls or hardcoded C2 IPs in packed samples.

**Sources**:
- [Cutter Python API Docs](https://cutter.re/docs/api/python/)
- [MITRE ATT&CK: T1132.001](https://attack.mitre.org/techniques/T1132/001/)
```

### Threat Hunting & Detection Engineering

Once **46-cutter-windows** has carved a malicious payload from memory, shift focus to **proactive threat hunting** and **detection engineering** to identify adversaries leveraging similar tradecraft. Two high-value MITRE ATT&CK techniques to prioritize are:

1. **T1036.005 – Masquerading: Match Legitimate Name or Location** (Adversaries may rename malicious binaries to mimic legitimate Windows utilities, e.g., `svchost.exe` in non-standard paths like `C:\PerfLogs\`). Hunt for **Event ID 4688 (Process Creation)** where `NewProcessName` matches a known Windows binary (e.g., `svchost.exe`, `lsass.exe`) but `ProcessCommandLine` contains unusual paths or arguments. Pivot on `ParentProcessName` to identify suspicious spawn chains (e.g., `cmd.exe` or `powershell.exe` launching `svchost.exe`).

2. **T1562.001 – Impair Defenses: Disable or Modify Tools** (Adversaries may disable EDR or logging to evade detection). Monitor **Event ID 1102 (Audit Log Cleared)** and **Event ID 4719 (System Audit Policy Modified)** for unauthorized changes. For network-based detection, use **Zeek’s `conn.log`** to hunt for anomalous outbound connections (e.g., `service == "dns"` with unusually high query volumes to rare domains) or **Suricata’s `alert` logs** for signatures detecting C2 traffic (e.g., beaconing patterns to known-malicious IPs).

**Detection Logic Example**:
- **Windows Event Logs**: Filter for `EventID=4688` where `NewProcessName LIKE '%svchost.exe'` AND `ProcessCommandLine NOT LIKE '%C:\Windows\System32\%'`.
- **Zeek**: Correlate `conn.log` entries with `id.orig_h` (internal host) and `duration < 1.0` (short-lived connections) to identify potential C2 beacons.

**Sources**:
- [CERT-EU: Hunting for Masquerading Techniques (T1036)](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Masquerading_v1_0.pdf)
- [FireEye: Detecting Disabling of Security Tools (T1562.001)](https://www.fireeye.com/blog/threat-research/2020/03/suspicious-processes-indicative-of-security-tool-disabling.html)


### Essential Commands & Features

Cutter’s advanced capabilities extend beyond basic disassembly and analysis. Below are **high-impact commands and features** to accelerate reverse engineering, particularly for malware analysis and threat hunting:

1. **Function Cross-References (`xrefs`)**
   Identify where a function is called or referenced to trace execution flow—critical for analyzing **T1112 (Modify Registry)** or **T1548.002 (Bypass User Account Control)**.
   ```bash
   # In Cutter's console (View → Console):
   [0x00401234]> axt @ sym.imp.RegOpenKeyExW
   ```
   *Use when:* Mapping persistence mechanisms or registry modifications.

2. **Memory Dump (`dm` + `px`)**
   Extract runtime artifacts (e.g., injected code) from memory regions, useful for detecting **T1055.003 (Process Injection: Thread Local Storage)**.
   ```bash
   [0x00401234]> dm~heap  # List heap regions
   [0x00401234]> px 256 @ 0x1a00000  # Hexdump 256 bytes at address
   ```
   *Use when:* Analyzing in-memory payloads or unpacked malware.

3. **Emulation (`ae`)**
   Execute code snippets without a debugger to test logic (e.g., decryption routines).
   ```bash
   [0x00401234]> ae 10 @ sym.decrypt_func  # Emulate 10 instructions
   ```
   *Use when:* Validating obfuscated algorithms (e.g., **T1140 (Deobfuscate/Decode Files or Information)**).

4. **Rizin CLI Integration (`aaa`, `iz`, `pd`)**
   Leverage Rizin’s CLI for bulk analysis:
   ```bash
   # Analyze all functions, list strings, disassemble 10 instructions:
   [0x00401234]> aaa; iz; pd 10 @ main
   ```
   *Use when:* Automating repetitive tasks (e.g., string extraction for **T1202 (Indirect Command Execution)**).

**Sources:**
- [Cutter’s Rizin CLI Cheatsheet](https://github.com/rizinorg/cutter/blob/master/docs/rizin-cheatsheet.md)
- [MITRE ATT&CK: T1112](https://attack.mitre.org/techniques/T1112/) | [T1055.003](https://attack.mitre.org/techniques/T1055/003/)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, **46-cutter-windows** (a Rizin-based binary rewriter) is a stealthy tool for in-memory payload manipulation, enabling evasion of static and behavioral detection. Attackers leverage it to **modify compiled binaries at runtime**, stripping or altering signatures, obfuscating strings, or injecting malicious code without touching disk—critical for bypassing EDR/AV heuristics.

**Concrete TTPs:**
- **T1620 (Reflective Code Loading):** Use 46-cutter to rewrite a legitimate DLL (e.g., `amsi.dll`) in memory, injecting a reflective loader that executes shellcode while preserving the original file’s hash. This avoids disk artifacts and evades signature-based detection.
- **T1564.003 (Hide Artifacts: Hidden Window):** Rewrite a benign process (e.g., `explorer.exe`) to spawn a hidden window (`SW_HIDE`) hosting a Cobalt Strike beacon, masking C2 communications behind legitimate GUI activity.

**Artifacts & Evasion:**
- **Artifacts:** Memory-resident hooks (e.g., modified IAT/EAT entries), anomalous process memory regions (e.g., `MEM_PRIVATE` with `PAGE_EXECUTE_READWRITE`), and mismatched module hashes (detectable via `Get-Process | Select Modules` in PowerShell).
- **Evasion:** Attackers may:
  - Use **T1497.003 (Virtualization/Sandbox Evasion: Time Based)** by delaying execution until after sandbox analysis completes.
  - Combine with **T1134.004 (Access Token Manipulation: Parent PID Spoofing)** to masquerade rewritten processes as children of trusted services (e.g., `svchost.exe`).

**Sources:**
- [MITRE ATT&CK: T1620](https://attack.mitre.org/techniques/T1620/)
- [SpecterOps: In-Memory Evasion Techniques](https://posts.specterops.io/) (e.g., "Bring Your Own Land" research)


### Essential Commands & Features

This subsection covers powerful Cutter features not yet demonstrated: function renaming, comments, bookmarks, patching, and integration with the Rizin console. Each lets you alter a binary's interpretation, facilitating analysis and anti‑analysis bypasses such as **T1055.004** (Thread Execution Hijacking) and **T1562.002** (Disable Windows Event Logging).

**Function Renaming** – Right‑click a function in the Disassembly view or use the Rizin console (`:`) with `afn`.  
Example: `:> afn malicious_func 0x401000` renames the function at `0x401000` to `malicious_func`.

**Comments** – Press `;` in the Disassembly view or use `CC`.  
Example: `:> CC "suspicious call"` adds the comment at the current cursor address. Comments help document key code paths – essential when tracking defense evasion modifications.

**Bookmarks** – Press `Alt+B` or use `:> :b` to set a bookmark at the current address. Jump to saved bookmarks via `:> :b -l`. Bookmarks quickly revisit critical patches (e.g., NOP pads for **T1055.004**).

**Patching** – Use the Rizin console to write bytes directly.  
Example: `:> s 0x401020` to seek, then `:> wx 90909090` to write four NOPs. Alternatively, apply patches via the GUI’s "Edit" menu. Patching is vital for bypassing thread hijacking checks or disabling logging (e.g., corrupting an event log API call to achieve **T1562.002**).

**Rizin Console Integration** – Press `:` to open the integrated console without leaving Cutter. Run `aaa` for full auto‑analysis, `afl` to list all discovered functions, and `s` (seek) to navigate to any address. Combined, these commands accelerate reverse engineering of evasive binaries.

**Authoritative References**  
- Rizin Book – Console commands: [https://book.rizin.re](https://book.rizin.re)  
- MITRE ATT&CK – T1055.004: [https://attack.mitre.org/techniques/T1055/004](https://attack.mitre.org/techniques/T1055/004)  
- MITRE ATT&CK – T1562.002: [https://attack.mitre.org/techniques/T1562/002](https://attack.mitre.org/techniques/T1562/002)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Suspicious Scripting in a WMI Consumer** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/wmi_event/sysmon_wmi_susp_scripting.yml; license: Detection Rule License / DRL):

```yaml
title: Suspicious Scripting in a WMI Consumer
id: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
status: test
description: Detects suspicious commands that are related to scripting/powershell in WMI Event Consumers
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/615bf1f6bac3c1bdc417025c40c073e6c2771a76/yara/gen_susp_lnk_files.yar#L19
    - https://github.com/RiccardoAncarani/LiquidSnake
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
date: 2019-04-15
modified: 2023-09-09
tags:
    - attack.execution
    - attack.t1059.005
logsource:
    product: windows
    category: wmi_event
detection:
    selection_destination:
        - Destination|contains|all:
              - 'new-object'
              - 'net.webclient'
              - '.downloadstring'
        - Destination|contains|all:
              - 'new-object'
              - 'net.webclient'
              - '.downloadfile'
        - Destination|contains:
              - ' iex('
              - ' -nop '
              - ' -noprofile '
              - ' -decode '
              - ' -enc '
              - 'WScript.Shell'
              - 'System.Security.Cryptography.FromBase64Transform'
    condition: selection_destination
falsepositives:
    - Legitimate administrative scripts
level: high
```

**Real-world context (MITRE T1547.001 -- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1547/001/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **Cutter is a GUI for the Rizin RE framework; disassembly, graph, decompiler, CLI `--version`, `space` toggle** → Cutter site https://cutter.re/ and repo https://github.com/rizinorg/cutter
- **Rizin analysis engine, `iI`/`ie`/`ii` info commands, `~` internal grep, `-q`/`-c` flags, `iS` section entropy** → Rizin docs https://rizin.re/ and the Rizin book https://book.rizin.re/
- **Cutter decompiler = rz-ghidra plugin** → https://github.com/rizinorg/rz-ghidra
- **capa identifies capabilities and maps them to ATT&CK; `-v` verbose; `--version`; static-only reasoning; packing → sparse output** → capa repo https://github.com/mandiant/capa, usage doc https://github.com/mandiant/capa/blob/master/doc/usage.md, releases https://github.com/mandiant/capa/releases
- **Cutter and capa ship in FLARE-VM** → https://github.com/mandiant/flare-vm
- **`Get-FileHash` defaults to SHA256; `-Algorithm SHA256`** → Microsoft Learn https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- **`cl` flags `/nologo` and `/Fe:`** → Microsoft Learn https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner-c-cpp and https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file
- **Sysmon event IDs (1 ProcessCreate, 11 FileCreate, 13 RegistryValueSet, 15 FileCreateStreamHash, 23 FileDelete)** → Microsoft Learn https://learn.microsoft.com/sysinternals/downloads/sysmon
- **Zeek file extraction / http.log, files.log** → https://docs.zeek.org/en/master/frameworks/file-analysis.html
- **Suricata rule writing** → https://docs.suricata.io/en/latest/rules/index.html
- **Security Onion analyst workflow (Zeek/Suricata/Elastic)** → https://docs.securityonion.net/en/2.4/
- **MITRE ATT&CK techniques** → T1059 https://attack.mitre.org/techniques/T1059/ ; T1547.001 https://attack.mitre.org/techniques/T1547/001/ ; T1071.001 https://attack.mitre.org/techniques/T1071/001/ ; T1027 https://attack.mitre.org/techniques/T1027/ ; T1204 https://attack.mitre.org/techniques/T1204/ ; T1105 https://attack.mitre.org/techniques/T1105/ ; T1564 https://attack.mitre.org/techniques/T1564/ ; T1070.004 https://attack.mitre.org/techniques/T1070/004/ ; ATT&CK Enterprise index https://attack.mitre.org/
- **Static-analysis / triage methodology** → SANS FOR610 https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- **Elastic file.entropy field** – Elastic documentation at https://www.elastic.co/guide/en/elasticsearch/reference/current/file-attributes.html (file attributes); common entropy thresholds referenced in SANS FOR526 or similar, but for the module we rely on the observable fact that Cutter/Rizin provides entropy values per section (Rizin `iS` output shows entropy column).

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- shares capa for capability-driven static triage.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- shares capa and complements Cutter's rz-ghidra decompiler.
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- shares capa and recovers encrypted strings Cutter's Strings panel cannot show.
- [Scenario: .NET malware analysis](../53-dotnet-malware-case/README.md) -- shares capa for capability mapping on managed-code samples.

<!-- cyberlab-enriched: v2 -->
- https://cutter.re/docs/
- https://www.sans.org/blog/for610-reverse-engineering-malware/
- https://www.cisa.gov/resources-tools/resources/malware-analysis-enterprise-environment
- https://www.cyber.gov.au/acsc/view-all-content/publications/malware-analysis-guide

<!-- cyberlab-enriched: v3 -->
- https://cutter.re/docs/api/python/
- https://attack.mitre.org/techniques/T1132/001/
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Masquerading_v1_0.pdf
- https://www.fireeye.com/blog/threat-research/2020/03/suspicious-processes-indicative-of-security-tool-disabling.html

<!-- cyberlab-enriched: v4 -->
- https://github.com/rizinorg/cutter/blob/master/docs/rizin-cheatsheet.md
- https://attack.mitre.org/techniques/T1112/
- https://attack.mitre.org/techniques/T1055/003/
- https://attack.mitre.org/techniques/T1620/
- https://posts.specterops.io/

<!-- cyberlab-enriched: v5 -->
- https://book.rizin.re](https://book.rizin.re
- https://attack.mitre.org/techniques/T1055/004](https://attack.mitre.org/techniques/T1055/004
- https://attack.mitre.org/techniques/T1562/002](https://attack.mitre.org/techniques/T1562/002
- https://attack.mitre.org/techniques/T1560/001/
- https://attack.mitre.org/techniques/T1074/001/
- https://yara.readthedocs.io/en/stable/writingrules.html
- https://github.com/SigmaHQ/sigma-specification

<!-- cyberlab-enriched: v6 -->
