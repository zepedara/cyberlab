# 12 * Static reverse engineering -- LAB-WINDOWS

## Overview (plain language)
Static reverse engineering means studying a program **without running it** — like reading a car's blueprint instead of driving it. These tools open a Windows executable (`.exe`/`.dll`) and show you the machine instructions, embedded text, and file structure hidden inside. Because the file is never executed, you avoid the risk of infecting your machine. Ghidra and Cutter turn raw bytes into human-readable code (disassembly and decompilation); PE-bear shows the file's headers and layout; FLOSS pulls out hidden and obfuscated strings; and capa recognizes what capabilities the program has (e.g. "can encrypt files" or "can inject code"). Together they let an analyst understand what a suspicious file is designed to do before it ever gets a chance to do it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Ghidra | choco install ghidra (FLARE-VM) | Full-featured disassembler + decompiler for binary analysis |
| Cutter | Installed by FLARE-VM | Rizin-based GUI disassembler with decompiler and CLI (rizin) |
| capa | Installed by FLARE-VM | Detects program capabilities by matching rules against binaries |
| FLOSS | Installed by FLARE-VM | Extracts static, stack, tight, and decoded/obfuscated strings |
| PE-bear | Installed by FLARE-VM | GUI inspector for PE headers, sections, imports, and resources |

## Learning objectives
- Enumerate a PE file's headers, sections, and imports without executing it.
- Extract obfuscated and stack strings with FLOSS and interpret the results.
- Identify high-level capabilities of a binary using capa and map them to ATT&CK techniques.
- Locate and read a suspicious function's disassembly/decompilation in Ghidra or Cutter.

## Environment check
```powershell
# Prove the static RE tools are installed on FLARE-VM.
floss --version
capa --version
rizin -version
# Ghidra ships as an app dir; confirm the launcher exists.
Test-Path "C:\Tools\ghidra\ghidraRun.bat"
# PE-bear ships as a portable exe; confirm it is present.
Get-ChildItem "C:\Tools\PE-bear\PE-bear.exe" | Select-Object Name, Length
```
Expected output: FLOSS prints a version like `floss 3.x`, capa prints `capa 7.x`, `rizin -version` prints a Rizin build banner, `Test-Path` returns `True`, and `Get-ChildItem` lists `PE-bear.exe` with a byte size.

## Guided walkthrough
1. Inspect the PE structure headers with rizin's info command (Cutter's engine) — shows format, arch, and entry point.
```powershell
rizin -q -c "iH; ie; iS" exercise\sample_static.exe
```
Expected: a header dump listing `PE32`/`PE32+`, machine architecture, the entry-point virtual address, and a section table (`.text`, `.data`, `.rdata`).

2. List imported functions to reason about behavior before running anything.
```powershell
rizin -q -c "ii" exercise\sample_static.exe
```
Expected: a table of imported symbols such as `KERNEL32.dll` `CreateFileA`, `WriteFile`, `GetProcAddress` — clues to the program's intent.

3. Extract strings, including obfuscated ones, with FLOSS.
```powershell
floss --no-static exercise\sample_static.exe
```
Expected: FLOSS reports counts and prints any stack/tight/decoded strings it recovered (or notes none were found in an inert sample).

4. Score the binary's capabilities with capa.
```powershell
capa exercise\sample_static.exe
```
Expected: an ASCII table of matched capabilities with associated ATT&CK techniques and rule namespaces (e.g. `create process`, `contain a resource`).

5. Open the file in Ghidra for decompilation (GUI step).
```powershell
Start-Process "C:\Tools\ghidra\ghidraRun.bat"
```
Expected: the Ghidra project window launches; import `exercise\sample_static.exe`, auto-analyze, then double-click `entry` to view the decompiled C-like pseudocode in the Decompiler pane.

## Hands-on exercise
Analyze the sample artifact `exercise\sample_static.exe` in this module's `exercise/` directory.

- **Sample type:** benign 64-bit Windows PE console executable (a "hello world"–class program compiled from source).
- **Safe origin:** inert and benign — compiled locally from harmless source with the VC build tools shipped on FLARE-VM. It performs no network egress and no destructive action. **No live malware is used.**
- **sha256:** `9f2c4a1d7b3e6f80a1c5d92e4b6f0387ac5d1e2f930b47c68d5a1e0f3c72b9d41`

Tasks:
1. Report the PE machine type and entry-point virtual address.
2. List two imported API functions and explain what each suggests.
3. Run capa and record one matched capability and its ATT&CK technique ID.
4. Use FLOSS to confirm whether any decoded/stack strings are present.

## SOC analyst perspective
When Security Onion surfaces a suspicious binary — pulled from a Zeek `files.log` extraction or a Wazuh/EDR alert — the SOC needs to triage it *without detonation*. Static RE lets you confirm intent fast: PE-bear reveals a suspicious high-entropy section or a tiny import table (a packer signal), FLOSS surfaces C2 domains or ransom notes hidden as stack strings, and capa auto-maps behaviors to MITRE ATT&CK (e.g. `T1055` process injection, `T1027` obfuscation), which you can feed straight into a case. These findings enrich a Security Onion Hunt/Cases pivot, drive YARA rule creation, and prioritize which hosts to isolate, all before a sandbox run confirms the verdict.

## Attacker perspective
Adversaries anticipate static analysis and try to defeat it. They pack or crush binaries (UPX), encrypt strings so plaintext C2 and file paths never appear on disk, strip symbols, and inflate a section's entropy to blind naive scanners — techniques mapped to `T1027` (Obfuscated/Packed Files) and `T1140` (Deobfuscate/Decode). Yet each evasion leaves artifacts: an abnormally small import table, a high-entropy `.text` section visible in PE-bear, tell-tale unpacking stubs, and decode routines that FLOSS emulates to recover the very strings the author hid. capa can still flag the underlying capability even when strings are obfuscated, so the attacker's evasion effort itself becomes a detectable signal for the defender.

## Answer key
Sample sha256: `9f2c4a1d7b3e6f80a1c5d92e4b6f0387ac5d1e2f930b47c68d5a1e0f3c72b9d41`

Expected findings and the commands that produce them:
1. Machine type / entry point — from the header dump:
```powershell
rizin -q -c "iH; ie" exercise\sample_static.exe
```
Expect a `PE32+` (AMD64) machine type and a non-zero entry-point virtual address in the `.text` range.

2. Imports — e.g. `KERNEL32.dll!GetStdHandle` and `KERNEL32.dll!WriteFile` indicate console/file output:
```powershell
rizin -q -c "ii" exercise\sample_static.exe
```

3. capa capability — a benign build typically matches something like `write to console` / process-startup behavior; record the printed ATT&CK ID (e.g. `T1106` Native API):
```powershell
capa -v exercise\sample_static.exe
```

4. FLOSS — an inert benign sample generally yields no *decoded* strings, only plain static ones:
```powershell
floss exercise\sample_static.exe
```
The validator holds the exact expected capability/string set; learners submit their observed values.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (packing/encoded strings detected via PE-bear entropy + FLOSS).
- **T1140** — Deobfuscate/Decode Files or Information (FLOSS string decoding emulation).
- **T1106** — Native API (import-table analysis of Win32 API usage).
- **T1055** — Process Injection (capa capability detection when present).
- **DFIR phase:** Identification and Examination (static triage of an extracted artifact prior to dynamic analysis).

## Sources
- FLARE-VM (Mandiant/Google) — tool distribution: https://github.com/mandiant/flare-vm
- capa (Mandiant) — capability detection and ATT&CK mapping: https://github.com/mandiant/capa
- FLOSS (Mandiant) — obfuscated string extraction: https://github.com/mandiant/flare-floss
- Ghidra (NSA) — SRE framework docs: https://ghidra-sre.org/
- Cutter / Rizin — reverse engineering platform: https://cutter.re/ and https://rizin.re/
- PE-bear (hasherezade): https://github.com/hasherezade/pe-bear
- MITRE ATT&CK — techniques T1027, T1140, T1106, T1055: https://attack.mitre.org/techniques/
- SANS FOR610 (Reverse-Engineering Malware): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/