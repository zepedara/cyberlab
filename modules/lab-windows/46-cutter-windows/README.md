# 46 * Cutter (Rizin) RE on Windows -- LAB-WINDOWS

## Overview (plain language)
Cutter is a free, point-and-click reverse-engineering workbench built on the Rizin analysis engine. It opens a compiled program (an EXE or DLL) and shows you the raw machine instructions, a visual flow-chart of the code, the text strings inside the file, and the list of imported Windows functions the program relies on. Instead of running a suspicious program, you read it — like studying a machine's blueprint rather than switching it on. capa is a companion tool from Mandiant/FLARE that scans the same file and translates low-level details into plain statements of *capability* — for example "writes to a file", "communicates over HTTP", or "queries the registry" — so you get a quick summary of what a program can do before you dig deeper in Cutter.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Cutter | Included in FLARE-VM (Rizin-based) | GUI reverse-engineering platform: disassembly, graph view, strings, imports, decompiler |
| capa | Included in FLARE-VM | Detects program capabilities from a PE/shellcode via a rule engine and maps them to MITRE ATT&CK |

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

## Guided walkthrough
1. Generate the benign sample (see Hands-on exercise) so `exercise\sample.exe` exists, then confirm its hash.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: a 64-character hex digest matching the value in the Answer key.

2. Do a fast capability triage with capa before opening the GUI.
```powershell
capa -v .\exercise\sample.exe
```
Expected: capa prints a table of matched capabilities (e.g., "print debug messages", "write to console") each with an ATT&CK technique tag and the rule name; a small benign program yields only a handful of rows.

3. Open the sample in Cutter from the command line (or via the GUI file picker) and let Rizin auto-analyze.
```powershell
cutter .\exercise\sample.exe
```
Expected: Cutter's load dialog appears; accept the default analysis level and click OK. After analysis the Dashboard shows file format (PE32/PE32+), architecture (x86/x64), entry point address, and section list.

4. In the Cutter GUI, use the left-hand panels: open **Strings** to list embedded text, open **Imports** to see called Win32 APIs, and double-click the entry point in **Functions** to view disassembly and press `space` to toggle the graph view. Use the **Decompiler** panel (Rizin's built-in) to read pseudo-C for the selected function.

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
Expected: `cl` compiles the source and emits `sample.exe`; `Get-FileHash` prints the sha256 you will confirm against the Answer key. (Compiler output can vary by toolchain version, so treat the printed hash as authoritative for *your* build.)

## SOC analyst perspective
When Security Onion surfaces a suspicious binary — for example a file extracted by Zeek/Suricata from an HTTP transfer or flagged by a Wazuh/Sysmon `ProcessCreate` alert — an analyst can pivot to Cutter and capa on FLARE-VM for static triage without detonating it. capa's ATT&CK mapping lets you turn a raw hash into detection language: if capa reports registry Run-key writes (T1547.001) or HTTP C2 (T1071.001), you can immediately write or tune Security Onion rules and hunt for matching process/registry telemetry across the fleet. Cutter confirms *where* in the code those behaviors live, giving IR the evidence to justify containment and to build IOCs (strings, imported APIs) for enterprise-wide sweeps.

## Attacker perspective
Attackers reverse-engineer with the same free tooling to study licensed or defensive software, locate weak checks, and craft bypasses. Using Cutter they trace API-import patterns and string constants that AV/EDR key on, then obfuscate or dynamically resolve those imports to evade static rules — exactly the capabilities capa is designed to flag. Analysts should remember that capa/Cutter reason over static structure, so packing, string encryption, and import hashing reduce what they see; heavily-stripped or packed binaries produce sparse capa output, itself a signal. Artifacts left for defenders include the on-disk PE (hashable), unencrypted strings, the import table, and section anomalies (high entropy, odd section names) that Cutter's Dashboard and section view expose during triage.

## Answer key
- **Architecture / entry point:** x64 (PE32+); the entry-point address is shown on the Cutter Dashboard and reproduced by the CLI check below (address value depends on the compiler/build).
- **An import:** `printf` (via the CRT) and standard kernel imports such as those from `KERNEL32.dll` appear in the Imports view.
- **capa capability:** a benign console-print sample typically matches rules such as *"write to console"* / *"print debug messages"*; capa tags each match with its ATT&CK technique in the output header.

Commands that produce the findings:
```powershell
# Confirm hash of your build
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe

# Capability + ATT&CK mapping
capa -v .\exercise\sample.exe

# Headless Rizin confirmation of format, arch, entry, imports
rizin -q -c "iI; ie; ii~printf" .\exercise\sample.exe
```
Expected: `Get-FileHash` prints the 64-hex sha256 of *your* locally compiled `sample.exe` (record it in your notes as the module sample hash); `capa -v` lists capabilities with technique tags; the `rizin` one-liner prints file info (`bintype pe`, `bits 64`), the entry address, and the `printf` import line.

## MITRE ATT&CK & DFIR phase
- **DFIR phase:** Identification and Examination (static malware triage / analysis).
- **Techniques an analyst may attribute during this workflow:** T1059 (Command and Scripting Interpreter, if scripting APIs seen), T1547.001 (Registry Run Keys / Startup Folder, if persistence writes seen), T1071.001 (Application Layer Protocol: Web), T1027 (Obfuscated/Packed Files — sparse capa output as an indicator). The benign lab sample itself matches only trivial capabilities; the technique IDs above illustrate how capa's output feeds ATT&CK mapping in real triage.

## Sources
- Cutter reverse-engineering platform (Rizin) — https://cutter.re/
- Rizin documentation — https://rizin.re/
- Mandiant/FLARE capa — https://github.com/mandiant/capa
- FLARE-VM (tool catalog & install) — https://github.com/mandiant/flare-vm
- MITRE ATT&CK (Enterprise techniques) — https://attack.mitre.org/
- SANS FOR610: Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/