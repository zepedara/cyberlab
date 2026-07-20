# 30 * PE static analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
When you get a suspicious Windows program (an `.exe` or `.dll`), you want to learn as much as you can about it *without running it*. That is called static analysis. Windows programs use a standard layout called the Portable Executable (PE) format, which is like a labeled box: a header at the top describing the contents, then sections holding code, data, and resources. This module teaches three tools that read that box for you. **PE-bear** shows you the structure — headers, sections, and imported functions — in a friendly table so you can spot odd or hollowed-out files. **Detect-It-Easy (DIE)** tells you what compiler or packer built the file and flags suspicious signs like high randomness (entropy) that suggests hidden or compressed code. **FLOSS** pulls readable text out of a file, including strings the malware tried to hide by scrambling them at runtime. Together these give you fast, low-risk clues about what a file is and what it might do.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PE-bear | Included in FLARE-VM | GUI PE parser: inspect DOS/NT headers, sections, imports/exports, resources |
| Detect-It-Easy (DIE) | Included in FLARE-VM | Identify compiler/packer/protector, scan entropy, run detection signatures |
| FLOSS | Included in FLARE-VM | Extract static, stack, tight, and decoded (obfuscated) strings from binaries |

## Learning objectives
- Parse a PE file's headers and sections with PE-bear and identify anomalies (e.g., high section entropy, mismatched raw/virtual sizes).
- Use Detect-It-Easy to identify the compiler/packer and interpret the entropy graph.
- Run FLOSS to recover both plain and obfuscated (stack/decoded) strings and triage indicators.
- Correlate imported API names to likely malware capabilities.
- Produce a defensible static triage note (packer status, suspicious imports, notable strings, sha256).

## Environment check
```powershell
# Confirm the three tools are present on FLARE-VM (adjust to your install paths if needed)
Get-Command floss.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
Get-ChildItem "C:\Tools\PE-bear" -Filter "PE-bear.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
Get-ChildItem "C:\Tools\die_win64_portable" -Filter "diec.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
floss.exe --version
```
Expected output: FLOSS prints its version (e.g., `floss 3.x`), and the `Get-ChildItem` calls print the full paths to `PE-bear.exe` and the DIE console binary `diec.exe`. If FLARE-VM was installed via Chocolatey, tool paths may live under `C:\ProgramData\chocolatey\lib\...` — adjust the search root accordingly.

## Guided walkthrough
1. Build a benign sample to analyze (see Hands-on exercise) and confirm its hash.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: a 64-character hex SHA256 for the compiled benign sample.

2. Identify the file type / compiler / packer with Detect-It-Easy console (`diec`).
```powershell
diec.exe .\exercise\sample.exe
```
Expected: DIE reports the file as a PE (e.g., `PE64` / `PE32`), names the compiler/linker (e.g., `Microsoft Visual C/C++`, `MinGW/GCC`), and — for an unpacked benign build — reports no packer. Entropy near ~6.0 or lower on the code section is typical for unpacked code.

3. Show the entropy breakdown per section to reason about compression/packing.
```powershell
diec.exe -e .\exercise\sample.exe
```
Expected: a per-section entropy table. A section entropy close to 8.0 signals compressed/encrypted (often packed) content; a benign compiled sample should show moderate values.

4. Recover strings — including obfuscated ones — with FLOSS.
```powershell
floss.exe --no-color .\exercise\sample.exe
```
Expected: FLOSS prints sections for STATIC, STACK, TIGHT, and DECODED strings. You should see readable static strings (e.g., the benign marker string embedded at build time) and any decoded strings FLOSS emulated out.

5. Open the sample in PE-bear (GUI) and review headers, sections, and imports.
```powershell
Start-Process "C:\Tools\PE-bear\PE-bear.exe" -ArgumentList "$PWD\exercise\sample.exe"
```
Expected: PE-bear launches with the file loaded. Review the **Section Hdrs** tab (compare `Raw size` vs `Virtual size`) and the **Imports** tab (note imported DLLs/APIs). No window flashes an execution of the sample — PE-bear only parses it.

## Hands-on exercise
Analyze the benign sample `exercise\sample.exe` in this module's `exercise/` directory.

**Sample declaration**
- **Type:** A tiny benign Windows console PE that prints a marker string and exits. It is inert — it performs no network, filesystem, registry, or persistence activity. **No live malware is used.**
- **Safe origin / generator (reproducible):** Compile from a one-line source on FLARE-VM using the included VC build tools. This guarantees a benign, no-egress binary you built yourself:
```powershell
# Reproducible benign generator (run from the module folder)
New-Item -ItemType Directory -Force -Path .\exercise | Out-Null
Set-Content -Path .\exercise\sample.c -Encoding ascii -Value '#include <stdio.h>
int main(void){ printf("LAB-WINDOWS-BENIGN-MARKER-30\n"); return 0; }'
cl.exe /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Because compiler/linker versions differ across FLARE-VM builds, the exact SHA256 will vary per machine — record the hash your build produces (see Answer key). The distinguishing invariant is the embedded marker string `LAB-WINDOWS-BENIGN-MARKER-30`.

**Tasks**
1. Use DIE to state the file class (PE32/PE64) and compiler.
2. Use DIE entropy mode to decide whether the sample is packed.
3. Use FLOSS to recover the benign marker string.
4. Use PE-bear to list at least two imported APIs and one section name.

## SOC analyst perspective
Static triage of a captured artifact is the first move in the DFIR examination phase. When an EDR or a Security Onion alert (e.g., Suricata flags a download, or a Zeek `files.log` records an extracted PE) surfaces a suspicious executable, an analyst pulls the file into a sandboxed FLARE-VM and runs DIE + FLOSS + PE-bear before deeper reversing. DIE's packer/entropy verdict maps to ATT&CK **T1027.002 (Software Packing)**; recovered import tables and FLOSS-decoded strings (URLs, mutex names, registry keys, command strings) become IOCs you feed back into Security Onion and hunt across your fleet. High entropy plus tiny import tables plus obfuscated strings is a classic "this is packed and hostile" signal that justifies escalation and detonation.

## Attacker perspective
Attackers know static analysts read the PE box, so they fight back at build time. They pack or crypt payloads (UPX, custom crypters) to raise section entropy and shrink the visible import table, and they build imports dynamically via `GetProcAddress`/`LoadLibrary` to hide capabilities (ATT&CK **T1027**, **T1140 Deobfuscate/Decode Files**). They XOR- or stack-encode strings so plain `strings` finds nothing — which is exactly why FLOSS's emulation of decoding routines is valuable. Yet these evasions leave artifacts: abnormally high entropy, packer signatures DIE recognizes, tell-tale section names (`UPX0`, `.themida`), mismatched raw vs. virtual sizes visible in PE-bear, and — once FLOSS runs its emulator — the very strings the attacker tried to conceal.

## Answer key
Expected findings and the commands that produce them:

1. **File class & compiler** — DIE identifies a PE (PE32 or PE64 depending on your `cl.exe` target) built by `Microsoft Visual C/C++`:
```powershell
diec.exe .\exercise\sample.exe
```
2. **Packed?** — No. Section entropy is moderate (well below 8.0), and DIE reports no packer:
```powershell
diec.exe -e .\exercise\sample.exe
```
3. **Marker string** — FLOSS recovers the static string `LAB-WINDOWS-BENIGN-MARKER-30`:
```powershell
floss.exe --no-color .\exercise\sample.exe | Select-String "LAB-WINDOWS-BENIGN-MARKER-30"
```
Expected: the line containing `LAB-WINDOWS-BENIGN-MARKER-30` is printed.
4. **Imports/section** — In PE-bear the **Imports** tab shows CRT/`kernel32.dll` APIs (e.g., `GetStdHandle`, `WriteFile`/`__acrt_*`) and the **Section Hdrs** tab lists standard sections such as `.text`, `.rdata`, `.data`.

**Sample sha256:** machine-specific (varies with compiler version). Record it with:
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe | Format-List Hash
```
Invariant validation marker string: `LAB-WINDOWS-BENIGN-MARKER-30`.

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (FLOSS surfaces obfuscated/encoded strings).
- **T1027.002 — Software Packing** (DIE entropy/packer detection).
- **T1140 — Deobfuscate/Decode Files or Information** (FLOSS emulates decoding routines).
- **T1518 — Software Discovery / build fingerprinting** (DIE compiler/linker identification, defensive context).
- **DFIR phase:** Identification → Examination (static triage of a recovered artifact prior to dynamic analysis/reversing).

## Sources
- Mandiant / FLARE-VM (tool distribution & FLOSS): https://github.com/mandiant/flare-vm and https://github.com/mandiant/flare-floss
- Detect-It-Easy (DIE) project: https://github.com/horsicq/Detect-It-Easy
- PE-bear project (hasherezade): https://github.com/hasherezade/pe-bear
- SANS FOR610 Reverse-Engineering Malware course: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Microsoft PE format specification: https://learn.microsoft.com/windows/win32/debug/pe-format
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/ and T1140: https://attack.mitre.org/techniques/T1140/
- Security Onion documentation (Zeek files.log / detection pivot): https://docs.securityonion.net/