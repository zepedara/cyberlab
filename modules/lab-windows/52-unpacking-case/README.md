# 52 * Scenario: packed-malware unpacking workflow -- LAB-WINDOWS

## Overview (plain language)
Many malicious programs are "packed" — squeezed and scrambled so their real code only appears in memory once the program runs. This makes them hard to read with normal static tools. This module walks through a beginner-friendly unpacking workflow: you first inspect a suspicious file to spot the tell-tale signs of packing, then run it under a controlled debugger, let it unpack itself in memory, and grab (dump) the now-visible clean code so you can study what the malware really does. The three tools work as a team — one shows the file's structure, one lets you drive and freeze execution, and one pulls readable strings out before and after unpacking so you can measure your success.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | Pre-installed on FLARE-VM | User-mode debugger to run a sample step-by-step, break at the unpacking tail-jump (OEP), and dump the unpacked process image. |
| PE-bear | Pre-installed on FLARE-VM | PE structure viewer to inspect sections, entropy, imports, and confirm packing indicators before/after unpacking. |
| FLOSS | Pre-installed on FLARE-VM | FireEye/Mandiant string extractor that also decodes obfuscated/stack strings, used to compare readable strings before vs after unpacking. |

## Learning objectives
- Identify at least three static indicators of a packed PE (high entropy, non-standard section names, tiny import table) using PE-bear.
- Compare FLOSS string output on the packed vs unpacked binary and quantify the difference.
- Use x64dbg to reach the Original Entry Point (OEP) after the unpacking stub runs.
- Produce a memory-dumped, reconstructed executable of the unpacked payload.
- Verify the dump is more analyzable than the original (richer imports and strings).

## Environment check
```powershell
# Confirm the three tools are present on FLARE-VM (PowerShell)
Get-ChildItem "C:\Tools\x64dbg" -Recurse -Filter "x64dbg.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 FullName

Get-ChildItem "C:\Tools" -Recurse -Filter "PE-bear.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 FullName

# FLOSS is on PATH via FLARE-VM
floss --version
```
Expected output: full paths to `x64dbg.exe` and `PE-bear.exe`, and a FLOSS version banner such as `floss 3.x`.

## Guided walkthrough
1. Build a benign, UPX-packed sample (safe, inert) so nothing malicious is ever run.
```powershell
# Compile a harmless C program that just prints a marker string, then pack it with UPX.
$src = @'
#include <stdio.h>
int main(void){ printf("BENIGN-UNPACK-LAB-MARKER-52\n"); return 0; }
'@
Set-Content -Path .\exercise\hello.c -Value $src -Encoding ASCII
cl /nologo /Fe:.\exercise\sample.exe .\exercise\hello.c
Copy-Item .\exercise\sample.exe .\exercise\sample_packed.exe
upx --best .\exercise\sample_packed.exe
```
Expected output: `cl` produces `sample.exe`; `upx` reports `Packed 1 file.` and shrinks `sample_packed.exe`.

2. Inspect packing indicators in PE-bear.
```powershell
# Open the packed file in PE-bear for manual review of sections/entropy/imports.
Start-Process "C:\Tools\PE-bear\PE-bear.exe" -ArgumentList ".\exercise\sample_packed.exe"
```
Expected observable: sections named `UPX0`/`UPX1`, high entropy (~7.5+) on the packed section, and a very small import table.

3. Compare readable strings before unpacking with FLOSS.
```powershell
# Extract strings from the packed sample; the marker should be hidden/absent.
floss .\exercise\sample_packed.exe > .\exercise\floss_packed.txt
Select-String -Path .\exercise\floss_packed.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"
```
Expected output: no match (the marker string is compressed away in the packed image).

4. Run under x64dbg, reach OEP, and dump. In the GUI:
   - File → Open `exercise\sample_packed.exe`.
   - The UPX stub uses a tail `jmp` to the OEP. Set a breakpoint or use "Run until user code", then dump with the built-in dump plugin (Scylla via *Plugins → Scylla*), and save `sample_dumped.exe`.

5. Confirm the dump is now readable with FLOSS.
```powershell
floss .\exercise\sample_dumped.exe > .\exercise\floss_dumped.txt
Select-String -Path .\exercise\floss_dumped.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"
```
Expected output: the marker string `BENIGN-UNPACK-LAB-MARKER-52` now appears.

## Hands-on exercise
Using the sample in this module's `exercise/` dir, complete the full workflow:
1. In PE-bear, record the two section names and the highest section entropy of `sample_packed.exe`.
2. Run FLOSS against the packed file and count matches for the marker string (should be 0).
3. Unpack `sample_packed.exe` in x64dbg, dump to `sample_dumped.exe`, and run FLOSS again to prove the marker is recovered.

Sample declaration:
- **Type:** UPX-packed 64-bit Windows PE executable (`sample_packed.exe`).
- **Safe origin:** Benign/inert — generated locally from the `hello.c` source shown above (prints one marker line, performs no network or file activity). NO live malware is used.
- **Reproducible generator:** the `cl` + `upx --best` commands in the Guided walkthrough build the sample deterministically inside `exercise/`. (Because UPX/toolchain versions vary, verify the *pre-pack* binary instead — see Answer key.)

## SOC analyst perspective
A defender rarely unpacks by hand in production, but understanding packing drives detection. Packed samples raise high-entropy alerts and yield almost no useful static strings, so a SOC pivots to behavior: in Security Onion, correlate Zeek/Suricata network telemetry and Sysmon process-creation (Event ID 1) and image-load events around the sample's execution. Mapping to MITRE ATT&CK, packing is **T1027.002 (Software Packing)** and self-unpacking maps to **T1140 (Deobfuscate/Decode Files or Information)**; process image manipulation aligns with **T1055 (Process Injection)**. FLOSS output on a dumped image feeds IOC extraction (C2 hosts, mutexes) that become Suricata/YARA hunt rules in the hunting workflow.

## Attacker perspective
Attackers pack payloads to defeat signature scanners, hide C2 strings, and slow analysts. Common packers (UPX, custom crypters) add a stub that decompresses the real code into memory at runtime, leaving only the loader visible on disk. Offensively this buys time and reduces detonation-time IOCs, but it also leaves artifacts: abnormal section names (`UPX0/UPX1`), section entropy near 8.0, a stripped import table later rebuilt at runtime, RWX memory regions, and a distinctive tail-jump to the OEP. Those very tells are what let PE-bear flag the file and x64dbg locate the unpacking jump, so the evasion technique itself seeds the evidence a defender uses to unmask it.

## Answer key
- **PE-bear:** sections `UPX0` and `UPX1`; packed section entropy roughly 7.5–7.9.
- **FLOSS (packed):** `Select-String ... "BENIGN-UNPACK-LAB-MARKER-52"` returns 0 matches.
- **FLOSS (dumped):** after x64dbg unpack + Scylla dump, the same command returns ≥1 match.
- Reproduce the string checks:
```powershell
floss .\exercise\sample_packed.exe | Select-String "BENIGN-UNPACK-LAB-MARKER-52"   # 0 hits
floss .\exercise\sample_dumped.exe | Select-String "BENIGN-UNPACK-LAB-MARKER-52"   # >=1 hit
```
- **Integrity check (pre-pack binary is deterministic per toolchain):**
```powershell
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
Sample sha256 (of the locally built unpacked reference `sample.exe`; recorded by the validator on first build):
`c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

## MITRE ATT&CK & DFIR phase
- **T1027.002** — Obfuscated Files or Information: Software Packing.
- **T1140** — Deobfuscate/Decode Files or Information (the runtime unpacking stub).
- **T1055** — Process Injection (relevant when real malware unpacks into a host process).
- **DFIR phase:** Examination / Analysis (malware static+dynamic reverse engineering).

## Sources
- Mandiant FLOSS — https://github.com/mandiant/flare-floss
- FLARE-VM (tooling incl. x64dbg, PE-bear, FLOSS) — https://github.com/mandiant/flare-vm
- x64dbg documentation — https://help.x64dbg.com/en/latest/
- PE-bear — https://github.com/hasherezade/pe-bear
- UPX packer — https://upx.github.io/
- MITRE ATT&CK T1027.002 — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 — https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/