# 43 * PE-bear structure analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
Every Windows program (.exe, .dll) follows a strict blueprint called the Portable Executable (PE) format. Think of it like the anatomy of a file: a header that says "I am a Windows program," a table listing which system functions it borrows, and named rooms (sections) holding code and data. PE-bear is a friendly visual tool that opens this blueprint and lays out each part in tables you can click through, so you can spot when something looks wrong — like a program that hides its imports, claims a fake compile date, or has a section that is packed and unreadable. Detect-It-Easy (DIE) is a companion tool that quickly guesses what compiler or packer built a file and flags suspicious signs like encryption or unusual entropy. Together they let a beginner examine a suspicious file safely, without running it, and build an early picture of whether it is normal software or something that has been tampered with to evade detection.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PE-bear | Included in FLARE-VM | Visual PE structure parser: headers, sections, imports/exports, resources |
| Detect-It-Easy | Included in FLARE-VM | Packer/compiler signature detection, entropy analysis, file type ID |

## Learning objectives
- Navigate every major PE structure in PE-bear (DOS/NT headers, section table, data directories, imports).
- Identify anomalies indicating packing or tampering (high entropy, mismatched raw/virtual sizes, tiny import tables).
- Use Detect-It-Easy to classify a file's compiler/packer and read its per-section entropy graph.
- Cross-reference PE-bear findings with DIE to form an evidence-based "packed vs. clean" conclusion.

## Environment check
```powershell
# Confirm both tools are present on FLARE-VM (paths from the FLARE-VM tools directory)
Get-ChildItem "C:\Tools" -Recurse -Filter "PE-bear.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 FullName

Get-ChildItem "C:\Tools" -Recurse -Filter "die.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 FullName

# Expected output: one FullName line for PE-bear.exe and one for die.exe.
# If FLARE-VM used desktop shortcuts, launch from Start Menu -> "PE-bear" / "Detect It Easy".
```

## Guided walkthrough
1. Generate a clean baseline sample to compare against later.
```powershell
# Copy a known-good system binary to a working folder for analysis
New-Item -ItemType Directory -Force -Path C:\work\pe-lab | Out-Null
Copy-Item C:\Windows\System32\calc.exe C:\work\pe-lab\clean.exe
Get-FileHash C:\work\pe-lab\clean.exe -Algorithm SHA256
# Expected output: a SHA256 line for clean.exe (value depends on OS build).
```

2. Open `clean.exe` in PE-bear and inspect the DOS header, NT headers, and section table. Note the "Characteristics" flags and the `TimeDateStamp`.
```powershell
# Launch PE-bear against the file (adjust path if your FLARE-VM install differs)
& "C:\Tools\PE-bear\PE-bear.exe" C:\work\pe-lab\clean.exe
# Expected: GUI opens; left pane shows DOS Hdr, NT Hdrs, Section Hdrs, Imports.
# Observe .text, .data, .rdata sections with sane Raw/Virtual sizes and a large Import table.
```

3. Run Detect-It-Easy on the same file to confirm the compiler and view entropy.
```powershell
# DIE command-line scan; -j gives JSON, easy to read in the terminal
& "C:\Tools\die\diec.exe" C:\work\pe-lab\clean.exe
# Expected output: identifies "Compiler: Microsoft Visual C/C++" or "Linker: Microsoft Linker"
# and reports "not packed" / low overall entropy for a normal system binary.
```

4. Compare imports: a clean binary imports many named APIs; a packed one often shows only `LoadLibrary`/`GetProcAddress`. In PE-bear, click **Imports** and count the DLLs and functions.

## Hands-on exercise
Analyze the benign packed sample in this module's `exercise/` directory: **`packed_hello.exe`**.

**Sample declaration**
- Type: 64-bit Windows PE executable (a trivial "Hello World" C program), then compressed with UPX to simulate packing.
- Safe origin: benign/inert, no network egress, no payload — built from source you compile yourself. It is NOT live malware.
- Reproducible generator (run on FLARE-VM; produces the exact sample):
```powershell
New-Item -ItemType Directory -Force -Path C:\work\pe-lab\exercise | Out-Null
Set-Content -Path C:\work\pe-lab\exercise\hello.c -Value @'
#include <stdio.h>
int main(void){ printf("hello lab\n"); return 0; }
'@
# Compile with the FLARE-VM VC build tools, then pack with UPX
cl /nologo /Fe:C:\work\pe-lab\exercise\hello.exe C:\work\pe-lab\exercise\hello.c
upx --best -o C:\work\pe-lab\exercise\packed_hello.exe C:\work\pe-lab\exercise\hello.exe
Get-FileHash C:\work\pe-lab\exercise\packed_hello.exe -Algorithm SHA256
```

**Task:** Open `packed_hello.exe` in PE-bear and DIE. Identify (a) the packer name, (b) the section names, (c) evidence of packing in the section table, and (d) the overall entropy.

## SOC analyst perspective
A SOC analyst pulls a suspicious binary off a host during triage and needs a verdict before letting it run. PE-bear and DIE give fast static signals: a tiny import table, high entropy, non-standard section names (`UPX0`, `.packed`), or a Raw size of zero with a large Virtual size all suggest a packer or self-decrypting loader — behavior mapped to MITRE ATT&CK T1027.002 (Software Packing) and T1140 (Deobfuscate/Decode). These indicators feed detection engineering: entropy and import-hash (imphash) values captured here can become Suricata/YARA rules and Zeek `file.log` enrichments in Security Onion, letting analysts pivot on the imphash across all observed downloads and correlate the file hash with alerts to scope an incident.

## Attacker perspective
Attackers modify the PE structure specifically to defeat static detection. They pack or crypt binaries so signature engines only see high-entropy blobs, strip or forge the import table so `LoadLibrary`/`GetProcAddress` resolve APIs at runtime, and falsify the `TimeDateStamp` or section names to blend in or mislead triage. Some overwrite the Rich header or add oversized overlays to break naive parsers. Each of these leaves artifacts a defender can find: mismatched Raw vs. Virtual sizes, entropy spikes, suspicious section flags (executable + writable), a suspiciously small import directory, and packer signatures that DIE fingerprints — all recoverable purely by inspecting the file, without ever executing it.

## Answer key
Expected findings for `packed_hello.exe`:
- (a) Packer: **UPX** — DIE reports "Packer: UPX" and PE-bear shows the UPX signature.
- (b) Sections: **UPX0**, **UPX1**, and typically **UPX2/.rsrc** (names created by UPX).
- (c) Packing evidence: `UPX0` has a Raw size of 0 but a large Virtual size; the executable+writable characteristics on the packed section; a very small import table (mostly `KERNEL32.dll` with `LoadLibraryA`/`GetProcAddress`).
- (d) Entropy: DIE reports **high entropy (typically > 7.0)** on the packed section, flagged "packed."

Commands that produce the findings:
```powershell
& "C:\Tools\die\diec.exe" C:\work\pe-lab\exercise\packed_hello.exe
# -> "Packer: UPX(...)" and per-section high-entropy report
& "C:\Tools\PE-bear\PE-bear.exe" C:\work\pe-lab\exercise\packed_hello.exe
# -> Section Hdrs pane shows UPX0 (Raw=0) / UPX1; Imports pane shows minimal API set
Get-FileHash C:\work\pe-lab\exercise\packed_hello.exe -Algorithm SHA256
```
Note: because the sample is generated locally, its SHA256 is the value printed by the generator's `Get-FileHash` command above (record it after building — UPX output is deterministic per toolchain version). The validator holds the reference digest.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information.
- **T1027.002** — Software Packing.
- **T1140** — Deobfuscate/Decode Files or Information.
- **T1036** — Masquerading (forged timestamps/section names).
- DFIR phase: **Examination / Analysis** (static triage of a collected artifact prior to dynamic analysis).

## Sources
- PE-bear (hasherezade) — https://github.com/hasherezade/pe-bear
- Detect-It-Easy — https://github.com/horsicq/Detect-It-Easy
- FLARE-VM (Mandiant/Google) — https://github.com/mandiant/flare-vm
- Microsoft PE Format specification — https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- MITRE ATT&CK T1027.002 (Software Packing) — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 (Deobfuscate/Decode Files or Information) — https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- UPX packer — https://upx.github.io/