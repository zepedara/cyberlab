# 43 * PE-bear structure analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
Every Windows program (.exe, .dll) follows a strict blueprint called the Portable Executable (PE) format. Think of it like the anatomy of a file: a header that says "I am a Windows program," a table listing which system functions it borrows, and named rooms (sections) holding code and data. PE-bear is a friendly visual tool that opens this blueprint and lays out each part in tables you can click through, so you can spot when something looks wrong — like a program that hides its imports, claims a fake compile date, or has a section that is packed and unreadable. Detect-It-Easy (DIE) is a companion tool that quickly guesses what compiler or packer built a file and flags suspicious signs like encryption or unusual entropy. Together they let a beginner examine a suspicious file safely, without running it, and build an early picture of whether it is normal software or something that has been tampered with to evade detection.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PE-bear | Included in FLARE-VM | Visual PE structure parser: headers, sections, imports/exports, resources |
| Detect-It-Easy | Included in FLARE-VM | Packer/compiler signature detection, entropy analysis, file type ID |

PE-bear is a free multi-platform PE reversing/analysis tool authored by hasherezade; the sections, imports, resources, and hex-diff views described here match its documented feature set ([github.com/hasherezade/pe-bear](https://github.com/hasherezade/pe-bear)). Detect-It-Easy (DIE) is an open-source program for determining file types, with a GUI, a console front-end (`diec`), and a scriptable signature engine ([github.com/horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)). Both are packaged as part of the Mandiant FLARE-VM tool set ([github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)).

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
Note: FLARE-VM installs tools via Chocolatey packages and creates Start Menu / Desktop shortcuts; exact on-disk paths under `C:\Tools` can vary by package version, so the recursive search above is the reliable way to locate the binaries ([github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)). The DIE distribution ships both `die.exe` (GUI) and `diec.exe` (console); the walkthrough uses `diec.exe` for terminal-friendly output ([github.com/horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)).

## Guided walkthrough
1. Generate a clean baseline sample to compare against later.
```powershell
# Copy a known-good system binary to a working folder for analysis
New-Item -ItemType Directory -Force -Path C:\work\pe-lab | Out-Null
Copy-Item C:\Windows\System32\calc.exe C:\work\pe-lab\clean.exe
Get-FileHash C:\work\pe-lab\clean.exe -Algorithm SHA256
# Expected output: a SHA256 line for clean.exe (value depends on OS build).
```
Why: a Microsoft-signed system binary is a trustworthy "known-good" reference, so any structural difference you later see in the packed sample stands out. Note that on Windows 10/11 `C:\Windows\System32\calc.exe` is a small launcher stub that starts the Store Calculator app rather than the classic calculator — that is fine here because we only care about its PE structure, not its behavior. `Get-FileHash` computes a SHA256 digest per Microsoft Learn's documented default/`-Algorithm` behavior ([learn.microsoft.com Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash)).

2. Open `clean.exe` in PE-bear and inspect the DOS header, NT headers, and section table. Note the "Characteristics" flags and the `TimeDateStamp`.
```powershell
# Launch PE-bear against the file (adjust path if your FLARE-VM install differs)
& "C:\Tools\PE-bear\PE-bear.exe" C:\work\pe-lab\clean.exe
# Expected: GUI opens; left pane shows DOS Hdr, NT Hdrs, Section Hdrs, Imports.
# Observe .text, .data, .rdata sections with sane Raw/Virtual sizes and a large Import table.
```
Why: the DOS header begins with the `MZ` magic (`0x5A4D`) and its `e_lfanew` field points to the PE header; the NT headers hold the COFF `FileHeader` (with `TimeDateStamp` and `Characteristics`) and the `OptionalHeader` (entry point, image base, data directories). These field definitions are from Microsoft's PE format spec ([learn.microsoft.com PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)). Nuance: `TimeDateStamp` is a 32-bit epoch value the linker writes and is trivially forgeable, so treat it as a lead, not proof. A benign compiler-produced binary shows conventional section names (`.text`, `.rdata`, `.data`, `.rsrc`) whose `Characteristics` flags match their role — `.text` is `MEM_EXECUTE|MEM_READ` and normally NOT writable; a section that is simultaneously writable and executable is a classic packer/self-modifying-code tell ([learn.microsoft.com PE Format — Section Flags](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags)).

3. Run Detect-It-Easy on the same file to confirm the compiler and view entropy.
```powershell
# DIE console scan; low overall entropy is expected for an unpacked binary
& "C:\Tools\die\diec.exe" C:\work\pe-lab\clean.exe
# Expected output: identifies "Linker: Microsoft Linker" / "Compiler: Microsoft Visual C/C++"
# and reports low overall entropy for a normal system binary (not packed).
```
Why: DIE matches the file against its signature database to name the compiler/linker and any known packer, and it can compute Shannon entropy per section. Interpretation nuance: entropy is measured on a 0–8 scale (bits per byte); ordinary code/data sits well below 8, while compressed or encrypted content approaches 8. DIE flags sections it considers "packed" when entropy is high (a commonly cited threshold near ~7.0) ([github.com/horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)). To print an entropy report explicitly, use the `-e` / entropy option documented by the project. (Earlier drafts of this module used `diec.exe -j`; the console front-end's exact flags vary by release, so run `diec.exe --help` to confirm the JSON/entropy switches for your installed version.)

4. Compare imports: a clean binary imports many named APIs; a packed one often shows only `LoadLibrary`/`GetProcAddress`. In PE-bear, click **Imports** and count the DLLs and functions.

Why: the Import Address Table (IAT) is described in the PE data directories; a normal program statically lists the DLLs and named functions it needs so the loader can resolve them ([learn.microsoft.com PE Format — The .idata Section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section)). A packed binary typically has its real imports compressed inside the payload and exposes only a bootstrap import set — most often `KERNEL32.dll!LoadLibraryA` and `GetProcAddress` — which the unpacking stub uses to rebuild the IAT at runtime. That collapse of the import table is one of the strongest static packing signals and maps to MITRE ATT&CK T1027.002 ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/)).

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
Note: `cl.exe` is the MSVC compiler driver; `/Fe` names the output executable ([learn.microsoft.com /Fe](https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file)). `upx --best` selects the best (slowest) compression level and `-o` names the output file, per the UPX manual ([upx.github.io](https://upx.github.io/), [github.com/upx/upx](https://github.com/upx/upx)).

**Task:** Open `packed_hello.exe` in PE-bear and DIE. Identify (a) the packer name, (b) the section names, (c) evidence of packing in the section table, and (d) the overall entropy.

## SOC analyst perspective
A SOC analyst pulls a suspicious binary off a host during triage and needs a verdict before letting it run. PE-bear and DIE give fast static signals: a tiny import table, high entropy, non-standard section names (`UPX0`, `.packed`), or a Raw size of zero with a large Virtual size all suggest a packer or self-decrypting loader.

Concrete detection logic and MITRE mapping:
- **Software packing — T1027.002** ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/)): alert on PE sections with Shannon entropy ≥ 7.0, on `UPX0/UPX1` (or other non-`.text/.rdata/.data/.rsrc`) section names, and on writable+executable section flags (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`) as defined in the PE spec ([learn.microsoft.com PE Format — Section Flags](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags)).
- **Deobfuscate/Decode at runtime — T1140** ([attack.mitre.org/techniques/T1140](https://attack.mitre.org/techniques/T1140/)): a bootstrap import set of only `LoadLibraryA`/`GetProcAddress` indicates the IAT is rebuilt at runtime.
- **Masquerading — T1036** ([attack.mitre.org/techniques/T1036](https://attack.mitre.org/techniques/T1036/)): forged `TimeDateStamp` or copied section names used to blend in.

Security Onion pivots:
- **Zeek** logs `pe.log` (compile time, section names, is-64-bit, machine) and `files.log` (`mime_type`, `sha256`, `md5`) for observed transfers; pivot from a PE-bear finding to every host that downloaded the same `sha256`, and use `pe.log` section names to hunt look-alikes ([docs.zeek.org PE analyzer](https://docs.zeek.org/en/master/scripts/base/protocols/http/files.zeek.html), [securityonion.net docs](https://docs.securityonion.net/)).
- **Suricata** can match on file `filesha256` / YARA-based `filemagic` rules to flag the hash or a UPX byte pattern on the wire ([suricata.readthedocs.io File Keywords](https://suricata.readthedocs.io/en/latest/rules/file-keywords.html)).
- **Elastic (Kibana Discover/Hunt)**: pivot on `file.hash.sha256` and `file.pe.imphash` to cluster related samples; the imphash (import-hash) groups binaries that share the same import layout, a well-known triage pivot ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/), [securityonion.net docs](https://docs.securityonion.net/)).

These indicators feed detection engineering: entropy and imphash values captured here become Suricata/YARA rules and Zeek `files.log`/`pe.log` enrichments in Security Onion, letting analysts correlate the file hash with alerts to scope an incident.

## Attacker perspective
Attackers modify the PE structure specifically to defeat static detection. Concrete TTPs and the artifacts they leave:
- **Pack/crypt the payload (T1027.002)** so signature engines see only a high-entropy blob. Artifact: near-8.0 entropy in the packed section, `UPX0` with Raw size 0 / large Virtual size, and a shrunken import directory ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/), [upx.github.io](https://upx.github.io/)).
- **Strip/forge the IAT (T1140)** so real APIs are resolved at runtime via `LoadLibrary`/`GetProcAddress`. Artifact: a suspiciously small import table dominated by loader-resolution functions ([learn.microsoft.com PE Format — .idata](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section), [attack.mitre.org/techniques/T1140](https://attack.mitre.org/techniques/T1140/)).
- **Masquerade (T1036)** by forging `TimeDateStamp`, copying legit section names, or overwriting/spoofing the Rich header (an undocumented MSVC-linker artifact between the DOS stub and PE header). Artifact: inconsistent or implausible timestamps and mismatched build metadata ([attack.mitre.org/techniques/T1036](https://attack.mitre.org/techniques/T1036/), [learn.microsoft.com PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)).
- **Evasion nuance:** to hide from naive entropy heuristics, attackers may re-pad sections toward "normal" entropy, append large low-entropy overlays, or use custom packers whose signatures DIE does not yet know. Even then, mismatched Raw vs. Virtual sizes, writable+executable section flags, and a collapsed IAT remain recoverable purely by inspecting the file, without ever executing it.

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

Why these findings hold: UPX's own documentation describes it as a compressor that produces the `UPX0`/`UPX1` layout, where the first section is reserved (uncompressed, zero raw data) to receive the decompressed image at runtime ([upx.github.io](https://upx.github.io/), [github.com/upx/upx](https://github.com/upx/upx)). The writable+executable flag on the unpacking section follows the PE section-flags definitions ([learn.microsoft.com PE Format — Section Flags](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags)).

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information. https://attack.mitre.org/techniques/T1027/
- **T1027.002** — Software Packing. https://attack.mitre.org/techniques/T1027/002/
- **T1140** — Deobfuscate/Decode Files or Information. https://attack.mitre.org/techniques/T1140/
- **T1036** — Masquerading (forged timestamps/section names). https://attack.mitre.org/techniques/T1036/
- DFIR phase: **Examination / Analysis** (static triage of a collected artifact prior to dynamic analysis).

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- PE-bear features (sections/imports/resources/hex views) — hasherezade PE-bear repo: https://github.com/hasherezade/pe-bear
- Detect-It-Easy behavior, `diec` console front-end, signature/entropy engine — DIE repo: https://github.com/horsicq/Detect-It-Easy
- Both tools bundled; FLARE-VM install model and shortcuts — Mandiant FLARE-VM: https://github.com/mandiant/flare-vm
- PE format fields: DOS `MZ`/`e_lfanew`, COFF `FileHeader` (`TimeDateStamp`, `Characteristics`), `OptionalHeader`, data directories — Microsoft PE Format spec: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Section characteristics flags (`MEM_EXECUTE`/`MEM_READ`/`MEM_WRITE`) — Microsoft PE Format, Section Flags: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
- Import table / IAT (`.idata`) layout — Microsoft PE Format, .idata Section: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
- `Get-FileHash` SHA256 behavior — Microsoft Learn: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- `cl.exe` `/Fe` output-name flag — Microsoft Learn: https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file
- UPX `--best` / `-o` options and `UPX0`/`UPX1` section behavior — UPX site and repo: https://upx.github.io/ and https://github.com/upx/upx
- MITRE ATT&CK T1027 — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 (Software Packing, imphash pivot) — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 (Deobfuscate/Decode) — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1036 (Masquerading) — https://attack.mitre.org/techniques/T1036/
- Zeek file/PE logging (`files.log`, `pe.log`) — Zeek docs: https://docs.zeek.org/
- Suricata file keywords (`filesha256`, filemagic/YARA) — Suricata docs: https://suricata.readthedocs.io/en/latest/rules/file-keywords.html
- Security Onion (Suricata/Zeek/Elastic pivots) — Security Onion docs: https://docs.securityonion.net/
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [PE static analysis deep-dive](../30-pe-static-deep/README.md) -- shares pe-bear for deeper header/section/data-directory analysis.
- [Static reverse engineering](../12-static-re/README.md) -- shares pe-bear within a broader static RE workflow.
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares pe-bear and extends this packing detection into a full unpacking case.
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- shares pe-bear for time-boxed triage decis

<!-- cyberlab-enriched: v1 -->
