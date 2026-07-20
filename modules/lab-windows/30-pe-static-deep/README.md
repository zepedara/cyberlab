# 30 * PE static analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
When you get a suspicious Windows program (an `.exe` or `.dll`), you want to learn as much as you can about it *without running it*. That is called static analysis. Windows programs use a standard layout called the Portable Executable (PE) format, which is like a labeled box: a header at the top describing the contents, then sections holding code, data, and resources. This module teaches three tools that read that box for you. **PE-bear** shows you the structure — headers, sections, and imported functions — in a friendly table so you can spot odd or hollowed-out files. **Detect-It-Easy (DIE)** tells you what compiler or packer built the file and flags suspicious signs like high randomness (entropy) that suggests hidden or compressed code. **FLOSS** pulls readable text out of a file, including strings the malware tried to hide by scrambling them at runtime. Together these give you fast, low-risk clues about what a file is and what it might do.

The PE format's overall layout (DOS header → NT headers → section table → sections) is defined in the Microsoft PE format specification, and every tool below simply parses that same structure (Microsoft Learn, *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PE-bear | Included in FLARE-VM | GUI PE parser: inspect DOS/NT headers, sections, imports/exports, resources |
| Detect-It-Easy (DIE) | Included in FLARE-VM | Identify compiler/packer/protector, scan entropy, run detection signatures |
| FLOSS | Included in FLARE-VM | Extract static, stack, tight, and decoded (obfuscated) strings from binaries |

Notes on tool behavior (from project docs):
- PE-bear is a multi-platform PE reversing tool that renders the DOS/NT headers, the section table, imports/exports, and resources; it parses only and does not execute the target (hasherezade/pe-bear: https://github.com/hasherezade/pe-bear).
- DIE is a signature-based file-type/packer identifier with an entropy calculator; the console front-end is `diec` (horsicq/Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy and https://github.com/horsicq/DIE-engine/wiki).
- FLOSS ("FLARE Obfuscated String Solver") extracts static strings and additionally uses emulation to recover *stack*, *tight*, and *decoded* strings that ordinary `strings` misses (mandiant/flare-floss: https://github.com/mandiant/flare-floss).
- All three are packaged and installed by FLARE-VM (mandiant/flare-vm: https://github.com/mandiant/flare-vm).

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
Expected output: FLOSS prints its version (e.g., `floss 3.x`), and the `Get-ChildItem` calls print the full paths to `PE-bear.exe` and the DIE console binary `diec.exe`. If FLARE-VM was installed via Chocolatey, tool paths may live under `C:\ProgramData\chocolatey\lib\...` — adjust the search root accordingly. FLARE-VM ships these packages via Chocolatey, so the exact install root can vary between builds (mandiant/flare-vm: https://github.com/mandiant/flare-vm). `floss --version` is a documented flag of the FLOSS CLI (mandiant/flare-floss: https://github.com/mandiant/flare-floss).

## Guided walkthrough
1. Build a benign sample to analyze (see Hands-on exercise) and confirm its hash.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: a 64-character hex SHA256 for the compiled benign sample. `Get-FileHash` is a built-in PowerShell cmdlet that defaults to SHA256; we pin `-Algorithm SHA256` explicitly so the digest is reproducible and comparable across machines (Microsoft Learn, *Get-FileHash*: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash). **Why:** hashing first gives you an immutable reference for your triage note and lets you confirm you analyzed exactly the bytes you think you did.

2. Identify the file type / compiler / packer with Detect-It-Easy console (`diec`).
```powershell
diec.exe .\exercise\sample.exe
```
Expected: DIE reports the file as a PE (e.g., `PE64` / `PE32`), names the compiler/linker (e.g., `Microsoft Visual C/C++`, `MinGW/GCC`), and — for an unpacked benign build — reports no packer. **Why:** DIE matches signature databases against header fields, entry-point code, and section characteristics to fingerprint the toolchain or packer, which tells you at a glance whether you are looking at a straightforward compiled binary or something wrapped for evasion (horsicq/Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy). Note the nuance: a "no packer detected" result is not proof of safety — custom or unknown packers may simply lack a signature, which is why step 3's entropy check is a useful cross-verification.

3. Show the entropy breakdown per section to reason about compression/packing.
```powershell
diec.exe -e .\exercise\sample.exe
```
Expected: a per-section entropy table. Entropy is measured on a 0–8 scale (bits per byte); a section value approaching 8.0 signals compressed or encrypted (often packed) content, while ordinary compiled x86/x64 code typically sits well below that. **Why:** packers and crypters compress or encrypt the real payload, which raises randomness — so the entropy view is an evidence-based check that complements the signature verdict in step 2 (DIE entropy calculator: https://github.com/horsicq/Detect-It-Easy). Do not treat a single high value as conclusive: legitimately compressed resources (e.g., embedded PNGs) can also read high, so combine entropy with import-table size and section names.

4. Recover strings — including obfuscated ones — with FLOSS.
```powershell
floss.exe --no-color .\exercise\sample.exe
```
Expected: FLOSS prints results grouped into static, stack, tight, and decoded string categories. You should see readable static strings (e.g., the benign marker string embedded at build time) and, for real malware, strings FLOSS reconstructs by emulating the sample's own decoding routines. **Why:** ordinary `strings` only recovers contiguous printable runs; FLOSS additionally uses the vivisect emulation engine to recover stack strings (built one character at a time on the stack), "tight" strings (built in tight loops), and decoded strings (produced by deobfuscation functions), which is exactly the text malware authors try to hide (mandiant/flare-floss: https://github.com/mandiant/flare-floss). `--no-color` disables ANSI coloring so output is clean for logs and `Select-String` (FLOSS CLI usage: https://github.com/mandiant/flare-floss/blob/master/doc/usage.md).

5. Open the sample in PE-bear (GUI) and review headers, sections, and imports.
```powershell
Start-Process "C:\Tools\PE-bear\PE-bear.exe" -ArgumentList "$PWD\exercise\sample.exe"
```
Expected: PE-bear launches with the file loaded. Review the **Section Hdrs** tab (compare `Raw size` vs `Virtual size`) and the **Imports** tab (note imported DLLs/APIs). **Why:** a large gap between raw (on-disk) and virtual (in-memory) size can indicate a section that unpacks itself at runtime, and a suspiciously small import table hints that capabilities are resolved dynamically at runtime rather than declared statically (hasherezade/pe-bear: https://github.com/hasherezade/pe-bear; PE section fields defined in Microsoft Learn *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format). PE-bear only parses the file — no window flashes an execution of the sample.

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
Because compiler/linker versions differ across FLARE-VM builds, the exact SHA256 will vary per machine — record the hash your build produces (see Answer key). The distinguishing invariant is the embedded marker string `LAB-WINDOWS-BENIGN-MARKER-30`. (`cl.exe` flags: `/Fe` names the output executable and `/nologo` suppresses the banner — Microsoft Learn, *MSVC compiler options*: https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file and https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner.)

**Tasks**
1. Use DIE to state the file class (PE32/PE64) and compiler.
2. Use DIE entropy mode to decide whether the sample is packed.
3. Use FLOSS to recover the benign marker string.
4. Use PE-bear to list at least two imported APIs and one section name.

## SOC analyst perspective
Static triage of a captured artifact is the first move in the DFIR examination phase. When an EDR or a Security Onion alert surfaces a suspicious executable, an analyst pulls the file into a sandboxed FLARE-VM and runs DIE + FLOSS + PE-bear before deeper reversing.

Concrete Security Onion pivots:
- **Suricata** may fire a file-download or malware-signature alert; the alert's `flow_id`/`community_id` lets you pivot from `alert` events to the corresponding `flow` records in Kibana/Hunt (Security Onion docs, *Alerts* and *Suricata*: https://docs.securityonion.net/en/2.4/suricata.html).
- **Zeek** logs the carved object in `files.log` (with `md5`/`sha1`/`sha256` when file hashing is enabled) and the transport in `http.log`/`conn.log`; pivot on the file hash and the `tx_hosts`/`rx_hosts` to see who else pulled the same PE (Security Onion docs, *Zeek*: https://docs.securityonion.net/en/2.4/zeek.html; Zeek `files.log` fields: https://docs.zeek.org/en/master/logs/files.html).
- **Elastic/Hunt**: take the FLOSS-decoded IOCs (URLs, mutex names, registry keys, command strings) and the DIE-identified packer name and run fleet-wide queries in the Security Onion Hunt/Dashboards interface (Security Onion docs: https://docs.securityonion.net/).

Detection logic and ATT&CK mapping:
- DIE's packer/entropy verdict maps to **T1027.002 (Software Packing)** (https://attack.mitre.org/techniques/T1027/002/). High entropy (approaching 8.0) plus a small import table plus obfuscated strings is a classic "packed and likely hostile" signal that justifies escalation and detonation.
- FLOSS-recovered obfuscated strings map to **T1027 (Obfuscated Files or Information)** (https://attack.mitre.org/techniques/T1027/) and, where a decode routine is emulated, **T1140 (Deobfuscate/Decode Files or Information)** (https://attack.mitre.org/techniques/T1140/).
- Recovered import tables and strings become IOCs you feed back into Security Onion and hunt across your fleet. Triaging a recovered artifact aligns with the SANS FOR610 static-analysis workflow (SANS FOR610: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).

## Attacker perspective
Attackers know static analysts read the PE box, so they fight back at build time. Concrete TTPs:
- **Packing/crypting (T1027.002, https://attack.mitre.org/techniques/T1027/002/):** UPX, Themida, or custom crypters compress/encrypt the real payload to raise section entropy and shrink the visible import table. *Artifacts left behind:* high per-section entropy (visible in DIE `-e`), tell-tale section names such as `UPX0`/`UPX1` or `.themida`, and a large gap between raw and virtual section sizes visible in PE-bear (UPX packer: https://github.com/upx/upx; section fields per Microsoft Learn *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format).
- **Dynamic import resolution (T1027, https://attack.mitre.org/techniques/T1027/):** building the import table at runtime via `LoadLibrary`/`GetProcAddress` hides capabilities from the static import view. *Artifact:* a suspiciously thin static import table alongside `LoadLibrary`/`GetProcAddress` in the imports (Microsoft Learn, *GetProcAddress*: https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).
- **String obfuscation (T1140, https://attack.mitre.org/techniques/T1140/):** XOR- or stack-encoding strings so plain `strings` finds nothing — which is exactly why FLOSS's emulation of stack/tight/decoded strings is valuable and, when it runs, surfaces the very strings the attacker tried to conceal (mandiant/flare-floss: https://github.com/mandiant/flare-floss).

Evasion vs. residual evidence: even sophisticated packing leaves abnormally high entropy, packer signatures DIE recognizes, anomalous section names, and raw/virtual size mismatches — the static-analysis "tells" that drive escalation.

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
4. **Imports/section** — In PE-bear the **Imports** tab shows CRT/`kernel32.dll` APIs (e.g., `GetStdHandle`, `WriteFile`/`__acrt_*`) and the **Section Hdrs** tab lists standard sections such as `.text`, `.rdata`, `.data`. (These are the standard sections emitted by MSVC; section semantics are defined in Microsoft Learn *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format. `GetStdHandle`/`WriteFile` are documented kernel32 console/file APIs: https://learn.microsoft.com/windows/console/getstdhandle and https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile.)

**Sample sha256:** machine-specific (varies with compiler version). Record it with:
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe | Format-List Hash
```
Invariant validation marker string: `LAB-WINDOWS-BENIGN-MARKER-30`.

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (FLOSS surfaces obfuscated/encoded strings) — https://attack.mitre.org/techniques/T1027/
- **T1027.002 — Software Packing** (DIE entropy/packer detection) — https://attack.mitre.org/techniques/T1027/002/
- **T1140 — Deobfuscate/Decode Files or Information** (FLOSS emulates decoding routines) — https://attack.mitre.org/techniques/T1140/
- **T1518 — Software Discovery** (build fingerprinting via DIE compiler/linker identification, defensive context) — https://attack.mitre.org/techniques/T1518/
- **DFIR phase:** Identification → Examination (static triage of a recovered artifact prior to dynamic analysis/reversing), consistent with the SANS FOR610 malware-analysis workflow (https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).

## Sources
Claim → source mapping (all URLs are official tool docs/repos, Microsoft Learn, MITRE ATT&CK, or Security Onion docs):

- PE file layout, section raw/virtual size fields, section semantics → Microsoft Learn, *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format
- Tool distribution (PE-bear, DIE, FLOSS packaged via Chocolatey) → Mandiant FLARE-VM: https://github.com/mandiant/flare-vm
- FLOSS behavior (static/stack/tight/decoded strings, emulation engine, `--version`, `--no-color`) → mandiant/flare-floss: https://github.com/mandiant/flare-floss and usage doc: https://github.com/mandiant/flare-floss/blob/master/doc/usage.md
- DIE file-type/packer identification, `diec` console, entropy calculator (`-e`) → horsicq/Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy and wiki: https://github.com/horsicq/DIE-engine/wiki
- PE-bear GUI parsing (DOS/NT headers, sections, imports/exports, resources; parse-only) → hasherezade/pe-bear: https://github.com/hasherezade/pe-bear
- `Get-FileHash` (default/`-Algorithm SHA256`) → Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- `cl.exe` flags `/Fe`, `/nologo` → Microsoft Learn MSVC options: https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file and https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner
- Kernel32 APIs `GetStdHandle`, `WriteFile`, `GetProcAddress` → Microsoft Learn: https://learn.microsoft.com/windows/console/getstdhandle , https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile , https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
- UPX packer (section names, compression) → https://github.com/upx/upx
- MITRE ATT&CK techniques → T1027: https://attack.mitre.org/techniques/T1027/ ; T1027.002: https://attack.mitre.org/techniques/T1027/002/ ; T1140: https://attack.mitre.org/techniques/T1140/ ; T1518: https://attack.mitre.org/techniques/T1518/
- SANS FOR610 Reverse-Engineering Malware course → https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Security Onion pivots (Suricata alerts, Zeek `files.log`) → https://docs.securityonion.net/ ; https://docs.securityonion.net/en/2.4/suricata.html ; https://docs.securityonion.net/en/2.4/zeek.html ; Zeek `files.log` fields: https://docs.zeek.org/en/master/logs/files.html

## Related modules
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- shares detect-it-easy (die) for fast file-type/packer verdicts.
- [Static reverse engineering](../12-static-re/README.md) -- shares floss for string-driven capability inference.
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares floss and extends the entropy/packing signals covered here.
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- shares floss and drills into stack/tight/decoded string recovery.

<!-- cyberlab-enriched: v1 -->
