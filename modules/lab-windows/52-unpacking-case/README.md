# 52 * Scenario: packed-malware unpacking workflow -- LAB-WINDOWS

## Overview (plain language)
Many malicious programs are "packed" — squeezed and scrambled so their real code only appears in memory once the program runs. This makes them hard to read with normal static tools. This module walks through a beginner-friendly unpacking workflow: you first inspect a suspicious file to spot the tell-tale signs of packing, then run it under a controlled debugger, let it unpack itself in memory, and grab (dump) the now-visible clean code so you can study what the malware really does. The three tools work as a team — one shows the file's structure, one lets you drive and freeze execution, and one pulls readable strings out before and after unpacking so you can measure your success.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | Pre-installed on FLARE-VM | Open-source x64/x32 user-mode debugger to run a sample step-by-step, break at the unpacking tail-jump (OEP), and dump the unpacked process image (via the bundled Scylla plugin). See the x64dbg docs. |
| PE-bear | Pre-installed on FLARE-VM | PE structure viewer (by hasherezade) to inspect sections, per-section entropy, imports, and confirm packing indicators before/after unpacking. |
| FLOSS | Pre-installed on FLARE-VM | Mandiant (formerly FireEye) string extractor that also decodes obfuscated/stack/tight strings, used to compare readable strings before vs after unpacking. |

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

> Note: FLARE-VM installs these packages via Chocolatey; exact install paths can vary by version, so the recursive `Get-ChildItem` search above is intentionally path-tolerant. FLOSS's `--version` flag is documented in the Mandiant flare-floss repo (see Sources).

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
Expected output: `cl` produces `sample.exe`; `upx --best` reports `Packed 1 file.` and shrinks `sample_packed.exe`.
**Why:** UPX is a real, open-source executable packer that compresses the original code/data into a compressed section and prepends a small self-decompression stub; `--best` selects the highest compression level (documented in the UPX help/README). We use UPX because its behavior — self-unpacking at runtime into memory, then jumping to the original entry point — mirrors what malicious packers do, but the payload here is provably benign. The *nuance*: UPX renames the original sections to `UPX0` (destination for the decompressed image, raw size 0 on disk) and `UPX1` (holds the compressed data + stub); this on-disk vs in-memory size mismatch is itself a packing tell.

2. Inspect packing indicators in PE-bear.
```powershell
# Open the packed file in PE-bear for manual review of sections/entropy/imports.
Start-Process "C:\Tools\PE-bear\PE-bear.exe" -ArgumentList ".\exercise\sample_packed.exe"
```
Expected observable: sections named `UPX0`/`UPX1`, high entropy on the packed section, and a very small import table.
**Why:** PE-bear parses the PE headers so you can read the Section Table without running the file. Look for three converging signals: (a) non-standard section names `UPX0`/`UPX1` instead of `.text`/`.data`/`.rdata`; (b) elevated entropy on the compressed section — compressed/encrypted data approaches the theoretical maximum of 8.0 bits/byte (Shannon entropy), so values in the ~7.5–8.0 range strongly suggest compression/encryption rather than normal code (~5.5–6.5); and (c) a stripped/minimal import table, because the real imports are reconstructed at runtime by the stub. The *nuance*: `UPX0` typically shows a large virtual size but a raw (on-disk) size of 0 — the decompressed code has nowhere to live on disk, only in memory.

3. Compare readable strings before unpacking with FLOSS.
```powershell
# Extract strings from the packed sample; the marker should be hidden/absent.
floss .\exercise\sample_packed.exe > .\exercise\floss_packed.txt
Select-String -Path .\exercise\floss_packed.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"
```
Expected output: no match (the marker string is compressed away in the packed image).
**Why:** FLOSS first runs a static-strings pass (like `strings`) and then attempts to automatically extract *obfuscated* strings (stack strings, tight strings, and — in older versions — emulated decoded strings). On a UPX-packed file the marker lives inside the compressed `UPX1` blob, so it does not appear as a contiguous ASCII/UTF-16 run to the static pass. The *nuance*: FLOSS may still surface stub/loader artifacts (e.g., the `UPX!` magic or library names the stub needs), which is exactly the "almost no useful strings, but obvious loader residue" pattern analysts learn to recognize.

4. Run under x64dbg, reach OEP, and dump. In the GUI:
   - File → Open `exercise\sample_packed.exe`.
   - The UPX stub decompresses `UPX1` into the `UPX0` region and finishes with a tail `jmp` that transfers control to the Original Entry Point (OEP). A reliable manual technique for UPX is to note that the stub begins with `pushad` (saving all registers) and restores them with `popad` near the end; set a hardware breakpoint on the saved stack region after `pushad`, run, and the breakpoint fires just before the tail `jmp` to OEP. Alternatively use "Run until user code" / step to the far jump.
   - Once paused at OEP, dump the process with the bundled Scylla plugin (*Plugins → Scylla*): use **Dump**, then **IAT Autosearch** + **Get Imports** to rebuild the import table, then **Fix Dump** to produce a reconstructed, statically-analyzable `sample_dumped.exe`.
   **Why:** x64dbg is a live debugger, so it lets the file unpack *itself* in memory — you never have to reverse the compression algorithm by hand. The reason to stop precisely at OEP is that this is the moment the original code is fully decompressed but has not yet run; dumping here captures the clean image. Scylla's IAT reconstruction matters because the raw memory dump has runtime-resolved import pointers that a static tool cannot follow — "Fix Dump" rewrites a valid import directory so PE-bear/FLOSS can parse it.

5. Confirm the dump is now readable with FLOSS.
```powershell
floss .\exercise\sample_dumped.exe > .\exercise\floss_dumped.txt
Select-String -Path .\exercise\floss_dumped.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"
```
Expected output: the marker string `BENIGN-UNPACK-LAB-MARKER-52` now appears.
**Why:** After unpacking, the decompressed `.rdata`/`.text` are present as plain bytes in the dump, so the static-strings pass recovers the marker. This before/after delta is the concrete, measurable proof that your unpack succeeded.

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
A defender rarely unpacks by hand in production, but understanding packing drives detection. Packed samples raise high-entropy alerts and yield almost no useful static strings, so a SOC pivots to behavior.

- **Static/scan-time detection:** high per-section entropy (~7.5–8.0) plus non-standard section names (`UPX0`/`UPX1`) and a near-empty import table are classic YARA/AV heuristics for **T1027.002 (Software Packing)**. The `UPX!` magic marker in the stub is a well-known signature. (MITRE ATT&CK T1027.002; see Sources.)
- **Behavioral detection in Security Onion:** correlate around the process's execution window —
  - **Sysmon Event ID 1 (Process Create):** unusual parent/child chains and command lines; ingest via Elastic and hunt in Kibana/Security Onion Console.
  - **Sysmon Event ID 7 (Image Load)** and **Event ID 8 (CreateRemoteThread)** / **Event ID 10 (ProcessAccess):** self-unpacking that maps to **T1140 (Deobfuscate/Decode Files or Information)** often precedes memory allocation and, in real malware, injection into a host process — **T1055 (Process Injection)** and its sub-techniques.
  - **Zeek + Suricata:** pivot on `conn.log`/`dns.log`/`http.log` and Suricata alerts for the C2 IOCs (domains, URIs, JA3/TLS fingerprints) recovered from the *unpacked* image.
- **Feeding the hunt loop:** FLOSS output on a dumped image feeds IOC extraction (C2 hosts, mutexes, user-agents) that become Suricata and YARA rules. Note that Microsoft Defender surfaces entropy/packing heuristics as well (Microsoft Learn documents Sysmon and Defender telemetry — see Sources).

## Attacker perspective
Attackers pack payloads to defeat signature scanners, hide C2 strings, and slow analysts (**T1027 / T1027.002**). A packer adds a stub that decompresses (or decrypts) the real code into memory at runtime and jumps to the OEP, leaving only the loader visible on disk.

- **Concrete TTPs:** off-the-shelf packers (UPX), custom crypters, and runtime deobfuscation (**T1140**); when the unpacked payload is written into another process's address space this becomes **T1055 (Process Injection)** — e.g., allocate RWX memory, write the payload, and create a remote thread.
- **Artifacts the technique leaves:** abnormal section names (`UPX0`/`UPX1`), section entropy near 8.0, a `UPX0` section with virtual size >> raw size, a stripped import table rebuilt at runtime, RWX memory regions during/after unpacking, a `pushad`/`popad`-bracketed stub, and a distinctive tail `jmp` to the OEP.
- **Evasion:** adversaries rename UPX sections and corrupt/strip the `UPX!` marker to break `upx -d`, add anti-debug/anti-VM checks before unpacking, use multi-layer or custom packing, or delay decoding — but each countermeasure typically adds *more* anomalous structure or timing that defenders can key on. The evasion technique itself seeds the evidence (high entropy, RWX pages, IAT rebuilding) a defender uses to unmask it.

## Answer key
- **PE-bear:** sections `UPX0` and `UPX1`; packed section entropy roughly 7.5–7.9 (compressed data trends toward the 8.0 bits/byte maximum).
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
- **T1027.002** — Obfuscated Files or Information: Software Packing — https://attack.mitre.org/techniques/T1027/002/
- **T1027** — Obfuscated Files or Information (parent technique) — https://attack.mitre.org/techniques/T1027/
- **T1140** — Deobfuscate/Decode Files or Information (the runtime unpacking stub) — https://attack.mitre.org/techniques/T1140/
- **T1055** — Process Injection (relevant when real malware unpacks into a host process) — https://attack.mitre.org/techniques/T1055/
- **DFIR phase:** Examination / Analysis (malware static+dynamic reverse engineering).

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **FLOSS behavior, `--version`, static + obfuscated/stack/tight string extraction** — Mandiant flare-floss repo — https://github.com/mandiant/flare-floss
- **FLARE-VM ships x64dbg, PE-bear, FLOSS via Chocolatey (paths vary by version)** — https://github.com/mandiant/flare-vm
- **x64dbg is an open-source x64/x32 user-mode debugger; GUI, breakpoints, Scylla plugin for dumping/IAT rebuild** — x64dbg documentation — https://help.x64dbg.com/en/latest/
- **Scylla dump + IAT Autosearch/Get Imports/Fix Dump for import reconstruction** — Scylla project — https://github.com/NtQuery/Scylla
- **PE-bear PE section table, entropy, and import viewing** — PE-bear (hasherezade) — https://github.com/hasherezade/pe-bear
- **UPX packer: `--best` compression level, `UPX0`/`UPX1` sections, self-decompression stub, `upx -d` decompression** — UPX project — https://upx.github.io/ and README — https://github.com/upx/upx
- **Windows compiler `cl.exe` flags (`/Fe`, `/nologo`)** — Microsoft Learn (MSVC command-line reference) — https://learn.microsoft.com/en-us/cpp/build/reference/compiler-command-line-syntax
- **Sysmon Event IDs 1/7/8/10 (Process Create, Image Load, CreateRemoteThread, ProcessAccess) for behavioral detection** — Microsoft Learn (Sysmon) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Security Onion Suricata/Zeek/Elastic pivots** — Security Onion documentation — https://docs.securityonion.net/
- **Zeek logs (conn/dns/http)** — https://docs.zeek.org/en/master/logs/index.html
- **Suricata rules/alerting** — https://docs.suricata.io/
- **MITRE ATT&CK T1027 / T1027.002 / T1140 / T1055** — https://attack.mitre.org/techniques/T1027/ , https://attack.mitre.org/techniques/T1027/002/ , https://attack.mitre.org/techniques/T1140/ , https://attack.mitre.org/techniques/T1055/
- **SANS FOR610 Reverse-Engineering Malware (unpacking workflow context)** — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- shares floss for fast pre-detonation string triage.
- [Static reverse engineering](../12-static-re/README.md) -- shares floss and covers reading unpacked code statically.
- [PE static analysis deep-dive](../30-pe-static-deep/README.md) -- shares floss and expands on PE section/entropy/import analysis.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares x64dbg for memory-based extraction and dumping.

<!-- cyberlab-enriched: v1 -->
