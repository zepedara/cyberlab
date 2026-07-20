# 33 * binwalk firmware & embedded extraction -- LAB-LINUX

## Overview (plain language)
When you download a router update, a smart-camera image, or any "firmware" file, it is usually one big blob that secretly contains many smaller files glued together — a Linux kernel, a compressed filesystem, config data, even hidden logos or certificates. `binwalk` is like an X-ray machine for those blobs: it scans byte by byte, recognizes the tell-tale signatures of known file types (gzip, squashfs, JPEG, ELF, and more), and can automatically pull the pieces apart so you can inspect them. `foremost` does a related job called "file carving": it recovers whole files out of raw data based purely on their headers and footers, which is perfect when there is no filesystem to guide you. Together these tools let a beginner take a mysterious binary and turn it into a folder of understandable, examinable files.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| binwalk | apt install binwalk | Scan firmware/binaries for embedded file signatures, extract and analyze entropy |
| foremost | apt install foremost | Header/footer-based file carving to recover embedded files from raw data |

Notes on provenance and versions:
- `binwalk` is developed by ReFirmLabs; its signature scanning, `-e` extraction, and `-E` entropy features are documented in the project README and wiki. See https://github.com/ReFirmLabs/binwalk and https://github.com/ReFirmLabs/binwalk/wiki/Usage . The v2.x line is a Python tool; a newer v3 rewrite in Rust exists at the same repository. Confirm your local version with `binwalk --help` (see Environment check).
- `foremost` is a header/footer/internal-structure file carver originally written by Jesse Kornblum, Kris Kendall, and Nick Mikus; current stable is 1.5.7. See the Kali Tools page https://www.kali.org/tools/foremost/ and the man page. Configuration for carve types lives in `foremost.conf` (typically `/etc/foremost.conf`).

## Learning objectives
- Use `binwalk` to enumerate embedded file signatures inside a firmware-style blob.
- Automatically extract nested filesystems and archives with `binwalk -e`.
- Interpret an entropy scan to locate compressed or encrypted regions.
- Recover embedded files with `foremost` when no filesystem metadata exists.
- Verify recovered artifacts by hash and file type.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX (SIFT/REMnux/Kali)
binwalk --help | head -n 3
foremost -V
```
Expected output: `binwalk` prints its usage banner including the version (e.g. `Binwalk v2.3.x`); `foremost` prints a version line such as `foremost version 1.5.7 by Jesse Kornblum...`. The exact banner text and version depend on your distribution's packaged build; the `-V`/`--help` behavior is documented in the foremost man page and the binwalk usage wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). If you are on REMnux, both tools are available per the REMnux tool catalog (https://docs.remnux.org/discover-the-tools/).

## Guided walkthrough
1. Build a benign, reproducible sample blob (see Hands-on exercise for exact generator). Nothing here is live malware. We build the sample ourselves so the byte layout is known in advance — that lets you predict exactly what `binwalk` and `foremost` should report, which is how you learn to trust (and sanity-check) the tools.
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise
ls -l firmware.bin
```
Expected: a single file `firmware.bin` a few kilobytes in size.

2. `binwalk firmware.bin` — signature scan. By default binwalk performs a signature scan, walking the file and matching byte patterns against its magic-signature database (libmagic-style rules bundled with the tool), then reporting the offset, description, and type of every recognized structure. Per the binwalk usage docs (https://github.com/ReFirmLabs/binwalk/wiki/Usage), signature scanning is the default mode when no other scan flag is given.
```bash
binwalk firmware.bin
```
Expected output: a table with columns `DECIMAL  HEXADECIMAL  DESCRIPTION` listing entries such as a `gzip compressed data` region and a `JPEG image data` region at their byte offsets. Nuance: because our blob is a raw concatenation, the offsets are meaningful — the gzip entry should appear after the plain-text banner, and the JPEG entry after the gzip stream. A leading ASCII banner may or may not produce a dedicated signature line (binwalk reports recognized structures, not arbitrary text), so don't be alarmed if offset 0 is not called out — the important entries are the gzip and JPEG matches.

3. `binwalk -e firmware.bin` — automatic extraction. The `-e`/`--extract` flag extracts known file types using the tool's extraction rules (external utilities such as `gzip`/`zcat`, `unsquashfs`, etc.), writing results into a sibling directory. This is documented under Extraction in the binwalk wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). Extraction is why binwalk is more than a scanner: it actually invokes decompressors to turn the recognized regions into inspectable files.
```bash
binwalk -e firmware.bin
ls -R _firmware.bin.extracted
```
Expected: a directory `_firmware.bin.extracted/` containing the decompressed/carved sub-files (e.g. a `*.gz` and its expanded contents). Nuance: extraction depends on the matching helper utility being installed; a signature can be recognized in the scan yet not extracted if the external tool is missing. Also note that automatic extraction of untrusted firmware executes third-party extractors on attacker-controlled data — do it only in an isolated lab (which is why this module uses a self-generated benign blob).

4. `binwalk -E firmware.bin` — entropy scan. The `-E`/`--entropy` flag computes Shannon entropy across the file to spot compressed or encrypted regions, which appear as high, flat entropy approaching the theoretical maximum (near 1.0 on binwalk's normalized 0–1 scale). This is documented under Entropy Analysis in the binwalk wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). Entropy is a heuristic: compressed and encrypted data both look high-entropy, so a flat high-entropy tail tells you "this is packed/opaque" but not whether it is merely zipped or genuinely encrypted.
```bash
binwalk -E firmware.bin
```
Expected: a textual entropy report (and, if a display and plotting dependencies are available, a plot) showing rising entropy at the compressed region's offset. In our sample the gzip stream is the high-entropy region; the plain-text banner region is low entropy.

5. `foremost` — carve recognizable files straight out of the blob by header/footer, independent of binwalk. foremost recovers files based on their headers, footers, and internal data structures as defined in its configuration; the `-i` (input) and `-o` (output directory) options and the generated `audit.txt` log are described in the foremost man page and the Kali Tools page (https://www.kali.org/tools/foremost/). This cross-checks binwalk: two independent tools recognizing the same embedded JPEG raises your confidence in the finding.
```bash
foremost -i firmware.bin -o foremost_out
cat foremost_out/audit.txt
```
Expected: `foremost_out/` with subfolders (e.g. `jpg/`) and an `audit.txt` summarizing carved files and their offsets. Nuance: our `tiny.jpg` contains the JPEG SOI header (`ff d8 ff e0` / `JFIF`) and the EOI footer (`ff d9`), which is exactly what foremost's default JPEG rule keys on — a real-world truncated image missing its footer might be carved to a default max size instead.

## Hands-on exercise
Analyze the sample `firmware.bin` in this module's `exercise/` directory.

Sample declaration:
- Type: synthetic firmware-style blob (raw concatenation of a text banner, a gzip stream, and a small JPEG).
- Safe origin: **benign/inert, no-egress** — it is generated locally by the command below from harmless data; it contains NO executable payload and NO live malware.
- Reproducible generator (run inside `exercise/`):
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise
printf 'FIRMWARE_HEADER_v1\n' > banner.txt
echo "benign embedded config data for training" | gzip -c > blob.gz
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > tiny.jpg
cat banner.txt blob.gz tiny.jpg > firmware.bin
rm -f banner.txt blob.gz tiny.jpg
sha256sum firmware.bin
```

Tasks:
1. List every embedded signature and its offset with `binwalk`.
2. Extract the gzip region and read the recovered config text.
3. Carve the JPEG with `foremost` and confirm its type with `file`.

## SOC analyst perspective
A defender in a Security Onion / DFIR workflow reaches for `binwalk` and `foremost` when triaging suspicious binaries, IoT/router firmware, or dropped files pulled from Zeek's file extraction output or Suricata's file store.

Where the files come from (Security Onion pivots):
- Zeek's File Analysis Framework logs file transfers in `files.log` (fields such as `mime_type`, `total_bytes`, `md5`/`sha1`/`sha256` when hashing is enabled) and can write reassembled files to disk via the extraction scripts; see the Zeek `files.log` documentation (https://docs.zeek.org/en/master/logs/files.html) and the File Analysis framework (https://docs.zeek.org/en/master/frameworks/file-analysis.html). Security Onion's file handling and Zeek integration are documented at https://docs.securityonion.net/en/2.4/zeek.html .
- Suricata can extract and store transferred files (`file-store`) and log file metadata in EVE JSON `fileinfo` records; see the Suricata File Extraction docs (https://docs.suricata.io/en/latest/file-extraction/file-extraction.html) and EVE `fileinfo` (https://docs.suricata.io/en/latest/output/eve/eve-json-output.html). Security Onion surfaces these alerts and logs in Elastic; general workflow at https://docs.securityonion.net/ .

Detection logic and hunts:
- Pivot in Elastic on Zeek `files.log`/Suricata `fileinfo` for a declared `mime_type` (e.g. `image/jpeg`) whose `total_bytes` is far larger than a normal image — a hallmark of appended/polyglot data. Then pull the reassembled/stored file and run `binwalk` + `binwalk -E` to confirm extra signatures or a high-entropy tail past the JPEG EOI.
- Embedded, compressed, or appended payloads map to ATT&CK **T1027** (Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/) and its sub-technique **T1027.009** (Embedded Payloads — https://attack.mitre.org/techniques/T1027/009/). The act of unpacking/decoding at runtime maps to **T1140** (Deobfuscate/Decode Files or Information — https://attack.mitre.org/techniques/T1140/).
- After extraction, hash each recovered artifact (`sha256sum`) and scan the inner files with YARA/ClamAV so hunt queries can pivot on recovered inner IOCs. This work sits in the DFIR **Examination** phase (see SANS FOR508, https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).

## Attacker perspective
Attackers abuse embedded/appended data to smuggle payloads past naive inspection: appending an archive to a JPEG (a polyglot), stuffing a backdoored filesystem into a legitimate-looking firmware image, or compressing a stager to raise entropy and defeat string-based rules.

Concrete TTPs and technique IDs:
- **T1027 / T1027.009 (Embedded Payloads)** — hiding a second-stage inside a benign-looking carrier file so the outer file's declared type/size masks the addition. See https://attack.mitre.org/techniques/T1027/009/ .
- **T1140 (Deobfuscate/Decode Files or Information)** — the dropper decompresses or decodes the hidden layer at runtime. See https://attack.mitre.org/techniques/T1140/ .
- **T1608 (Stage Capabilities)** and specifically **T1608.001 (Upload Malware)** — embedding payloads in firmware or media staged for delivery. See https://attack.mitre.org/techniques/T1608/ and https://attack.mitre.org/techniques/T1608/001/ .

Offensive use of the same tools: analysts and attackers alike use `binwalk -e` to unpack a vendor firmware image, then grep the extracted squashfs/rootfs for hardcoded credentials, API keys, or private keys, modify the filesystem, repack it, and reflash.

Artifacts the technique leaves (what a defender finds):
- Anomalous file sizes — bytes present after a valid end-of-file marker (e.g. data after the JPEG `ff d9` EOI).
- Extra file-type signatures at odd offsets in a `binwalk` scan that don't match the file's declared type.
- Unusually high, flat entropy in a tail region on `binwalk -E` (compressed/encrypted appended data).
- Carved secondary files that appear in `foremost`/Zeek output but were never meant to be visible.

Evasion the attacker attempts: encrypting rather than merely compressing the payload (still high entropy, but no recognizable inner signatures), placing the payload where a naive parser stops reading, or splitting it so no single magic byte sequence is contiguous. Entropy and offset anomalies remain the durable tells even when signatures are suppressed.

## Answer key
Sample sha256 (of the file produced by the exact generator above — the validator holds the canonical digest; reproduce locally with `sha256sum firmware.bin`).

Expected findings and the commands that produce them:
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise

# 1. Signatures: banner text at offset 0, gzip stream, then JPEG (magic ff d8 ff e0 / JFIF)
binwalk firmware.bin

# 2. Extract and read the benign config text
binwalk -e firmware.bin
find _firmware.bin.extracted -name '*.gz' -exec zcat {} \;
# -> "benign embedded config data for training"

# 3. Carve and verify the JPEG
foremost -i firmware.bin -o foremost_out
file foremost_out/jpg/*.jpg 2>/dev/null || file foremost_out/*/*
# -> JPEG image data, JFIF standard

# Confirm the sample's integrity
sha256sum firmware.bin
```
Expected: binwalk lists at least a `gzip compressed data` entry and a `JPEG image data` entry; the extracted gzip decompresses to the training string; foremost's `audit.txt` records the carved JPEG. The `file` output identifying a JFIF-standard JPEG relies on libmagic; the JPEG magic bytes (`ff d8 ff`) and JFIF marker are the recognized signature (see the foremost config rules and Kali Tools page, https://www.kali.org/tools/foremost/).

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (appended/compressed embedded payloads): https://attack.mitre.org/techniques/T1027/
- T1027.009 — Embedded Payloads (payload hidden inside a benign carrier file): https://attack.mitre.org/techniques/T1027/009/
- T1140 — Deobfuscate/Decode Files or Information (extracting/decompressing embedded layers): https://attack.mitre.org/techniques/T1140/
- T1608 — Stage Capabilities (attacker embedding payloads in benign-looking files/firmware): https://attack.mitre.org/techniques/T1608/
- T1608.001 — Upload Malware (staging the embedded payload for delivery): https://attack.mitre.org/techniques/T1608/001/
- DFIR phase: **Examination / Analysis** (file triage, extraction, and artifact recovery) — see SANS FOR508: https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

## Sources
Claim → source mapping (all URLs are to official/authoritative pages):

- binwalk default signature scan, `-e`/`--extract` extraction, `-E`/`--entropy` entropy analysis, output columns, and behavior — ReFirmLabs binwalk repo and usage wiki:
  - https://github.com/ReFirmLabs/binwalk
  - https://github.com/ReFirmLabs/binwalk/wiki/Usage
- binwalk install/availability and general description — Kali Tools:
  - https://www.kali.org/tools/binwalk/
- foremost version 1.5.7, `-i`/`-o` options, `audit.txt` output, header/footer/internal-structure carving, config rules — Kali Tools (and the packaged man page):
  - https://www.kali.org/tools/foremost/
- Tool availability on analysis distros — SANS SIFT Workstation and REMnux catalog:
  - https://www.sans.org/tools/sift-workstation/
  - https://docs.remnux.org/discover-the-tools/
- Zeek file extraction / `files.log` fields (mime_type, total_bytes, hashes) and File Analysis Framework — Zeek docs:
  - https://docs.zeek.org/en/master/logs/files.html
  - https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Suricata file extraction (`file-store`) and EVE `fileinfo` metadata — Suricata docs:
  - https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
  - https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Security Onion Zeek integration and general workflow — Security Onion docs:
  - https://docs.securityonion.net/en/2.4/zeek.html
  - https://docs.securityonion.net/
- MITRE ATT&CK techniques — technique pages:
  - T1027: https://attack.mitre.org/techniques/T1027/
  - T1027.009: https://attack.mitre.org/techniques/T1027/009/
  - T1140: https://attack.mitre.org/techniques/T1140/
  - T1608: https://attack.mitre.org/techniques/T1608/
  - T1608.001: https://attack.mitre.org/techniques/T1608/001/
- DFIR examination phase / incident response methodology — SANS FOR508:
  - https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

## Related modules
- [File carving](../05-file-carving/README.md) -- shares foremost for header/footer recovery of embedded files.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); extends artifact recovery into memory.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); scan extracted/carved artifacts with YARA.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); filesystem-aware carving and metadata analysis.

<!-- cyberlab-enriched: v1 -->
