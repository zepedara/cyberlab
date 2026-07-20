# 33 * binwalk firmware & embedded extraction -- LAB-LINUX

## Overview (plain language)
When you download a router update, a smart-camera image, or any "firmware" file, it is usually one big blob that secretly contains many smaller files glued together — a Linux kernel, a compressed filesystem, config data, even hidden logos or certificates. `binwalk` is like an X-ray machine for those blobs: it scans byte by byte, recognizes the tell-tale signatures of known file types (gzip, squashfs, JPEG, ELF, and more), and can automatically pull the pieces apart so you can inspect them. `foremost` does a related job called "file carving": it recovers whole files out of raw data based purely on their headers and footers, which is perfect when there is no filesystem to guide you. Together these tools let a beginner take a mysterious binary and turn it into a folder of understandable, examinable files.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| binwalk | apt install binwalk | Scan firmware/binaries for embedded file signatures, extract and analyze entropy |
| foremost | apt install foremost | Header/footer-based file carving to recover embedded files from raw data |

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
Expected output: `binwalk` prints its usage banner including the version (e.g. `Binwalk v2.3.x`); `foremost` prints a version line such as `foremost version 1.5.7 by Jesse Kornblum...`.

## Guided walkthrough
1. Build a benign, reproducible sample blob (see Hands-on exercise for exact generator). Nothing here is live malware.
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise
ls -l firmware.bin
```
Expected: a single file `firmware.bin` a few kilobytes in size.

2. `binwalk firmware.bin` — signature scan. It walks the file and reports the offset, description, and type of every recognized structure.
```bash
binwalk firmware.bin
```
Expected output: a table with columns `DECIMAL  HEXADECIMAL  DESCRIPTION` listing entries such as a `gzip compressed data` region and a `JPEG image data` region at their byte offsets.

3. `binwalk -e firmware.bin` — automatic extraction of every recognized/extractable region into a sibling directory.
```bash
binwalk -e firmware.bin
ls -R _firmware.bin.extracted
```
Expected: a directory `_firmware.bin.extracted/` containing the decompressed/carved sub-files (e.g. a `*.gz` and its expanded contents).

4. `binwalk -E firmware.bin` — entropy scan to spot compressed/encrypted regions (high, flat entropy near 1.0).
```bash
binwalk -E firmware.bin
```
Expected: a textual entropy report (and, if a display is available, a plot) showing rising entropy at the compressed region's offset.

5. `foremost` — carve recognizable files straight out of the blob by header/footer, independent of binwalk.
```bash
foremost -i firmware.bin -o foremost_out
cat foremost_out/audit.txt
```
Expected: `foremost_out/` with subfolders (e.g. `jpg/`) and an `audit.txt` summarizing carved files and their offsets.

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
A defender in a Security Onion / DFIR workflow reaches for `binwalk` and `foremost` when triaging suspicious binaries, IoT/router firmware, or dropped files pulled from Zeek `extracted/` file-carving output or Suricata `filestore`. Embedded, compressed, or appended payloads are a classic evasion trick — malware hides a second-stage inside a "picture" or pads an installer with a squashfs image. Signature scanning and entropy analysis quickly flag high-entropy blobs (packed/encrypted) that map to ATT&CK T1027 (Obfuscated/Compressed Files) and T1140 (Deobfuscate/Decode). Analysts extract the layers, hash each artifact, run YARA/ClamAV over them, and enrich alerts so hunt queries can pivot on the recovered inner IOCs during the examination phase.

## Attacker perspective
Attackers abuse embedded/appended data to smuggle payloads past naive inspection: appending an archive to a JPEG (polyglot), stuffing a backdoored filesystem into legitimate-looking firmware, or compressing a stager to raise entropy and defeat string-based rules (ATT&CK T1027, T1608 staging). The same tools an analyst uses can be used offensively to reverse a vendor firmware image, locate hardcoded credentials or private keys, and modify a squashfs root before reflashing. The tradecraft leaves artifacts a defender can find: anomalous file sizes, mismatched trailing bytes after a valid EOF marker, unusually high/flat entropy tails, extra file-type signatures at odd offsets, and carved secondary files that were never meant to be visible.

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
Expected: binwalk lists at least a `gzip compressed data` entry and a `JPEG image data` entry; the extracted gzip decompresses to the training string; foremost's `audit.txt` records the carved JPEG.

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (appended/compressed embedded payloads).
- T1140 — Deobfuscate/Decode Files or Information (extracting/decompressing embedded layers).
- T1608 — Stage Capabilities (attacker embedding payloads in benign-looking files/firmware).
- DFIR phase: **Examination / Analysis** (file triage, extraction, and artifact recovery).

## Sources
- Kali Tools — binwalk: https://www.kali.org/tools/binwalk/
- Kali Tools — foremost: https://www.kali.org/tools/foremost/
- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- REMnux documentation (static/file analysis tools): https://docs.remnux.org/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1140: https://attack.mitre.org/techniques/T1140/