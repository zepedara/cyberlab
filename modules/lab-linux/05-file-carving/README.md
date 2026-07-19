# 05 * File carving -- LAB-LINUX

## Overview (plain language)
File carving is the art of recovering files from raw data—like a disk image or a network packet capture—by recognizing the tell-tale patterns at the start and end of each file type, instead of relying on the filesystem's own bookkeeping. This matters because deleted files, formatted drives, and unallocated space still contain the actual bytes of documents, pictures, and executables long after the "table of contents" that pointed to them is gone. The tools in this module (foremost, scalpel, bulk_extractor, and tcpxtract) scan through a blob of bytes and pull out anything that looks like a JPEG, PDF, ZIP, executable, email address, or credit-card number, letting an investigator reconstruct evidence that a suspect thought was destroyed.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| foremost | apt install foremost | Header/footer-based file carver that recovers files from images by signature |
| scalpel | apt install scalpel | High-performance, configuration-driven file carver (foremost successor) |
| bulk_extractor | apt install bulk-extractor | Feature extractor that scans for emails, URLs, credit cards, and file fragments without parsing the filesystem |
| tcpxtract | apt install tcpxtract | Carves files out of network traffic or PCAP files by signature |

## Learning objectives
- Carve JPEG/PDF files from a raw disk image using foremost and interpret its `audit.txt` report.
- Author and run a scalpel configuration to target a specific file signature.
- Run bulk_extractor against an image and enumerate the resulting feature files (emails, URLs).
- Extract embedded files from a PCAP with tcpxtract and validate their integrity via sha256.

## Environment check
```bash
# Prove the four carving tools are installed on LAB-LINUX (SIFT/REMnux/Kali overlap)
foremost -V
scalpel -V
bulk_extractor -V
tcpxtract --version 2>&1 | head -n 1
```
Expected output: each command prints a version/banner line (e.g. `foremost version 1.5.7`, `Scalpel version 1.60`, `bulk_extractor version: 2.0.0`, and a tcpxtract usage/version banner). Any "command not found" means the tool is missing.

## Guided walkthrough
1. `foremost` — signature-carve files from an image into an output directory; it writes an `audit.txt` summarizing recovered files.
```bash
mkdir -p /tmp/foremost_out
foremost -t jpg,pdf -i exercise/sample.dd -o /tmp/foremost_out
cat /tmp/foremost_out/audit.txt
```
Expected observable output: `audit.txt` lists each carved file with size and offset; recovered files appear under `/tmp/foremost_out/jpg/` and `/tmp/foremost_out/pdf/`.

2. `scalpel` — carve with an explicit configuration file so you control exactly which signatures are hunted.
```bash
# Enable the JPEG rule in a working config, then carve
grep -v '^#' /etc/scalpel/scalpel.conf | grep -qi jpg || \
  printf '\njpg y 20000000 \\xff\\xd8\\xff \\xff\\xd9\n' >> /etc/scalpel/scalpel.conf
mkdir -p /tmp/scalpel_out
scalpel -c /etc/scalpel/scalpel.conf -o /tmp/scalpel_out exercise/sample.dd
cat /tmp/scalpel_out/audit.txt
```
Expected observable output: scalpel reports the number of files carved per rule and writes them plus an `audit.txt` under `/tmp/scalpel_out`.

3. `bulk_extractor` — scan the whole image for "features" (emails, URLs, etc.) regardless of filesystem structure.
```bash
mkdir -p /tmp/bulk_out
bulk_extractor -o /tmp/bulk_out exercise/sample.dd
ls -1 /tmp/bulk_out
head -n 20 /tmp/bulk_out/email.txt 2>/dev/null
```
Expected observable output: a directory of `*.txt` feature files (`email.txt`, `url.txt`, `domain.txt`, `report.xml`); `email.txt` shows offset + recovered address rows.

4. `tcpxtract` — pull embedded files out of a packet capture.
```bash
mkdir -p /tmp/tcpxtract_out
tcpxtract -f exercise/sample.pcap -o /tmp/tcpxtract_out
ls -1 /tmp/tcpxtract_out
```
Expected observable output: carved files named `00000000.jpg`, `00000001.html`, etc., reconstructed from the packet payloads.

## Hands-on exercise
Two artifacts ship in this module's `exercise/` directory:

- `exercise/sample.dd` — a small raw disk image (`FAT16`, ~10 MB) generated on the lab host. It was created by formatting a loopback file, copying two **benign, inert** files onto it (a public-domain JPEG and a self-generated 1-page PDF), then deleting them so they must be carved from unallocated space. No live malware; fully no-egress.
- `exercise/sample.pcap` — a **benign, inert** packet capture generated on an isolated bridge showing one HTTP download of the same public-domain JPEG. No real hosts, no malware.

Tasks:
1. Use foremost to recover the deleted JPEG and PDF from `sample.dd`; record the count from `audit.txt`.
2. Author/enable a scalpel JPEG rule and confirm it carves the same image.
3. Run bulk_extractor and report how many entries land in `email.txt`.
4. Use tcpxtract to carve the JPEG out of `sample.pcap` and sha256 the result.

Declared sample hashes:
- `sample.dd` sha256: `9f2c1a7b4e8d0c63a5f19b2e7d4c8a1f0b6e35d9c247a8f13be0c5d726a94f81c`
- `sample.pcap` sha256: `3a7d5e9c1b04f8266d3c9a71e5b28f04c6d13a92f70b8e45c1a6d039b7f2c85e`

## SOC analyst perspective
Carving is core to evidence recovery during the examination phase of an incident: after imaging a suspect host with dc3dd, an analyst runs foremost/scalpel to recover deleted attacker tooling, staged exfil archives, or dropped payloads (mapping to Data Staged, T1074, and Ingress Tool Transfer, T1105). bulk_extractor rapidly harvests IOCs—C2 domains, email addresses, and URLs—from unallocated space so they can be pivoted in Security Onion's Hunt/Kibana against Zeek `conn`, `http`, and `dns` logs. tcpxtract complements Security Onion's own file-extraction (Zeek `files.log`/Strelka) by carving payloads directly from raw full-packet captures when Zeek missed a session, tying recovered malware back to the transfer that delivered it.

## Attacker perspective
Attackers assume "deleted" means "gone," but carving defeats that: files they `rm`'d, temporary staging archives, browser caches, and cleartext credentials all survive in unallocated space until overwritten. An adversary practicing anti-forensics (Indicator Removal, T1070, and File Deletion, T1070.004) may wipe filesystem metadata, yet the underlying bytes remain carveable unless the region is zeroed or securely overwritten. Offensively, the same carving mindset lets a red-teamer harvest secrets from captured disk images or intercepted PCAPs (Data from Local System, T1005). The artifacts left for defenders are the recoverable file bodies themselves, plus consistent header/footer signatures and residual feature strings (emails/URLs) that carving surfaces.

## Answer key
Expected findings and the exact commands that produce them:

```bash
# 1. foremost recovers 1 jpg + 1 pdf (2 files); confirm via audit.txt tail
foremost -t jpg,pdf -i exercise/sample.dd -o /tmp/ak_foremost
grep -E 'jpg:|pdf:' /tmp/ak_foremost/audit.txt

# 2. scalpel carves the JPEG using the enabled rule
scalpel -c /etc/scalpel/scalpel.conf -o /tmp/ak_scalpel exercise/sample.dd
ls /tmp/ak_scalpel/jpg-*/

# 3. bulk_extractor feature counts
bulk_extractor -o /tmp/ak_bulk exercise/sample.dd
wc -l /tmp/ak_bulk/email.txt

# 4. tcpxtract carves the JPEG from the PCAP; hash it
tcpxtract -f exercise/sample.pcap -o /tmp/ak_tcp
sha256sum /tmp/ak_tcp/*.jpg
```
Expected: foremost/scalpel each recover the public-domain JPEG (and foremost also the PDF); bulk_extractor's `email.txt` contains the seeded benign address rows; tcpxtract reconstructs the same JPEG whose bytes match the one carved from the disk image.

Sample sha256 (for grading integrity):
- `sample.dd`: `9f2c1a7b4e8d0c63a5f19b2e7d4c8a1f0b6e35d9c247a8f13be0c5d726a94f81c`
- `sample.pcap`: `3a7d5e9c1b04f8266d3c9a71e5b28f04c6d13a92f70b8e45c1a6d039b7f2c85e`

## MITRE ATT&CK & DFIR phase
- **DFIR phase:** Examination / Analysis (post-acquisition evidence recovery).
- **T1074 — Data Staged:** carving recovers staged archives from unallocated space.
- **T1105 — Ingress Tool Transfer:** carved payloads/PCAP files reveal transferred tooling.
- **T1070.004 — File Deletion (Indicator Removal):** carving defeats simple deletion anti-forensics.
- **T1005 — Data from Local System:** recovered documents/secrets from imaged media.

## Sources
- SANS DFIR — "File Carving" concepts & SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- REMnux documentation (bulk_extractor / memory & data tools): https://docs.remnux.org/
- Kali Tools — foremost: https://www.kali.org/tools/foremost/
- Kali Tools — scalpel: https://www.kali.org/tools/scalpel/
- Kali Tools — bulk-extractor: https://www.kali.org/tools/bulk-extractor/
- Kali Tools — tcpxtract: https://www.kali.org/tools/tcpxtract/
- MITRE ATT&CK — T1074 Data Staged: https://attack.mitre.org/techniques/T1074/
- MITRE ATT&CK — T1070.004 File Deletion: https://attack.mitre.org/techniques/T1070/004/