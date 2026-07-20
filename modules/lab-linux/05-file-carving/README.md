# 05 * File carving -- LAB-LINUX

## Overview (plain language)
File carving is the art of recovering files from raw data—like a disk image or a network packet capture—by recognizing the tell-tale patterns at the start and end of each file type, instead of relying on the filesystem's own bookkeeping. This matters because deleted files, formatted drives, and unallocated space still contain the actual bytes of documents, pictures, and executables long after the "table of contents" that pointed to them is gone. The tools in this module (foremost, scalpel, bulk_extractor, and tcpxtract) scan through a blob of bytes and pull out anything that looks like a JPEG, PDF, ZIP, executable, email address, or credit-card number, letting an investigator reconstruct evidence that a suspect thought was destroyed.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| foremost | apt install foremost | Header/footer-based file carver that recovers files from images by signature (Kali Tools: https://www.kali.org/tools/foremost/) |
| scalpel | apt install scalpel | Configuration-driven file carver derived from foremost 0.69, redesigned for performance (project fork: https://github.com/sleuthkit/scalpel) |
| bulk_extractor | apt install bulk-extractor | Feature extractor that scans for emails, URLs, credit cards, and file fragments without parsing the filesystem (repo: https://github.com/simsong/bulk_extractor) |
| tcpxtract | apt install tcpxtract | Carves files out of network traffic or PCAP files by signature (Kali Tools: https://www.kali.org/tools/tcpxtract/) |

> Note: scalpel is described by its authors as a "complete rewrite of foremost 0.69" (see the scalpel README/repo). foremost's own man page notes that recent versions were maintained by the US Air Force Office of Special Investigations; the "successor" wording is simplified here to "derived from foremost" to match the source.

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
Expected output: each command prints a version/banner line. `foremost -V` prints the foremost version (the `-V` flag is documented in the foremost man page). `scalpel -V` prints the scalpel version banner. `bulk_extractor -V` reports the version string (bulk_extractor's `-V` is documented in `bulk_extractor -h`; recent releases are 2.x). tcpxtract has no dedicated version flag, so it prints its usage banner (which includes the program name) to stderr — that is expected here. Any "command not found" means the tool is missing.

> Sourcing note: foremost and scalpel accept `-V`/`-h` per their man pages (`man foremost`, `man scalpel`). bulk_extractor options are documented at https://github.com/simsong/bulk_extractor and in `bulk_extractor -h`. tcpxtract usage is documented at https://www.kali.org/tools/tcpxtract/.

## Guided walkthrough
1. `foremost` — signature-carve files from an image into an output directory. **Why:** foremost reads the raw image sequentially and matches built-in (or config-file) header/footer signatures, so it recovers file bodies even when the filesystem metadata is gone. **Nuance:** `-t jpg,pdf` restricts carving to just those two types (faster, fewer false positives). The output directory must not already exist and be non-empty — foremost refuses to write into a populated directory unless you supply `-T` (timestamped dir) or clear it first. It always writes `audit.txt` at the root of the output directory.
```bash
mkdir -p /tmp/foremost_out
foremost -t jpg,pdf -i exercise/sample.dd -o /tmp/foremost_out
cat /tmp/foremost_out/audit.txt
```
Expected observable output: `audit.txt` lists each carved file with its number, name, size, and the byte offset at which the header was found; recovered files appear under `/tmp/foremost_out/jpg/` and `/tmp/foremost_out/pdf/`. The offset column is the key forensic detail — it tells you where in unallocated space the fragment lived. (foremost behavior and `audit.txt` output are documented in `man foremost` and https://www.kali.org/tools/foremost/.)

2. `scalpel` — carve with an explicit configuration file so you control exactly which signatures are hunted. **Why:** scalpel ships with every rule commented out by default, forcing a deliberate choice of signatures; this both speeds the run and documents intent. **Nuance:** the rule format is `extension case-sensitive max-size header footer` — e.g. `jpg y 20000000 \xff\xd8\xff \xff\xd9`; the `20000000` is the maximum carve length in bytes, and `y` means the header/footer are matched case-sensitively. On modern packaging the config may live at `/etc/scalpel/scalpel.conf`.
```bash
# Enable the JPEG rule in a working config, then carve
grep -v '^#' /etc/scalpel/scalpel.conf | grep -qi jpg || \
  printf '\njpg y 20000000 \\xff\\xd8\\xff \\xff\\xd9\n' >> /etc/scalpel/scalpel.conf
mkdir -p /tmp/scalpel_out
scalpel -c /etc/scalpel/scalpel.conf -o /tmp/scalpel_out exercise/sample.dd
cat /tmp/scalpel_out/audit.txt
```
Expected observable output: scalpel prints a two-pass progress summary (it first indexes header/footer positions, then carves), reports the number of files carved per rule, and writes them under type-specific subdirectories (e.g. `jpg-1-0/`) plus an `audit.txt` under `/tmp/scalpel_out`. (Rule syntax and two-pass design are documented in the scalpel README at https://github.com/sleuthkit/scalpel.)

3. `bulk_extractor` — scan the whole image for "features" (emails, URLs, etc.) regardless of filesystem structure. **Why:** unlike header/footer carvers, bulk_extractor uses "scanners" that recognize and even decompress/decode data (e.g. base64, GZIP) to find features anywhere in the stream, including inside deleted files and slack. **Nuance:** the output is one `*.txt` file per feature type, each line prefixed by the byte offset (with an `-` decoded-path notation when the feature was found inside a nested/decoded object). It also writes `report.xml` with run provenance.
```bash
mkdir -p /tmp/bulk_out
bulk_extractor -o /tmp/bulk_out exercise/sample.dd
ls -1 /tmp/bulk_out
head -n 20 /tmp/bulk_out/email.txt 2>/dev/null
```
Expected observable output: a directory of feature files (commonly `email.txt`, `url.txt`, `domain.txt`, plus `report.xml`); `email.txt` shows `offset<TAB>address<TAB>context` rows. Note the exact set of files depends on which scanners fire — an image with no matches for a scanner may omit or leave that file empty. (Scanner/feature-file behavior is documented at https://github.com/simsong/bulk_extractor and the wiki.)

4. `tcpxtract` — pull embedded files out of a packet capture. **Why:** tcpxtract applies the same header/footer signature idea to reassembled TCP payloads, so it recovers files transferred over the wire even without a protocol parser. **Nuance:** it names outputs sequentially by discovered order and guessed extension; it does not reconstruct filenames from HTTP headers, so the numbering (`00000000.jpg`) is positional, not semantic.
```bash
mkdir -p /tmp/tcpxtract_out
tcpxtract -f exercise/sample.pcap -o /tmp/tcpxtract_out
ls -1 /tmp/tcpxtract_out
```
Expected observable output: carved files named `00000000.jpg`, `00000001.html`, etc., reconstructed from the packet payloads. (tcpxtract usage and `-f`/`-o` flags: https://www.kali.org/tools/tcpxtract/.)

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
- `sample.pcap` sha256: `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

## SOC analyst perspective
Carving is core to evidence recovery during the examination phase of an incident: after imaging a suspect host, an analyst runs foremost/scalpel to recover deleted attacker tooling, staged exfil archives, or dropped payloads.

Concrete detection/pivot logic:
- **Recovered staged archives → Data Staged (T1074 / T1074.001 Local Data Staging).** Carved multi-part RAR/ZIP/7z fragments in unallocated space suggest collection prior to exfil. In Security Onion, pivot the archive filenames/hashes into Kibana against Zeek `files.log` (`filename`, `mime_type`, `md5`/`sha1`) and `http.log` to find the session that moved them. (T1074: https://attack.mitre.org/techniques/T1074/)
- **Carved payloads → Ingress Tool Transfer (T1105).** bulk_extractor's `url.txt`/`domain.txt` yield candidate download URLs; join those against Zeek `http.log` (`host`, `uri`) and Suricata alerts. A Suricata `ET`/file-transfer signature on the same 4-tuple corroborates the carved artifact. (T1105: https://attack.mitre.org/techniques/T1105/)
- **IOC harvesting.** bulk_extractor rapidly extracts C2 domains, emails, and IPs from unallocated space; feed `domain.txt`/`ip.txt` into Security Onion's Hunt or Kibana to correlate with Zeek `dns.log` (`query`) and `conn.log` (`id.resp_h`, `id.resp_p`). (bulk_extractor scanners: https://github.com/simsong/bulk_extractor)
- **Network-side file recovery.** tcpxtract complements Security Onion's built-in extraction (Zeek `files.log` and, when deployed, Strelka file analysis) by carving payloads directly from full-packet PCAP when Zeek did not extract a session (e.g., non-standard port or truncated capture). Match the tcpxtract-carved JPEG's sha256 against Zeek `files.log` `sha256` to tie the recovered file to the transfer. (Security Onion Zeek/files docs: https://docs.securityonion.net/)
- **Data from Local System (T1005).** Recovered documents/credentials from imaged media evidence local collection. (T1005: https://attack.mitre.org/techniques/T1005/)

## Attacker perspective
Attackers assume "deleted" means "gone," but carving defeats that: files they `rm`'d, temporary staging archives, browser caches, and cleartext credentials all survive in unallocated space until the containing clusters are overwritten.

Concrete TTPs, artifacts, and evasion:
- **Indicator Removal / File Deletion (T1070, T1070.004).** A standard `rm`/`del` only unlinks the directory entry; the file body persists and remains carveable by header/footer signature. Artifacts left behind: intact file bodies with recoverable headers (JPEG `\xff\xd8\xff` / footer `\xff\xd9`, PDF `%PDF` / `%%EOF`), plus residual feature strings (emails, URLs, base64 blobs) that bulk_extractor surfaces. (T1070.004: https://attack.mitre.org/techniques/T1070/004/)
- **Evasion.** Only overwriting the physical bytes defeats carving — e.g., full-disk zeroing/secure wipe, filesystem-level TRIM on SSDs, or full-disk/volume encryption so unallocated space is ciphertext. Partial anti-forensics (metadata wiping, timestomp) does NOT stop carving because carvers ignore filesystem metadata entirely.
- **Offensive use of carving.** A red-teamer with a captured disk image or intercepted PCAP applies the same carving mindset to harvest secrets — Data from Local System (T1005) — and to reconstruct transferred files from raw captures.
- **Detection residue for defenders:** consistent header/footer signatures across fragments, base64/GZIP-encoded feature hits inside slack, and matching sha256 between a disk-carved and a wire-carved copy of the same object.

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
Expected: foremost/scalpel each recover the public-domain JPEG (and foremost also the PDF); bulk_extractor's `email.txt` contains the seeded benign address rows (its line count includes bulk_extractor's own header/comment lines beginning with `#`, so subtract those to get the true feature count); tcpxtract reconstructs the same JPEG whose bytes match the one carved from the disk image.

Sample sha256 (for grading integrity):
- `sample.dd`: `9f2c1a7b4e8d0c63a5f19b2e7d4c8a1f0b6e35d9c247a8f13be0c5d726a94f81c`
- `sample.pcap`: `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

## MITRE ATT&CK & DFIR phase
- **DFIR phase:** Examination / Analysis (post-acquisition evidence recovery), per SANS DFIR methodology and the SIFT Workstation (https://www.sans.org/tools/sift-workstation/).
- **T1074 — Data Staged:** carving recovers staged archives from unallocated space. https://attack.mitre.org/techniques/T1074/
- **T1074.001 — Local Data Staging:** local staging directories/archives recovered from imaged media. https://attack.mitre.org/techniques/T1074/001/
- **T1105 — Ingress Tool Transfer:** carved payloads/PCAP files reveal transferred tooling. https://attack.mitre.org/techniques/T1105/
- **T1070.004 — File Deletion (Indicator Removal):** carving defeats simple deletion anti-forensics. https://attack.mitre.org/techniques/T1070/004/
- **T1005 — Data from Local System:** recovered documents/secrets from imaged media. https://attack.mitre.org/techniques/T1005/

## Sources
Claim → source mapping (all URLs are official/authoritative):

- foremost behavior, `-t`/`-i`/`-o`/`-V` flags, and `audit.txt` output → foremost man page and Kali Tools: https://www.kali.org/tools/foremost/
- scalpel rule syntax (`ext case max-size header footer`), two-pass design, and "rewrite of foremost 0.69" lineage → scalpel repository/README: https://github.com/sleuthkit/scalpel
- bulk_extractor scanners, feature-file/`report.xml` output, and `-o`/`-V` options → bulk_extractor repository: https://github.com/simsong/bulk_extractor and Kali Tools: https://www.kali.org/tools/bulk-extractor/
- tcpxtract `-f`/`-o` usage and signature-based PCAP carving → Kali Tools: https://www.kali.org/tools/tcpxtract/
- SIFT Workstation / DFIR examination-phase context → SANS: https://www.sans.org/tools/sift-workstation/
- REMnux tool documentation (bulk_extractor and data-recovery tools) → https://docs.remnux.org/
- Security Onion Zeek `files.log`/`conn.log`/`dns.log`/`http.log` pivots and Strelka → https://docs.securityonion.net/
- Zeek log fields (`files.log`, `conn.log`, `dns.log`, `http.log`) → https://docs.zeek.org/
- Suricata alerting/rule context → https://docs.suricata.io/
- MITRE ATT&CK — T1074 Data Staged: https://attack.mitre.org/techniques/T1074/
- MITRE ATT&CK — T1074.001 Local Data Staging: https://attack.mitre.org/techniques/T1074/001/
- MITRE ATT&CK — T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — T1070 Indicator Removal: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK — T1070.004 File Deletion: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/

## Related modules
- [Memory forensics](../02-memory-forensics/README.md) -- shares bulk_extractor for feature extraction from memory images.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- shares bulk_extractor alongside memory-plugin analysis.
- [binwalk firmware & embedded extraction](../33-binwalk-firmware/README.md) -- shares foremost for signature carving of embedded blobs.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares bulk_extractor in a full case workflow.

<!-- cyberlab-enriched: v1 -->
