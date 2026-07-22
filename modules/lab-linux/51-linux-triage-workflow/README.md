# 51 * Scenario: end-to-end host triage -- LAB-LINUX

## Overview (plain language)
Imagine you get handed a copy of a suspicious computer's hard drive and you need to quickly figure out what happened without changing anything. This module walks through that "first look" — called triage — using three free tools. The Sleuth Kit lets you browse the files inside a disk image the way you'd look through drawers, including files that were deleted. `bulk_extractor` scans the whole image and pulls out interesting text like email addresses, URLs, and credit-card-shaped numbers, even from unallocated space. ClamAV is an antivirus scanner that flags known-bad files. Together they give you a fast, repeatable way to answer "is this host compromised, and what did the attacker touch?" before you commit to a deep investigation.

The triage process is **non-destructive** and **forensically sound**: no writes are made to the evidence image, and every command produces verifiable output that can be documented in a SOC ticket or chain-of-custody record. This aligns with the **identification** and **examination** phases of the DFIR process (SANS FOR508).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Sleuth Kit | apt install sleuthkit | Command-line disk/filesystem forensics: list files, recover deleted entries, build timelines from an image |
| bulk_extractor | apt install bulk-extractor | Bulk feature carving (emails, URLs, IPs, PII) from raw images including slack/unallocated space |
| ClamAV | apt install clamav clamav-daemon | Open-source antivirus signature scanning of mounted/extracted files |

> **Package/binary naming and versioning:**
> - The Sleuth Kit (TSK) ships the `mmls`, `fsstat`, `fls`, and `icat` binaries. The current stable release is **4.12.1** (as of TSK GitHub repo: [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit/releases)). Version banners are printed with `-V` (e.g., `The Sleuth Kit ver 4.12.1`); see the per-tool man pages at [sleuthkit.org/man](https://www.sleuthkit.org/sleuthkit/man/).
> - `bulk_extractor` is packaged as `bulk-extractor` in Debian/Kali, with the binary named `bulk_extractor`. The current major release is **2.0.0**, documented in the [project repo](https://github.com/simsong/bulk_extractor) and [Kali tools page](https://www.kali.org/tools/bulk-extractor/).
> - ClamAV provides `clamscan` (on-demand scanner), `clamd`/`clamdscan` (daemon), and `freshclam` (signature updater). The engine version (e.g., `ClamAV 1.0.0`) and signature database version (e.g., `main.cvd`, `daily.cvd`) are printed with `clamscan --version`. See [ClamAV Scanning Docs](https://docs.clamav.net/manual/Usage/Scanning.html) and [Signature Management](https://docs.clamav.net/manual/Usage/SignatureManagement.html).

## Learning objectives
- Enumerate partitions and filesystem metadata from a raw disk image with `mmls` and `fsstat`, including sector offsets and filesystem type identification.
- Recover file listings (including deleted inodes) using `fls` and extract file content with `icat`, even when directory entries are unlinked.
- Carve investigative features (emails, URLs, IPs, PII) from an image with `bulk_extractor`, including unallocated space and file slack.
- Signature-scan extracted content with `clamscan` and interpret hit/clean results, including signature names and database versions.
- Produce a documented, reproducible triage sequence suitable for a SOC handoff ticket, including hashes and timestamps for chain-of-custody.

## Environment check
```bash
# Prove the three tools are installed on LAB-LINUX
fls -V
bulk_extractor -V
clamscan --version
```
**Expected output:**
- The Sleuth Kit prints a version banner (e.g., `The Sleuth Kit ver 4.12.1`).
- `bulk_extractor` prints its version (e.g., `bulk_extractor 2.0.0`).
- `clamscan` prints `ClamAV 1.x.x/...` including its virus database version (e.g., `main.cvd ver. 62`).

> **Notes on version strings:**
> - TSK tools accept `-V` to print the version banner; see the [per-tool man pages](https://www.sleuthkit.org/sleuthkit/man/).
> - `bulk_extractor 2.x` is the current major release line, documented in the [project repo](https://github.com/simsong/bulk_extractor).
> - ClamAV `clamscan --version` prints the engine version and the loaded signature database version. A first run may report the database as out of date until `freshclam` runs (see [ClamAV Signature Management](https://docs.clamav.net/manual/Usage/SignatureManagement.html)).

## Guided walkthrough
1. **`mmls` — Display the partition/volume layout**
   Identify the starting sector offset for each filesystem to avoid silent failures in later tools. `mmls` lists all partitions, unallocated gaps, and metadata rows (e.g., GPT primary/backup headers).
   ```bash
   mmls disk.raw
   ```
   **Expected observable:** A table of slots with `Start`/`End` sector offsets, lengths, and descriptions (e.g., a partition starting at sector 2048). Unallocated gaps between partitions can hide hidden or wiped volumes (e.g., attacker-staged data in slack space). See [mmls man page](https://www.sleuthkit.org/sleuthkit/man/mmls.html).

2. **`fsstat` — Read filesystem-level metadata**
   Confirm the filesystem type (e.g., FAT, NTFS, ext4) and sector/cluster size before listing files. This ensures correct interpretation of inode/cluster numbers and manual carving.
   ```bash
   fsstat -o 2048 disk.raw
   ```
   **Expected observable:** Filesystem type, volume label/serial, block/cluster size, and metadata structures (e.g., FAT root directory or NTFS `$MFT` details). `-o` is the volume offset in sectors. See [fsstat man page](https://www.sleuthkit.org/sleuthkit/man/fsstat.html).

3. **`fls` — List files and directories (including deleted entries)**
   The core triage listing: `-r` recurses, `-p` prints full paths (grep-able), and deleted entries are flagged with a leading `*`. Deleted directory entries whose metadata still resides in the filesystem are recoverable until overwritten.
   ```bash
   fls -o 2048 -r -p disk.raw
   ```
   **Expected observable:** A recursive path listing where each line shows:
   - Entry type (e.g., `r/r` = regular file, `d/d` = directory).
   - Metadata/inode address (e.g., `12345`).
   - Name (deleted entries appear with a leading `*` and may show `(realloc)` if metadata is reused).
   See [fls man page](https://www.sleuthkit.org/sleuthkit/man/fls.html). Add `-m /` to emit body-file format for `mactime` (see [TSK Timeline Workflow](https://wiki.sleuthkit.org/index.php?title=FLS)).

4. **`icat` — Extract file content by metadata address**
   Recover content even when the directory entry is gone, as long as the data blocks are still allocated to the metadata entry. `icat` reads by metadata address (not path).
   ```bash
   icat -o 2048 disk.raw 5 > recovered_file.bin
   ```
   **Expected observable:** The file's raw bytes are written to `recovered_file.bin`. The number `5` is the metadata/inode address from `fls`. See [icat man page](https://www.sleuthkit.org/sleuthkit/man/icat.html).

5. **`bulk_extractor` — Carve features from the whole image**
   Scans every byte (allocated files, slack, unallocated space) in parallel using pluggable scanners. Surfaces indicators that filesystem-aware tools miss (e.g., URLs in unallocated space).
   ```bash
   bulk_extractor -o be_out disk.raw
   ```
   **Expected observable:** A `be_out/` directory containing:
   - Per-feature files (e.g., `email.txt`, `url.txt`, `ip.txt`).
   - `report.xml` (run summary) and `*_histogram.txt` (ranked frequent values).
   See [bulk_extractor Usage](https://github.com/simsong/bulk_extractor) and [Feature File Docs](https://github.com/simsong/bulk_extractor/wiki).

6. **`clamscan` — Scan recovered files for known malware**
   `-r` recurses directories, `--infected` limits output to detections, and `--stdout` sends results to stdout for ticket capture.
   ```bash
   clamscan -r --infected --stdout be_out recovered_file.bin
   ```
   **Expected observable:** Per-file `FOUND` lines (e.g., `file.bin: Win.Test.EICAR_HDB-1 FOUND`) and a summary block (e.g., `Infected files: 1`). Clean files are suppressed with `--infected`. See [ClamAV Scanning Docs](https://docs.clamav.net/manual/Usage/Scanning.html).

## Hands-on exercise
The sample lives in this module's `exercise/` directory as `triage_sample.raw`.

- **Type:** A small raw FAT filesystem image (benign, inert — contains only harmless text files plus one file carrying the EICAR antivirus test string).
- **Safe origin / no-egress:** Generated locally with the deterministic generator below; no network access, no live malware. The EICAR string is the industry-standard, harmless AV test signature.
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

> **Why these values are safe:**
> - `203.0.113.0/24` and `example.com` are reserved documentation ranges (RFC 5737 and RFC 2606, respectively), so carved "indicators" cannot resolve to or contact real hosts.
> - The EICAR test file is a defined, harmless detection test string published at [eicar.org](https://www.eicar.org/download-anti-malware-testfile/).

**Tasks:**
1. List all files in the image with `fls`.
2. Carve the embedded email address and URL with `bulk_extractor`.
3. Extract `eicar.com` and confirm ClamAV flags it.

## SOC analyst perspective
During an incident, the SOC receives a disk image and must triage fast before escalating. The Sleuth Kit provides an **auditable, mount-free file listing and timeline** that answers:
- What files exist (including deleted)?
- When were they touched?
- What was staged or exfiltrated?

**Detection Logic and Pivots:**
1. **Carved Network Indicators → Security Onion Correlation**
   - Feed URLs/IPs from `be_out/url.txt` and `be_out/ip.txt` into Security Onion.
   - **Zeek `conn.log`:** Pivot on `id.resp_h` (destination IP) and `service` (e.g., `http`, `dns`). Example query:
     ```
     event.dataset: "zeek.conn" AND destination.ip: "203.0.113.10"
     ```
   - **Zeek `http.log`:** Pivot on `host` (HTTP Host header) and `uri` (request path). Example query:
     ```
     event.dataset: "zeek.http" AND url.path: "/payload"
     ```
   - **Suricata Alerts:** Check for alerts on the same indicators (e.g., `ET INFO Observed Malicious C2 Traffic`).
   - **MITRE ATT&CK:** Correlates to **T1071.001 Application Layer Protocol: Web Protocols** (C2) and **T1041 Exfiltration Over C2 Channel** (data exfiltration). See [T1071.001](https://attack.mitre.org/techniques/T1071/001/) and [T1041](https://attack.mitre.org/techniques/T1041/).

2. **ClamAV Signature Hits**
   - A `FOUND` result on a recovered file corroborates:
     - **T1105 Ingress Tool Transfer** (dropped payload).
     - **T1204 User Execution** (if the file was launched).
     - **T1486 Data Encrypted for Impact** (if the file is ransomware).
   - Record the exact signature name (e.g., `Win.Test.EICAR_HDB-1`) for the ticket. See [ClamAV Signatures](https://docs.clamav.net/manual/Signatures.html).

3. **Deleted File Recovery**
   - `*`-marked `fls` entries indicate **T1070.004 Indicator Removal: File Deletion**.
   - Recover content with `icat` to identify:
     - **T1055 Process Injection** (e.g., injected DLLs in deleted files).
     - **T1059.004 Command and Scripting Interpreter: Unix Shell** (e.g., deleted bash scripts).
   - See [T1070.004](https://attack.mitre.org/techniques/T1070/004/) and [T1055](https://attack.mitre.org/techniques/T1055/).

4. **Timeline Analysis with `mactime`**
   - Build a timeline to detect **T1053 Scheduled Task/Job** (e.g., `cron` jobs) or **T1547 Boot or Logon Autostart Execution** (e.g., `.bashrc` modifications).
   - Commands:
     ```bash
     fls -o 2048 -r -m / disk.raw > bodyfile
     mactime -b bodyfile -d > timeline.csv
     ```
   - Hunt for clusters of file creation/modification (e.g., tool staging). See [TSK Timeline Workflow](https://wiki.sleuthkit.org/index.php?title=Mactime).

**Threat Hunting Pivots:**
- **Linux Process Injection (T1055):**
  - Hunt for deleted files with `icat` that contain shellcode or ELF headers.
  - Check `/proc/<pid>/maps` for suspicious memory regions (e.g., `rwx` permissions).
  - Correlate with `auditd` logs for `execve` syscalls (Event ID 1300). See [Linux Auditd Docs](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening).
- **File and Directory Discovery (T1083):**
  - Look for `fls` entries with unusual paths (e.g., `/tmp/.hidden`).
  - Correlate with `lsof` or `find` commands in `bash_history`. See [T1083](https://attack.mitre.org/techniques/T1083/).

## Attacker perspective
An attacker who compromises a host drops tooling (**T1105 Ingress Tool Transfer**), executes it (**T1204 User Execution**), and then tries to hide by deleting files (**T1070.004 File Deletion**) or timestomping (**T1070.006 Timestomp**). However, forensic triage tools like The Sleuth Kit and `bulk_extractor` recover artifacts that attackers assume are gone.

**Concrete TTPs and Artifacts:**
1. **Staging in Temp/Loot Directories**
   - Attackers stage tools in `/tmp`, `/var/tmp`, or custom directories (e.g., `/var/loot`).
   - **Artifacts:**
     - Directory entries and cluster runs remain in the filesystem until overwritten.
     - Deleted directory entries appear as `*`-marked in `fls` output.
     - File slack and unallocated space may retain fragments of staged filenames or payloads.
   - **MITRE ATT&CK:** **T1083 File and Directory Discovery** (reconnaissance) and **T1105 Ingress Tool Transfer** (staging). See [T1083](https://attack.mitre.org/techniques/T1083/) and [T1105](https://attack.mitre.org/techniques/T1105/).

2. **Hard-Coded Indicators in Binaries/Configs**
   - Attackers embed C2 URLs, IPs, and staging paths in binaries, scripts, or configs.
   - **Artifacts:**
     - `bulk_extractor` recovers these from file slack, unallocated space, or even allocated files.
     - Example: A carved URL in `url.txt` (e.g., `http://203.0.113.10/c2`) may match Zeek `http.log` entries.
   - **MITRE ATT&CK:** **T1071.001 Application Layer Protocol: Web Protocols** (C2) and **T1041 Exfiltration Over C2 Channel**. See [T1071.001](https://attack.mitre.org/techniques/T1071/001/) and [T1041](https://attack.mitre.org/techniques/T1041/).

3. **Obfuscation and Packing (T1027)**
   - Attackers obfuscate payloads (e.g., base64, XOR) or pack binaries to evade string searches.
   - **Artifacts:**
     - `bulk_extractor` may still carve plaintext indicators from slack/unallocated space.
     - ClamAV signatures (e.g., `Win.Trojan.Generic`) may detect packed samples.
   - **MITRE ATT&CK:** **T1027 Obfuscated Files or Information** and **T1140 Deobfuscate/Decode Files or Information**. See [T1027](https://attack.mitre.org/techniques/T1027/) and [T1140](https://attack.mitre.org/techniques/T1140/).

4. **Process Injection (T1055)**
   - Attackers inject code into legitimate processes (e.g., `sshd`, `nginx`) to evade detection.
   - **Artifacts:**
     - Deleted files recovered with `icat` may contain shellcode or ELF headers.
     - Memory regions with `rwx` permissions in `/proc/<pid>/maps`.
     - `auditd` logs for `execve` or `ptrace` syscalls.
   - **MITRE ATT&CK:** **T1055 Process Injection** and **T1055.001 Dynamic-Link Library Injection**. See [T1055](https://attack.mitre.org/techniques/T1055/) and [T1055.001](https://attack.mitre.org/techniques/T1055/001/).

**Evasion Techniques and Why Triage Still Wins:**
1. **Secure-Wipe Tools**
   - Attackers use `shred` or `dd` to overwrite free space, reducing carve yield.
   - **Why triage wins:** `bulk_extractor` may still recover fragments from slack space or unallocated clusters not fully overwritten.

2. **Timestomping (T1070.006)**
   - Attackers forge MACB times (e.g., `touch -t 202001010000 file`).
   - **Why triage wins:** Anomalies in the TSK timeline (e.g., `$MFT` sequence vs. timestamp inconsistencies) reveal tampering. See [T1070.006](https://attack.mitre.org/techniques/T1070/006/).

3. **Masquerading (T1036)**
   - Attackers rename binaries (e.g., `mv /bin/bash /tmp/.hidden`) or change extensions.
   - **Why triage wins:** File content (not name) determines signature hits and carved features. See [T1036](https://attack.mitre.org/techniques/T1036/).

## Answer key
Sample sha256: run `sha256sum exercise/triage_sample.raw` after generating; the digest is fixed by the deterministic generator above and is held by the validator for the check.

**Expected findings and the exact commands that produce them:**
```bash
# 1. Files present in the image (note.txt, eicar.com; FAT image usually at offset 0)
fls -r -p exercise/triage_sample.raw
# -> lists r/r entries for note.txt and eicar.com

# 2. Carved email + URL indicators
bulk_extractor -o exercise/be_out exercise/triage_sample.raw
grep -i example.com exercise/be_out/email.txt   # -> analyst@example.com
cat exercise/be_out/url.txt                     # -> http://203.0.113.10/payload

# 3. Extract eicar.com and scan
mkdir -p exercise/extract
icat exercise/triage_sample.raw $(fls -p exercise/triage_sample.raw | awk '/eicar.com/{gsub(/:/,"",$2);print $2}') > exercise/extract/eicar.com
clamscan --infected --stdout exercise/extract/eicar.com
# -> exercise/extract/eicar.com: Eicar-Test-Signature FOUND ; Infected files: 1
```
**Expected result summary:** Two indicators carved (`analyst@example.com`, `http://203.0.113.10/payload`) and exactly one ClamAV detection (`Eicar-Test-Signature`).

> **Note on the detection name:** ClamAV reports the EICAR test string as `Eicar-Test-Signature` (or `Win.Test.EICAR_HDB-1` depending on signature database version). The exact string comes from the loaded ClamAV database; see [ClamAV Scanning Docs](https://docs.clamav.net/manual/Usage/Scanning.html). A single-partition FAT image made with `mkfs.vfat` has its filesystem at offset 0, so no `-o` is required here.

### Common Pitfalls & Result Validation
Analysts often make critical mistakes during host triage that lead to false negatives or misinterpreted findings. Here are **concrete pitfalls** and how to validate results:

1. **Ignoring Filesystem Offsets**
   - **Pitfall:** Running `fls` or `fsstat` without `-o` on a multi-partition image reads garbage or fails silently.
   - **Validation:** Always run `mmls` first to identify the correct offset. For example, a GPT-partitioned disk may have the filesystem at sector 2048, not 0. Use `fsstat -o 2048 disk.raw` to confirm the filesystem type before proceeding. See [TSK Man Pages](https://www.sleuthkit.org/sleuthkit/man/fsstat.html).

2. **Misinterpreting Deleted Files**
   - **Pitfall:** Assuming `*`-marked `fls` entries are fully recoverable. If metadata is reused (`(realloc)`), `icat` may extract unrelated content.
   - **Validation:** Check the `fls` output for `(realloc)` flags. If present, the file content may be partially or fully overwritten. Correlate with `fsstat` to confirm cluster allocation status. This aligns with **T1564 Hide Artifacts** (e.g., hiding payloads in slack space). See [T1564](https://attack.mitre.org/techniques/T1564/).

3. **Overlooking Slack/Unallocated Space**
   - **Pitfall:** Relying solely on `fls` for indicators misses data in slack or unallocated space (e.g., carved URLs from freed clusters).
   - **Validation:** Use `bulk_extractor` to scan the entire image, not just allocated files. Cross-reference carved indicators (e.g., `url.txt`) with Zeek/Suricata logs to confirm C2 activity (**T1071.001**). See [bulk_extractor Wiki](https://github.com/simsong/bulk_extractor/wiki).

4. **False Positives in ClamAV Scans**
   - **Pitfall:** Treating all `FOUND` results as malicious. ClamAV may flag benign files (e.g., test scripts) or use generic signatures (e.g., `Win.Trojan.Generic`).
   - **Validation:** Verify the signature name against the [ClamAV Signature Database](https://www.clamav.net/documents/signatures). For example, `Eicar-Test-Signature` is benign, while `Win.Ransomware.Cerber` is actionable. Correlate with other indicators (e.g., carved URLs) to confirm **T1485 Data Destruction** or **T1486 Data Encrypted for Impact**. See [T1485](https://attack.mitre.org/techniques/T1485/) and [T1486](https://attack.mitre.org/techniques/T1486/).

5. **Timestomping Detection**
   - **Pitfall:** Accepting MACB times at face value. Attackers forge timestamps (**T1070.006**) to blend in.
   - **Validation:** Build a TSK timeline (`fls -m` + `mactime`) and look for anomalies:
     - Timestamps predating the filesystem creation date.
     - Inconsistent `$MFT` sequence numbers (NTFS) or FAT directory entries.
     See [SANS FOR508](https://www.sans.org/courses/advanced-incident-response-threat-hunting-training/) for timeline analysis techniques.

**Authoritative Sources for Validation:**
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://www.nist.gov/publications/guide-integrating-forensic-techniques-incident-response)
- [CISA Alert (AA22-257A): Understanding and Mitigating Russian State-Sponsored Cyber Threats to U.S. Critical Infrastructure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-257a)

## MITRE ATT&CK & DFIR phase
- **T1105 Ingress Tool Transfer** — Dropped/staged files recovered via Sleuth Kit. [Source](https://attack.mitre.org/techniques/T1105/)
- **T1070.004 Indicator Removal: File Deletion** — Deleted metadata entries recovered with `fls`/`icat`. [Source](https://attack.mitre.org/techniques/T1070/004/)
- **T1027 Obfuscated Files or Information** — Embedded/obfuscated indicators surfaced by `bulk_extractor`. [Source](https://attack.mitre.org/techniques/T1027/)
- **T1204 User Execution** — Malicious file identified by ClamAV signature. [Source](https://attack.mitre.org/techniques/T1204/)
- **T1071.001 Application Layer Protocol: Web Protocols** — Carved C2 URLs correlated to Zeek `http.log`. [Source](https://attack.mitre.org/techniques/T1071/001/)
- **T1041 Exfiltration Over C2 Channel** — Data exfiltration indicators carved from unallocated space. [Source](https://attack.mitre.org/techniques/T1041/)
- **T1055 Process Injection** — Injected code recovered from deleted files or slack space. [Source](https://attack.mitre.org/techniques/T1055/)
- **T1564 Hide Artifacts** — Artifacts hidden in slack/unallocated space or via timestomping. [Source](https://attack.mitre.org/techniques/T1564/)
- **DFIR phases:** Identification (`mmls`/`fsstat`), Examination (`fls`/`icat`/`bulk_extractor`), Analysis (`clamscan` + indicator correlation) — consistent with SANS DFIR process material. [Source](https://www.sans.org/posters/)


### Essential Commands & Features

While core triage commands like `fls` and `mmls` are covered, **The Sleuth Kit (TSK)** offers powerful utilities for bulk extraction and signature-based hunting that are often overlooked. Below are the most impactful commands for rapid forensic analysis, with concrete examples and tactical use cases.

#### **1. `tsk_recover` – Bulk File Extraction**
Extract all recoverable files from a forensic image to a designated directory. Critical for **T1562.001 (Indicator Removal: Clear Windows Event Logs)** or **T1074.001 (Data Staged: Local Data Staging)**, where adversaries hide artifacts in slack space or deleted files.
```bash
tsk_recover -a /evidence/disk.img /output/recovered_files/
```
- **`-a`**: Recover *all* files (allocated + unallocated).
- **Use when**: You need to quickly preserve evidence before deeper analysis or when hunting for staged exfiltration data.

#### **2. `hfind` – Hash Lookup (NSRL or Custom)**
Compare file hashes against known-good (NSRL) or custom hashsets (e.g., IOCs). Vital for detecting **T1036.005 (Masquerading: Match Legitimate Name or Location)** or **T1553.002 (Subvert Trust Controls: Code Signing)**.
```bash
hfind -i nsrl-md5 /evidence/hashes.txt
```
- **`-i nsrl-md5`**: Use NSRL’s MD5 hashset (pre-downloaded).
- **Use when**: Triaging large datasets for known malware or unauthorized software.

#### **3. `sigfind` – Signature-Based Carving**
Search for byte signatures (e.g., file headers) in raw disk data. Essential for **T1127 (Trusted Developer Utilities Proxy Execution)** or **T1027.001 (Obfuscated Files or Information: Binary Padding)**.
```bash
sigfind -b 512 -o 0x00 -t "JFIF" /evidence/disk.img
```
- **`-b 512`**: Block size (adjust for filesystem).
- **`-o 0x00`**: Offset (0x00 for start of sector).
- **`-t "JFIF"`**: Target signature (e.g., JPEG files).
- **Use when**: Recovering fragmented files or hunting for embedded payloads.

**Authoritative Sources**:
- [TSK Official Documentation: `tsk_recover`](https://www.sleuthkit.org/sleuthkit/man/tsk_recover.1.html)
- [SANS FOR500: Advanced Digital Forensics](https://

### Threat Hunting & Detection Engineering

Once triage has identified suspicious Linux artifacts, shift to proactive threat hunting and detection engineering. Focus on **T1560.001 Archive Collected Data: Archive via Utility** and **T1059.006 Command and Scripting Interpreter: Python**. Hunt for `tar`, `gzip`, or `zip` processes invoked with `-czf` or `-cvf` flags that compress `/home/*/.ssh`, `/var/log`, or `/etc` directories—common targets for exfiltration staging (T1560.001). Use `auditd` logs (`type=EXECVE` with `a0=tar` or `a0=gzip`) or `sysmon-linux` Event ID 1 (Process Creation) with `Image` fields matching these utilities.

For T1059.006, detect Python scripts executing base64-encoded commands via `python3 -c` or `python -c` followed by `exec(base64.b64decode(` in process arguments. Pivot on `ptrace` syscalls (`strace` or `auditd` logs) where Python processes attach to other processes (e.g., `PTRACE_ATTACH`), a technique used for credential dumping or code injection. Leverage Zeek’s `conn.log` to correlate high-volume outbound connections from these processes to unusual external IPs, filtering on `id.orig_h` and `id.resp_p` (e.g., non-standard ports like 8443/tcp).

**Sources:**
- [Linux Audit Framework Documentation (Red Hat)](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)
- [Sysmon for Linux (Microsoft Threat Intelligence)](https://www.microsoft.com/en-us/security/blog/2021/08/10/sysmon-for-linux-now-available-for-public-preview/)


### Essential Commands & Features  
For full forensic recovery and slack-space analysis, The Sleuth Kit (TSK) provides three underutilized commands. `tsk_recover` extracts all allocated files from a disk image to a directory, preserving metadata. Use it when you need a complete, organized file export without manually carving each item:  
```bash  
tsk_recover -o 2048 disk.dd /recovered_files  
```  
`blkls` lists the block (sector) data of a volume, and with the `-s` flag outputs only slack space bytes – the unused portion of a block after a file ends. Adversaries may hide data here to evade detection. Examine slack with:  
```bash  
blkls -s disk.dd > slack_dump.bin  
```  
`blkcalc` correlates a block address from `blkls` output (or a raw offset) to its logical file system block number. Use it to pinpoint where a suspicious byte sequence resides within a file or slack space:  
```bash  
blkcalc -u 12345 disk.dd  
```  
This trio supports detection of techniques like **T1048 (Exfiltration Over Alternative Protocol)** when hidden data is later retrieved, and **T1202 (Indicator Removal from Tools)** if slack space is used to discard tool artifacts.  

**Additional Resources:**  
- TSK man pages on linux.die.net: [blkls](https://linux.die.net/man/1/blkls), [tsk_recover](https://linux.die.net/man/1/tsk_recover)  
- Forensic Focus, “Slack Space Forensics”: [link](https://www.forensicfocus.com/articles/slack-space-forensics/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- WSL Kali-Linux Usage** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wsl_kali_linux_usage.yml; license: Detection Rule License / DRL):

```yaml
title: WSL Kali-Linux Usage
id: 6f1a11aa-4b8a-4b7f-9e13-4d3e4ff0e0d4
status: experimental
description: Detects the use of Kali Linux through Windows Subsystem for Linux
references:
    - https://medium.com/@redfanatic7/running-kali-linux-on-windows-51ad95166e6e
    - https://learn.microsoft.com/en-us/windows/wsl/install
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-10
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_img_appdata:
        - Image|contains|all:
              - ':\Users\'
              - '\AppData\Local\packages\KaliLinux'
        - Image|contains|all:
              - ':\Users\'
              - '\AppData\Local\Microsoft\WindowsApps\kali.exe'
    selection_img_windowsapps:
        Image|contains: ':\Program Files\WindowsApps\KaliLinux.'
        Image|endswith: '\kali.exe'
    selection_kali_wsl_parent:
        ParentImage|endswith:
            - '\wsl.exe'
            - '\wslhost.exe'
    selection_kali_wsl_child:
        - Image|contains:
              - '\kali.exe'
              - '\KaliLinux'
        - CommandLine|contains:
              - 'Kali.exe'
              - 'Kali-linux'
              - 'kalilinux'
    filter_main_install_uninstall:
        CommandLine|contains:
            - ' -i '
            - ' --install '
            - ' --unregister '
    condition: 1 of selection_img_* or all of selection_kali_* and not 1 of filter_main_*
falsepositives:
    - Legitimate installation or usage of Kali Linux WSL by administrators or security teams
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/apt_winnti_linux.yar, author: Silas Cutler (havex [@] chronicle.security), Chronicle Security):

```yara
rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
        id = "d641de9a-e563-5067-b7e4-0aa83a087ed4"
    strings:
        $config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
        $export1 = "our_sockets"
        $export2 = "get_our_pids"
    condition:
        uint16(0) == 0x457f and all of them
}
```

**Real-world context (MITRE T1071.001 -- Application Layer Protocol: Web Protocols):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1071/001/ -- real in-the-wild use includes Sandworm, APT18, APT19, APT28.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

When triaging Linux systems, **The Sleuth Kit (TSK)** provides powerful block-level analysis capabilities that are critical for uncovering hidden artifacts. Below are three **undemonstrated but essential** commands for deep forensic inspection:

1. **`blkcat` – Extract Raw Block Data**
   Use to dump the contents of a specific disk block, ideal for recovering deleted files or examining slack space.
   **Example:**
   ```bash
   blkcat -o 2048 /dev/sdb 12345 > block_12345.raw
   ```
   *When to use:* Investigate **T1074.001 (Data Staged)** or **T1560.001 (Archive Collected Data)** where adversaries hide data in unallocated blocks.

2. **`blkls` – List/Extract Unallocated Blocks**
   Extracts all unallocated blocks (slack space) for offline analysis, revealing remnants of deleted files.
   **Example:**
   ```bash
   blkls -o 2048 /dev/sdb > unallocated_blocks.raw
   ```
   *When to use:* Detect **T1070.004 (File Deletion)** or **T1485 (Data Destruction)** where attackers attempt to cover tracks.

3. **`hfind` – Hash Lookup (NSRL/Hash Sets)**
   Quickly checks if a file hash exists in a known-good database (e.g., NSRL) or custom hash sets.
   **Example:**
   ```bash
   hfind -i nsrl-md5 /path/to/hashes.txt 098f6bcd4621d373cade4e832627b4f6
   ```
   *When to use:* Identify **T1140 (Deobfuscate/Decode Files or Information)** or **T1204.002 (Malicious File)** by filtering known-good files.

**Sources:**
- [TSK Official Documentation: `blkcat`, `blkls`, `hfind`](https://www.sleuthkit.org/sleuthkit/man/)
- [DFIR Review: Slack Space Analysis](https://www.dfir.review/)

### Adversary Emulation & Red-Team Perspective

From an attacker’s perspective, Linux triage workflows present opportunities to evade detection, maintain persistence, and exfiltrate data. Adversaries often **abuse legitimate system tools** to blend in with normal activity, leveraging **Living-off-the-Land Binaries (LOLBins)** to execute malicious actions. For example, an attacker may use `curl` or `wget` to download additional payloads (**[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)**), disguising traffic as routine updates. They may also **obfuscate scripts** using `base64` encoding or compression (e.g., `gzip`) to bypass signature-based detection (**[T1027.010: Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/010/)**).

Attackers frequently **manipulate timestamps** (`touch -r`) or **hide files in alternate data streams** (on filesystems like XFS or ext4 with extended attributes) to evade timeline analysis. Persistence mechanisms, such as **cron jobs** or **systemd services**, may be disguised as legitimate processes (e.g., `systemd-analyze` masquerading as a performance tool). Artifacts left behind include:
- Modified `~/.bashrc`, `/etc/crontab`, or `/etc/systemd/system/` entries.
- Unusual network connections in `ss -tulnp` or `netstat` output.
- Suspicious process trees (e.g., `bash` spawning `curl` or `python`).

Evasion considerations include **clearing logs** (`rm -rf /var/log/*`) or **disabling auditd** to hinder forensic analysis. Red teams should test detection gaps by simulating these TTPs in controlled environments.

**Sources:**
- [MITRE ATT&CK: Linux Techniques](https://attack.mitre.org/matrices/enterprise/linux/)
- [Red Canary: Linux Threat Detection](https://redcanary.com/threat-detection/linux/)

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1105 (Ingress Tool Transfer)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1105/
- **Threat actors documented using it:** Sandworm (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
**Claim → Source Mapping (all URLs are official/authoritative):**

- **The Sleuth Kit (TSK) tool behavior and flags** (`mmls`, `fsstat`, `fls`, `icat`, `-o`/`-r`/`-p`/`-m`, `*` deleted markers):
  - [TSK Man Pages](https://www.sleuthkit.org/sleuthkit/man/) (specifically [mmls](https://www.sleuthkit.org/sleuthkit/man/mmls.html), [fsstat](https://www.sleuthkit.org/sleuthkit/man/fsstat.html), [fls](https://www.sleuthkit.org/sleuthkit/man/fls.html), [icat](https://www.sleuthkit.org/sleuthkit/man/icat.html))
  - [TSK GitHub Repo](https://github.com/sleuthkit/sleuthkit) (current release: 4.12.1)
  - [TSK Timeline Workflow](https://wiki.sleuthkit.org/index.php?title=Mactime) (`fls -m`, `mactime`)

- **bulk_extractor behavior, output feature files, `-o` option, scanners:**
  - [bulk_extractor GitHub Repo](https://github.com/simsong/bulk_extractor) (current release: 2.0.0)
  - [bulk_extractor Wiki](https://github.com/simsong/bulk_extractor/wiki) (feature file documentation)
  - [Kali Tools: bulk-extractor](https://www.kali.org/tools/bulk-extractor/)

- **ClamAV `clamscan` flags** (`-r`, `--infected`, `--stdout`, `--version`), detection names, signature updates via `freshclam`:
  - [ClamAV Scanning Docs](https://docs.clamav.net/manual/Usage/Scanning.html)
  - [ClamAV Signature Management](https://docs.clamav.net/manual/Usage/SignatureManagement.html)
  - [ClamAV Signature Database](https://www.clamav.net/documents/signatures)

- **EICAR test file (harmless AV test string):**
  - [EICAR Test File](https://www.eicar.org/download-anti-malware-testfile/)

- **Reserved test ranges used in the sample:**
  - RFC 5737 (203.0.113.0/24 documentation range): [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)
  - RFC 2606 (example.com reserved): [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)

- **Security Onion pivots (Suricata/Zeek/Elastic):**
  - [Security Onion Docs](https://docs.securityonion.net/en/2.4/)
  - [Zeek Log Reference](https://docs.zeek.org/en/master/logs/index.html)

- **SANS SIFT Workstation and DFIR process/posters:**
  - [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/)
  - [SANS DFIR Posters](https://www.sans.org/posters/)

- **MITRE ATT&CK techniques:**
  - [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
  - [T1070.004 Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
  - [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006/)
  - [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
  - [T1204 User Execution](https://attack.mitre.org/techniques/T1204/)
  - [T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
  - [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
  - [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/)
  - [T1055.001 Dynamic-Link Library Injection](https://attack.mitre.org/techniques/T1055/001/)
  - [T1564 Hide Artifacts](https://attack.mitre.org/techniques/T1564/)
  - [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)
  - [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
  - [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
  - [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)

- **Linux Auditd and Detection Engineering:**
  - [Red Hat Auditd Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)
  - [NIST SP 800-86: Forensic Techniques in Incident Response](https://www.nist.gov/publications/guide-integrating-forensic-techniques-incident-response)
  - [CISA Alert AA22-257A: Russian State-Sponsored Cyber Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-257a)

## Related modules
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares `bulk_extractor` for carving indicators from acquired evidence.
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares The Sleuth Kit for building MACB timelines.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- shares The Sleuth Kit for partition/filesystem examination.
- [Memory forensics](../02-memory-forensics/README.md) -- shares `bulk_extractor` for feature carving from memory images.

<!-- cyberlab-enriched: v3 -->
- https://www.sleuthkit.org/sleuthkit/man/tsk_recover.1.html
- https://www.microsoft.com/en-us/security/blog/2021/08/10/sysmon-for-linux-now-available-for-public-preview/

<!-- cyberlab-enriched: v4 -->
- https://linux.die.net/man/1/blkls
- https://linux.die.net/man/1/tsk_recover
- https://www.forensicfocus.com/articles/slack-space-forensics/
- https://attack.mitre.org/techniques/T1059/003/

<!-- cyberlab-enriched: v5 -->
- https://www.dfir.review/
- https://attack.mitre.org/techniques/T1027/010/
- https://attack.mitre.org/matrices/enterprise/linux/
- https://redcanary.com/threat-detection/linux/

<!-- cyberlab-enriched: v6 -->
