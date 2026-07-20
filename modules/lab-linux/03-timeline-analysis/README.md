# 03 * Timeline / super-timelining -- LAB-LINUX

## Overview (plain language)
When investigating a compromised computer, one of the hardest questions is "what happened, and in what order?" Timeline tools answer this by collecting the tiny timestamps that operating systems and applications leave behind — file creation and modification times, browser history, event logs, registry changes, and more — and lining them all up into one big chronological list. Plaso (whose main engine is called `log2timeline`) is the modern "super-timeline" tool: it reads dozens of artifact types from a disk image and merges them into a single searchable database, so an analyst can scroll through the day of an incident minute by minute. `mactime` is an older, focused tool from The Sleuth Kit that builds a simpler timeline from filesystem MAC (Modified, Accessed, Changed) times. Together they turn scattered, cryptic timestamps into a human-readable story of the event.

Plaso stores extracted events in an SQLite-based `.plaso` storage file, then a separate tool (`psort.py`) sorts, filters, and exports them — this two-stage design (collect once, analyze many times) is documented in the Plaso user guide (https://plaso.readthedocs.io/en/latest/sources/user/index.html).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso (preinstalled on SIFT) | Super-timelining framework that parses many artifact types into a single storage file. |
| log2timeline | apt install plaso (preinstalled on SIFT) | The Plaso front-end CLI that extracts events from images/directories into a `.plaso` store. |
| mactime | apt install sleuthkit (preinstalled on SIFT) | The Sleuth Kit tool that turns a filesystem `bodyfile` into a chronological MAC-time timeline. |

Notes on install/source: Plaso is distributed as the `plaso` package and documented at https://plaso.readthedocs.io/ with source at https://github.com/log2timeline/plaso. The Sleuth Kit tools (`fls`, `mactime`) are documented at https://www.sleuthkit.org/sleuthkit/docs.php and packaged by Kali at https://www.kali.org/tools/sleuthkit/. Plaso is also preinstalled on the SANS SIFT Workstation (https://www.sans.org/tools/sift-workstation/).

## Learning objectives
- Generate a Plaso storage file from a benign disk-image sample using `log2timeline.py`.
- Produce a filtered, human-readable CSV super-timeline with `psort.py`.
- Create a filesystem bodyfile with `fls` and render a timeline with `mactime`.
- Interpret timeline output to identify the sequence and timing of file activity.

## Environment check
```bash
# Prove the timelining tools are installed on LAB-LINUX (SIFT)
log2timeline.py --version
psort.py --version
mactime -V
fls -V
```
Expected output: `log2timeline.py` and `psort.py` each print a `plaso - ...` version banner (e.g. `plaso - log2timeline version 20230717`); `mactime -V` and `fls -V` print a Sleuth Kit version line such as `The Sleuth Kit ver 4.12.0`.

The `--version` flag for the Plaso CLI tools and the version-banner format are documented in the Plaso tool references (https://plaso.readthedocs.io/en/latest/sources/user/Tools.html). The Sleuth Kit `-V` version flag is documented in the TSK tool manuals (https://www.sleuthkit.org/sleuthkit/man/); note that most TSK tools accept an uppercase `-V` for version.

## Guided walkthrough
1. `log2timeline.py` — extracts events from a source (image/dir) into a `.plaso` storage file.
```bash
# Ingest the benign sample directory into a Plaso storage file
log2timeline.py --status_view none --storage-file /tmp/case.plaso exercise/sample_fs/
```
Why: `log2timeline.py` is the *collection* stage — it runs the appropriate parsers/plugins against the source and writes every extracted event into the storage file for later analysis. The `--storage-file` option names the output `.plaso` store, and `--status_view none` suppresses the live progress window so the command runs cleanly in a script or non-interactive shell (both options are documented at https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html). Nuance: when the source is a mounted directory (not a raw image), only file-content and filesystem-metadata parsers apply, so `filestat` dominates; feeding a full disk image instead engages many more parsers (event logs, registry, browser history). Expected: a progress summary and a new `/tmp/case.plaso` file; the closing report lists parsers used and the number of events extracted.

2. `psort.py` — sorts/filters the storage file into a readable timeline.
```bash
# Export the full timeline to CSV (l2tcsv output)
psort.py -o l2tcsv -w /tmp/timeline.csv /tmp/case.plaso
head -n 5 /tmp/timeline.csv
```
Why: `psort.py` is the *analysis* stage — it reads the `.plaso` store, sorts events chronologically, applies any filters, and writes to a chosen output module. `-o l2tcsv` selects the classic log2timeline CSV format and `-w` names the output file (output modules and options are documented at https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html). Nuance: the `l2tcsv` header is `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra` — the `MACB` column tells you which of Modified/Accessed/Changed/Born flags a given row represents, which is central to spotting timestomping later. Expected: `psort.py` reports the number of events written; `head` shows the header row followed by chronologically sorted event rows.

3. `fls` + `mactime` — build and render a Sleuth Kit filesystem timeline.
```bash
# Create a bodyfile from the sample raw image, then render it with mactime
fls -r -m / -o 2048 exercise/disk.raw > /tmp/body.txt
mactime -b /tmp/body.txt -d > /tmp/mactime.csv
head -n 5 /tmp/mactime.csv
```
Why: `fls` lists file/directory names from a filesystem; `-r` recurses into subdirectories, `-m /` emits a `mactime` bodyfile with `/` prepended to paths, and `-o 2048` tells TSK the filesystem starts at sector offset 2048 within the image (flags documented at https://www.sleuthkit.org/sleuthkit/man/fls.html). `mactime` then converts that bodyfile into a time-ordered timeline: `-b` names the bodyfile and `-d` requests comma-delimited output (documented at https://www.sleuthkit.org/sleuthkit/man/mactime.html and https://wiki.sleuthkit.org/index.php?title=Mactime). Nuance: the sector offset must match the partition layout of the specific image — if the FAT filesystem here begins at the very start of the image rather than a partition, drop `-o 2048`; use `mmls` to confirm the correct offset. Expected: `body.txt` contains pipe-delimited TSK entries; `mactime.csv` is a comma-delimited timeline with `Date,Size,Type,Mode,UID,GID,Meta,File Name` columns sorted by time.

## Hands-on exercise
Using the sample in this module's `exercise/` directory, build a Plaso super-timeline and locate the earliest and latest file-system events, then answer: which parser produced the most events, and what is the timestamp of the first `filestat` event?

Sample declaration:
- **Type:** small FAT filesystem raw disk image (`exercise/disk.raw`) plus an unpacked file tree (`exercise/sample_fs/`).
- **Safe origin:** benign/inert — generated in the lab with `dd`/`mkfs.vfat` and populated with harmless text files. Contains NO malware and requires NO network egress.
- **sha256 (disk.raw):** `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

## SOC analyst perspective
Super-timelines are a core examination technique for incident responders because they reconstruct the exact order of adversary actions across many artifact sources at once (the value of the "super timeline" is described in the SANS log2timeline material at https://www.sans.org/blog/digital-forensics-sifting-cheating-timelines-with-log2timeline/ and the SANS FOR508 course at https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/). When Security Onion alerts fire on a host, the analyst pulls a disk image and runs `log2timeline.py`, then uses `psort.py` filters to zoom into the alert window, correlating filesystem MACB times with browser, prefetch, and event-log events.

Concrete detection logic and pivots:
- **Scope the timeline to the alert window.** Use a `psort.py` date filter to slice around the alert (documented at https://plaso.readthedocs.io/en/latest/sources/user/Filtering-events.html), e.g. `psort.py -o l2tcsv -w window.csv /tmp/case.plaso "date > '2024-01-01 00:00:00' AND date < '2024-01-01 06:00:00'"`.
- **Timestomp indicator (T1070.006):** flag files where the `$STANDARD_INFORMATION` (SI) times precede or diverge from `$FILE_NAME` (FN) times, or where MACB shows a "born" time in the past but the MFT sequence number is recent. Plaso surfaces both SI and FN entries via the NTFS `$MFT` parser (https://plaso.readthedocs.io/en/latest/sources/user/Supported-formats.html).
- **Log clearing (T1070.001):** look for a gap where expected recurring events (logon events, service starts) stop, and for a `winevtx` record indicating the Security event log was cleared (Windows Event ID 1102) — cross-reference the Microsoft Learn documentation for that audit event (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102).
- **Data staging (T1074):** cluster the timeline by directory and creation time to reveal a burst of files written into a staging path.
- **Security Onion pivots:** correlate the on-disk timeline against Suricata alerts, Zeek `conn.log`/`http.log`/`files.log` connection and transfer records, and Elastic/Kibana host events (Security Onion analyst tooling documented at https://docs.securityonion.net/en/2.4/analyst-tools.html). Match a Zeek file-download timestamp to the filesystem `filestat` creation time of the dropped artifact to confirm initial access ordering.

This maps activity to ATT&CK techniques such as T1070.006 (Timestomp), T1070.001 (Clear logs), and T1074 (Data Staged) by revealing inconsistencies between MACB values.

## Attacker perspective
Attackers know timelines betray them, so they attempt anti-forensics. Concrete TTPs, the artifacts they leave, and evasion notes:
- **Timestomping (T1070.006):** tools like SetMACE, `timestomp`, or a simple `touch -d` set a file's SI timestamps to blend into OS-install dates (technique documented at https://attack.mitre.org/techniques/T1070/006/). Artifact: on NTFS the `$FILE_NAME` attribute timestamps are updated by the kernel and are far harder to forge, so SI-vs-FN divergence and an MFT sequence/record number inconsistent with an "old" born date remain. Evasion attempt: some tools also rewrite FN times via lower-level writes, but nanosecond-precision truncation (SI times ending in zeros) is itself an indicator noted in DFIR guidance (SANS FOR508, https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).
- **Clearing event logs (T1070.001):** `wevtutil cl`, `Clear-EventLog`, or `Remove-Item` on `.evtx` files (https://attack.mitre.org/techniques/T1070/001/). Artifact: Windows writes Event ID 1102 ("The audit log was cleared", https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102) and leaves a suspicious gap in the timeline; on Linux, truncated `/var/log` files show reset inode/size timings.
- **Wiping browser history:** deleting history/cache leaves the SQLite databases with unallocated/freed pages and shifts the file's own MACB times, which Plaso's browser and `filestat` parsers still record.

Ironically these actions leave their own artifacts — Plaso surfaces the divergence between `$STANDARD_INFORMATION` and `$FILE_NAME` MFT timestamps, out-of-order sequence numbers, and files whose filesystem `filestat` time contradicts their content or registry references. An analyst reviewing the super-timeline can spot the impossible ordering (e.g., a file "created" before the OS) that a timestomp introduces, turning the attacker's cover-up into a detection signal.

## Answer key
Sample sha256 (disk.raw): `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

Commands producing the findings:
```bash
# Build the storage file and full timeline
log2timeline.py --status_view none --storage-file /tmp/case.plaso exercise/sample_fs/
psort.py -o l2tcsv -w /tmp/timeline.csv /tmp/case.plaso

# Which parser produced the most events (l2tcsv column 6 = sourcetype/parser)
cut -d',' -f6 /tmp/timeline.csv | sort | uniq -c | sort -nr | head -n 1

# Timestamp of the first filestat event (earliest by sort)
grep filestat /tmp/timeline.csv | sort -t',' -k1,2 | head -n 1
```
Expected findings: the `filestat` parser produces the most events for a raw filesystem sample; the first `filestat` event is the earliest MACB timestamp in the CSV (the topmost row after sorting by date/time). The `mactime` cross-check (`head -n 2 /tmp/mactime.csv`) reports the same earliest timestamp, validating consistency between the Plaso and Sleuth Kit timelines. (The `l2tcsv` column ordering used above is defined in the Plaso output-module reference, https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html.)

## MITRE ATT&CK & DFIR phase
- **T1070.006** — Indicator Removal: Timestomp (detect via MACB / SI-vs-FN inconsistencies in the super-timeline). https://attack.mitre.org/techniques/T1070/006/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs (gaps or missing log events; Event ID 1102). https://attack.mitre.org/techniques/T1070/001/
- **T1074** — Data Staged (staging directories revealed by clustered filesystem creation times). https://attack.mitre.org/techniques/T1074/
- **DFIR phase:** Examination / Analysis (timeline reconstruction and event correlation).

## Sources
Claim → source mapping (all URLs are authoritative tool/vendor/standards pages):

- Plaso two-stage design, `.plaso` storage file, `log2timeline.py`/`psort.py` usage and options — Plaso official documentation: https://plaso.readthedocs.io/en/latest/ ; user guide: https://plaso.readthedocs.io/en/latest/sources/user/index.html ; `log2timeline` usage & `--storage-file`/`--status_view`: https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html ; `psort` usage & output modules: https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html ; filtering/date filters: https://plaso.readthedocs.io/en/latest/sources/user/Filtering-events.html ; output/formatting (l2tcsv columns): https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html ; supported formats/parsers (NTFS `$MFT`, browser): https://plaso.readthedocs.io/en/latest/sources/user/Supported-formats.html
- Plaso tool reference / `--version` banner — https://plaso.readthedocs.io/en/latest/sources/user/Tools.html
- Plaso source repository — https://github.com/log2timeline/plaso
- SANS — "Digital Forensics SIFT-ing: Cheating Timelines with log2timeline" (super-timeline value): https://www.sans.org/blog/digital-forensics-sifting-cheating-timelines-with-log2timeline/
- SANS FOR508 (Advanced IR & Threat Hunting; DFIR timeline analysis, SI-vs-FN, timestomp truncation): https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- SANS SIFT Workstation (Plaso/TSK preinstalled): https://www.sans.org/tools/sift-workstation/
- The Sleuth Kit — `fls` manual (`-r`, `-m`, `-o`): https://www.sleuthkit.org/sleuthkit/man/fls.html
- The Sleuth Kit — `mactime` manual (`-b`, `-d`): https://www.sleuthkit.org/sleuthkit/man/mactime.html
- The Sleuth Kit — `mactime`/bodyfile wiki reference: https://wiki.sleuthkit.org/index.php?title=Mactime
- The Sleuth Kit — tool docs / man index (version flags): https://www.sleuthkit.org/sleuthkit/docs.php ; https://www.sleuthkit.org/sleuthkit/man/
- Kali Tools — Sleuth Kit package: https://www.kali.org/tools/sleuthkit/
- Microsoft Learn — Event 1102 "The audit log was cleared": https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
- Security Onion — analyst tools (Suricata/Zeek/Elastic/Kibana pivots): https://docs.securityonion.net/en/2.4/analyst-tools.html
- MITRE ATT&CK — T1070.006 Timestomp: https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK — T1070.001 Clear Windows Event Logs: https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK — T1074 Data Staged: https://attack.mitre.org/techniques/T1074/

## Related modules
- [Plaso super-timeline deep-dive](../23-plaso-supertimeline/README.md) -- shares log2timeline as its core engine and goes deeper on parsers/filters.
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- applies plaso super-timelines to a full end-to-end intrusion case.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same Foundations learning path; supplies the filesystem/`fls` groundwork used here.
- [Memory forensics](../02-memory-forensics/README.md) -- same Foundations learning path; complements on-disk timelines with volatile-memory artifacts.

<!-- cyberlab-enriched: v1 -->
