# 03 * Timeline / super-timelining -- LAB-LINUX

## Overview (plain language)
When investigating a compromised computer, one of the hardest questions is "what happened, and in what order?" Timeline tools answer this by collecting the tiny timestamps that operating systems and applications leave behind — file creation and modification times, browser history, event logs, registry changes, and more — and lining them all up into one big chronological list. Plaso (whose main engine is called `log2timeline`) is the modern "super-timeline" tool: it reads dozens of artifact types from a disk image and merges them into a single searchable database, so an analyst can scroll through the day of an incident minute by minute. `mactime` is an older, focused tool from The Sleuth Kit that builds a simpler timeline from filesystem MAC (Modified, Accessed, Changed) times. Together they turn scattered, cryptic timestamps into a human-readable story of the event.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso (preinstalled on SIFT) | Super-timelining framework that parses many artifact types into a single storage file. |
| log2timeline | apt install plaso (preinstalled on SIFT) | The Plaso front-end CLI that extracts events from images/directories into a `.plaso` store. |
| mactime | apt install sleuthkit (preinstalled on SIFT) | The Sleuth Kit tool that turns a filesystem `bodyfile` into a chronological MAC-time timeline. |

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

## Guided walkthrough
1. `log2timeline.py` — extracts events from a source (image/dir) into a `.plaso` storage file.
```bash
# Ingest the benign sample directory into a Plaso storage file
log2timeline.py --status_view none --storage-file /tmp/case.plaso exercise/sample_fs/
```
Expected: a progress summary and a new `/tmp/case.plaso` file; the closing report lists parsers used and the number of events extracted.

2. `psort.py` — sorts/filters the storage file into a readable timeline.
```bash
# Export the full timeline to CSV (l2tcsv output)
psort.py -o l2tcsv -w /tmp/timeline.csv /tmp/case.plaso
head -n 5 /tmp/timeline.csv
```
Expected: `psort.py` reports the number of events written; `head` shows a header row (`date,time,timezone,MACB,source,...`) followed by chronologically sorted event rows.

3. `fls` + `mactime` — build and render a Sleuth Kit filesystem timeline.
```bash
# Create a bodyfile from the sample raw image, then render it with mactime
fls -r -m / -o 2048 exercise/disk.raw > /tmp/body.txt
mactime -b /tmp/body.txt -d > /tmp/mactime.csv
head -n 5 /tmp/mactime.csv
```
Expected: `body.txt` contains pipe-delimited TSK entries; `mactime.csv` is a comma-delimited timeline with `Date,Size,Type,Mode,UID,GID,Meta,File Name` columns sorted by time.

## Hands-on exercise
Using the sample in this module's `exercise/` directory, build a Plaso super-timeline and locate the earliest and latest file-system events, then answer: which parser produced the most events, and what is the timestamp of the first `filestat` event?

Sample declaration:
- **Type:** small FAT filesystem raw disk image (`exercise/disk.raw`) plus an unpacked file tree (`exercise/sample_fs/`).
- **Safe origin:** benign/inert — generated in the lab with `dd`/`mkfs.vfat` and populated with harmless text files. Contains NO malware and requires NO network egress.
- **sha256 (disk.raw):** `9f2c4d7a1e8b3f60c5a29d4e7b8c1f03a6d92e4b7c8f105a3d6e9b2c4f70185d`

## SOC analyst perspective
Super-timelines are a core examination technique for incident responders because they reconstruct the exact order of adversary actions across many artifact sources at once. When Security Onion alerts fire (via Suricata/Zeek/Elastic) on a host, the analyst pulls a disk image and runs `log2timeline.py`, then uses `psort.py` filters to zoom into the alert window, correlating filesystem MACB times with browser, prefetch, and event-log events. This confirms initial access, staging, and execution ordering, and lets the analyst pivot Security Onion Kibana network events against on-disk timestamps. It supports mapping activity to ATT&CK techniques such as T1070.006 (Timestomp) and T1074 (Data Staged) by revealing inconsistencies between MACB values.

## Attacker perspective
Attackers know timelines betray them, so they attempt anti-forensics: timestomping files (T1070.006) with tools like SetMACE or `touch` to blend malicious files into system-install dates, clearing logs (T1070.001), and wiping browser history. Ironically these actions leave their own artifacts — Plaso surfaces the divergence between `$STANDARD_INFORMATION` and `$FILE_NAME` MFT timestamps, out-of-order sequence numbers, and files whose filesystem `filestat` time contradicts their content or registry references. An analyst reviewing the super-timeline can spot the impossible ordering (e.g., a file "created" before the OS) that a timestomp introduces, turning the attacker's cover-up into a detection signal.

## Answer key
Sample sha256 (disk.raw): `9f2c4d7a1e8b3f60c5a29d4e7b8c1f03a6d92e4b7c8f105a3d6e9b2c4f70185d`

Commands producing the findings:
```bash
# Build the storage file and full timeline
log2timeline.py --status_view none --storage-file /tmp/case.plaso exercise/sample_fs/
psort.py -o l2tcsv -w /tmp/timeline.csv /tmp/case.plaso

# Which parser produced the most events
cut -d',' -f7 /tmp/timeline.csv | sort | uniq -c | sort -nr | head -n 1

# Timestamp of the first filestat event (earliest by sort)
grep filestat /tmp/timeline.csv | sort -t',' -k1,2 | head -n 1
```
Expected findings: the `filestat` parser produces the most events for a raw filesystem sample; the first `filestat` event is the earliest MACB timestamp in the CSV (the topmost row after sorting by date/time). The `mactime` cross-check (`head -n 2 /tmp/mactime.csv`) reports the same earliest timestamp, validating consistency between the Plaso and Sleuth Kit timelines.

## MITRE ATT&CK & DFIR phase
- **T1070.006** — Indicator Removal: Timestomp (detect via MACB inconsistencies in the super-timeline).
- **T1070.001** — Indicator Removal: Clear Windows/Linux logs (gaps or missing log events in the timeline).
- **T1074** — Data Staged (staging directories revealed by clustered filesystem creation times).
- **DFIR phase:** Examination / Analysis (timeline reconstruction and event correlation).

## Sources
- SANS — "Digital Forensics SIFT-ing: Cheating Timelines with log2timeline": https://www.sans.org/blog/digital-forensics-sifting-cheating-timelines-with-log2timeline/
- Plaso official documentation: https://plaso.readthedocs.io/en/latest/
- The Sleuth Kit — `mactime` and `fls` documentation: https://wiki.sleuthkit.org/index.php?title=Mactime
- Kali Tools — Sleuth Kit: https://www.kali.org/tools/sleuthkit/
- MITRE ATT&CK — T1070.006 Timestomp: https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK — T1074 Data Staged: https://attack.mitre.org/techniques/T1074/