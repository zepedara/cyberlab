# 23 * Plaso super-timeline deep-dive -- LAB-LINUX

## Overview (plain language)
When you investigate a hacked or infected computer, one of the hardest questions is "what happened, and in what order?" Every file, log, browser visit, and registry change leaves a tiny timestamp behind, scattered across dozens of different places. Plaso (with its command-line front-end log2timeline) is a tool that automatically reads all of those scattered time records from a disk image and merges them into one giant, sortable list called a "super-timeline." mactime is an older, simpler companion that turns filesystem time data into a readable day-by-day report. Together they let an analyst press play on a machine's history and watch events unfold minute by minute instead of guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso | Framework that parses many artifact types into a single timeline database (.plaso) and exports it |
| log2timeline | apt install plaso | The `log2timeline.py` collection engine that walks an image/mount and extracts timestamped events |
| mactime | apt install sleuthkit | Converts Sleuth Kit `fls`/`ils` bodyfile output into a chronological MAC(b) timeline |

## Learning objectives
- Generate a `.plaso` storage file from a mounted artifact set using `log2timeline.py`.
- Convert a `.plaso` file into a filterable CSV super-timeline with `psort.py`.
- Produce a filesystem timeline from a Sleuth Kit bodyfile using `mactime`.
- Filter a super-timeline to a specific date window and identify the earliest suspicious event.

## Environment check
```bash
# Confirm the Plaso tools and Sleuth Kit are installed on LAB-LINUX (SIFT)
log2timeline.py --version
psort.py --version
mactime -V
```
Expected output: `log2timeline.py` and `psort.py` each print a `plaso - ... version YYYYMMDD` banner, and `mactime -V` prints the Sleuth Kit version string (e.g. `The Sleuth Kit ver 4.12.1`). If any command is "not found", install with `sudo apt install plaso sleuthkit`.

## Guided walkthrough
1. `log2timeline.py` — collect timestamped events from a source into a `.plaso` database.
```bash
# Build a .plaso storage file from the benign sample bodyfile-source directory
log2timeline.py --status_view none \
  --storage-file /tmp/case.plaso \
  exercise/artifacts/
```
Expected observable output: a progress summary ending with "Processing completed." and a new `/tmp/case.plaso` file on disk.

2. `psort.py` — sort and export the `.plaso` database to a readable CSV super-timeline.
```bash
# Export everything to CSV, then narrow to a single day with a date filter
psort.py -o l2tcsv -w /tmp/case_timeline.csv /tmp/case.plaso
psort.py -o l2tcsv -w /tmp/case_day.csv /tmp/case.plaso \
  "date > '2023-06-01 00:00:00' AND date < '2023-06-02 00:00:00'"
```
Expected observable output: `psort.py` reports the number of events written; `/tmp/case_timeline.csv` opens with header `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,...`.

3. `mactime` — build a plain filesystem timeline from a Sleuth Kit bodyfile.
```bash
# The sample ships a pre-generated bodyfile; render it as a MACB timeline
mactime -b exercise/bodyfile.txt -d 2023-06-01 > /tmp/fs_timeline.csv
head -n 5 /tmp/fs_timeline.csv
```
Expected observable output: comma-separated rows beginning with the date, MACB flags column (e.g. `m...`, `.a..`), size, and file path.

## Hands-on exercise
Using the sample in this module's `exercise/` directory, build a super-timeline and answer: **What is the date/time of the earliest file-creation ("...b" MACB) event in the timeline, and which file path does it belong to?**

Sample declaration:
- **Type:** Sleuth Kit bodyfile (plain-text pipe-delimited `MD5|name|inode|...|mtime|atime|ctime|crtime` records) named `bodyfile.txt`, plus a small directory `artifacts/` of inert benign log/text files.
- **Safe origin:** Generated on the SIFT VM from a throwaway ext4 loopback image populated with empty benign files (`touch`/`fls`). Contains **no live malware**, no executable payloads, and requires **no network egress** to process.
- **sha256 (bodyfile.txt):** `4f3a9c1e7b2d6058a1c4e93f7d0b8e2a6c5f19d34b7a08e2c1f6935ad84b70e5`

## SOC analyst perspective
In IR the super-timeline is the backbone of the examination phase: after Security Onion alerts on suspicious activity (a Zeek/Suricata hit, a Sigma detection), you pull the endpoint's disk image and run `log2timeline.py` to reconstruct exactly when the intrusion began and how it progressed. Correlating Plaso event times with Security Onion's network PCAP timeline lets you pin process execution and file drops to network callbacks. This directly supports mapping ATT&CK behaviours such as T1070.006 (Timestomp), T1053 (Scheduled Task/Job), and T1547 (Boot/Logon Autostart) by exposing when persistence artifacts were actually written versus their claimed timestamps.

## Attacker perspective
Attackers know timelines betray them, so they actively fight timestamp evidence. Techniques like timestomping (T1070.006) rewrite the Standard-Information $MFT times to blend a malicious binary into an old system-file cluster — but Plaso pulls the $FILE_NAME attribute and multiple independent sources (prefetch, event logs, registry, browser history), so the forged MACB rarely matches every source. An attacker clearing logs (T1070.001) or deleting files still leaves NTFS journal, USN, and shellbag artifacts that log2timeline harvests, meaning the super-timeline often reconstructs deleted activity and exposes the inconsistencies the intruder tried to hide.

## Answer key
Expected finding: the earliest creation event is `2023-06-01 08:14:22` for the path `/var/log/app/install.log` (MACB flag column shows `...b`).

Commands that produce it:
```bash
# Sort the mactime output ascending and grab the first creation-flagged row
mactime -b exercise/bodyfile.txt -d 2023-06-01 \
  | awk -F',' '$3 ~ /b/' | head -n 1

# Cross-check via Plaso: earliest crtime event in the exported CSV
log2timeline.py --status_view none --storage-file /tmp/case.plaso exercise/artifacts/
psort.py -o l2tcsv -w /tmp/case_timeline.csv /tmp/case.plaso
sort -t',' -k1,2 /tmp/case_timeline.csv | grep -m1 'crtime'
```
Expected: both approaches return the `2023-06-01 08:14:22` / `/var/log/app/install.log` row.
Sample sha256 (`bodyfile.txt`): `4f3a9c1e7b2d6058a1c4e93f7d0b8e2a6c5f19d34b7a08e2c1f6935ad84b70e5`

## MITRE ATT&CK & DFIR phase
- **T1070.006** — Indicator Removal: Timestomp (detected via $FILE_NAME vs $STANDARD_INFORMATION discrepancies in the timeline).
- **T1070.001** — Indicator Removal: Clear Windows/Linux logs (residual journal/USN entries recovered).
- **T1053** — Scheduled Task/Job; **T1547** — Boot or Logon Autostart Execution (persistence write times).
- **DFIR phase:** Examination & Analysis (timeline reconstruction), supporting Identification of the earliest compromise indicator.

## Sources
- Plaso / log2timeline official documentation — https://plaso.readthedocs.io/en/latest/
- Plaso `psort` and filters — https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html
- The Sleuth Kit `mactime` manual — https://www.sleuthkit.org/sleuthkit/man/mactime.html
- SANS DFIR "Digital Forensics SIFT'ing: Cheating Timelines with log2timeline" — https://www.sans.org/blog/digital-forensic-sifting-super-timeline-analysis-and-creation/
- MITRE ATT&CK T1070.006 Indicator Removal: Timestomp — https://attack.mitre.org/techniques/T1070/006/
- Kali Tools — Plaso — https://www.kali.org/tools/plaso/
- Kali Tools — Sleuth Kit — https://www.kali.org/tools/sleuthkit/