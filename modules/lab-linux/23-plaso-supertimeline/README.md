# 23 * Plaso super-timeline deep-dive -- LAB-LINUX

## Overview (plain language)
When you investigate a hacked or infected computer, one of the hardest questions is "what happened, and in what order?" Every file, log, browser visit, and registry change leaves a tiny timestamp behind, scattered across dozens of different places. Plaso (with its command-line front-end log2timeline) is a tool that automatically reads all of those scattered time records from a disk image and merges them into one giant, sortable list called a "super-timeline." mactime is an older, simpler companion that turns filesystem time data into a readable day-by-day report. Together they let an analyst press play on a machine's history and watch events unfold minute by minute instead of guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso | Framework that parses many artifact types into a single timeline storage file (.plaso) and exports it ([plaso.readthedocs.io](https://plaso.readthedocs.io/en/latest/)) |
| log2timeline | apt install plaso | The `log2timeline.py` collection engine that walks an image/mount/directory and extracts timestamped events into a `.plaso` file ([plaso.readthedocs.io — Using log2timeline](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html)) |
| mactime | apt install sleuthkit | Converts a Sleuth Kit `fls`/`ils` body file into an ASCII, chronological MAC(b) timeline ([sleuthkit.org — mactime](https://www.sleuthkit.org/sleuthkit/man/mactime.html)) |

Note: Plaso also ships `psort.py` (sort/filter/export) and `pinfo.py` (inspect a `.plaso` file); both are part of the `plaso` package ([plaso.readthedocs.io — Using psort](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html)).

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
Expected output: `log2timeline.py` and `psort.py` each print a `plaso - ... version YYYYMMDD` banner (Plaso releases are date-versioned, e.g. `20230717`, per the [Plaso releases page](https://github.com/log2timeline/plaso/releases)), and `mactime -V` prints the Sleuth Kit version string (e.g. `The Sleuth Kit ver 4.12.1` — current releases are listed on the [Sleuth Kit GitHub releases](https://github.com/sleuthkit/sleuthkit/releases)). If any command is "not found", install with `sudo apt install plaso sleuthkit` ([kali.org/tools/plaso](https://www.kali.org/tools/plaso/), [kali.org/tools/sleuthkit](https://www.kali.org/tools/sleuthkit/)).

## Guided walkthrough
1. `log2timeline.py` — collect timestamped events from a source into a `.plaso` database.
```bash
# Build a .plaso storage file from the benign sample bodyfile-source directory
log2timeline.py --status_view none \
  --storage-file /tmp/case.plaso \
  exercise/artifacts/
```
Why: `log2timeline.py` runs its parsers/plugins over the *source* (a directory, a mounted filesystem, or a raw/E01 image) and writes every extracted event into the `.plaso` storage file; the storage file is an intermediate database, NOT yet a readable timeline — you export it later with `psort.py`. `--storage-file` names the output; the trailing positional argument is the source path. `--status_view none` suppresses the interactive live status window so the command is script/log friendly (the default is a `window`/`linear` progress view) ([plaso.readthedocs.io — Using log2timeline](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html)). Expected observable output: a progress summary ending with "Processing completed." and a new `/tmp/case.plaso` file on disk. Nuance: log2timeline auto-detects source type and selects an appropriate parser preset; on a directory it applies file/generic parsers rather than the full disk-image parser set, so event counts are smaller than on a mounted image.

2. `psort.py` — sort and export the `.plaso` database to a readable CSV super-timeline.
```bash
# Export everything to CSV, then narrow to a single day with a date filter
psort.py -o l2tcsv -w /tmp/case_timeline.csv /tmp/case.plaso
psort.py -o l2tcsv -w /tmp/case_day.csv /tmp/case.plaso \
  "date > '2023-06-01 00:00:00' AND date < '2023-06-02 00:00:00'"
```
Why: `psort.py` reads the `.plaso` storage file, sorts events chronologically, applies an optional event-filter expression (the quoted final argument), and writes them out in the chosen output format. `-o l2tcsv` selects the classic log2timeline CSV output module and `-w` names the output file; the trailing quoted string is a filter using psort's date/field syntax ([plaso.readthedocs.io — Using psort](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html), [Filters](https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html)). Expected observable output: `psort.py` reports the number of events written; `/tmp/case_timeline.csv` opens with the l2tcsv header `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`. Nuance: psort de-duplicates near-identical events by default, so the exported line count is typically lower than the raw event count reported by `log2timeline.py` — this is expected, not data loss.

3. `mactime` — build a plain filesystem timeline from a Sleuth Kit bodyfile.
```bash
# The sample ships a pre-generated bodyfile; render it as a MACB timeline
mactime -b exercise/bodyfile.txt -d 2023-06-01 > /tmp/fs_timeline.csv
head -n 5 /tmp/fs_timeline.csv
```
Why: `mactime` takes a Sleuth Kit **body file** (`-b`) — the pipe-delimited output of `fls`/`ils` — and collapses the four MAC(b) times per file into one chronological listing, where each row's `MACB` column marks which of Modified/Accessed/Changed/Birth(created) times fired at that instant. `-d` requests comma-delimited (CSV) output rather than the default fixed-width text ([sleuthkit.org — mactime](https://www.sleuthkit.org/sleuthkit/man/mactime.html)). Expected observable output: comma-separated rows beginning with the date, MACB flags column (e.g. `m...`, `.a..`, `...b`), size, and file path. Nuance: `mactime` groups events that share the same timestamp onto one line and only reflects the four filesystem times in the body file — it does not add application/registry artifacts the way Plaso does, which is why the two tools complement each other.

## Hands-on exercise
Using the sample in this module's `exercise/` directory, build a super-timeline and answer: **What is the date/time of the earliest file-creation ("...b" MACB) event in the timeline, and which file path does it belong to?**

Sample declaration:
- **Type:** Sleuth Kit bodyfile (plain-text pipe-delimited `MD5|name|inode|...|mtime|atime|ctime|crtime` records) named `bodyfile.txt`, plus a small directory `artifacts/` of inert benign log/text files. (Body file column layout per [sleuthkit.org — body file format](https://wiki.sleuthkit.org/index.php?title=Body_file).)
- **Safe origin:** Generated on the SIFT VM from a throwaway ext4 loopback image populated with empty benign files (`touch`/`fls`). Contains **no live malware**, no executable payloads, and requires **no network egress** to process.
- **sha256 (bodyfile.txt):** `ad0a859947384b0ad9e942aaa37633ba181b3f2c701d0d3e72ef3265a48fba8d`

## SOC analyst perspective
In IR the super-timeline is the backbone of the examination phase: after Security Onion alerts on suspicious activity (a Suricata IDS hit, a Zeek log anomaly, or a Sigma-based detection surfaced in the Alerts interface), you pull the endpoint's disk image and run `log2timeline.py` to reconstruct exactly when the intrusion began and how it progressed ([securityonion.net docs](https://docs.securityonion.net/en/2.4/)). Concrete pivots:

- **Time-anchor the network to the disk.** Take the connection time from a Zeek `conn.log` / Suricata alert in Security Onion and filter the Plaso CSV to a tight window around it (`psort.py ... "date > '...' AND date < '...'"`) to find the file drop or process-execution artifact that immediately preceded the callback. Zeek and Suricata logs are viewable/pivotable in Kibana/Elastic within Security Onion ([Security Onion — Zeek](https://docs.securityonion.net/en/2.4/zeek.html), [Suricata](https://docs.securityonion.net/en/2.4/suricata.html)).
- **Detect timestomping (T1070.006).** In the timeline, compare NTFS `$STANDARD_INFORMATION` vs `$FILE_NAME` times for the same file; a `$SI` time older than the `$FN` time, or sub-second-zeroed `$SI` timestamps, is a classic timestomp tell. Plaso's `filestat`/NTFS parsers surface both attribute sets ([plaso.readthedocs.io](https://plaso.readthedocs.io/en/latest/)); the discrepancy is the documented detection for T1070.006 ([attack.mitre.org/techniques/T1070/006](https://attack.mitre.org/techniques/T1070/006/)).
- **Detect log clearing (T1070.001).** A gap in the Windows Security log paired with Event ID 1102 ("audit log was cleared") is the primary signal; Security Onion ingests Windows event logs so this can be alerted/hunted in Elastic ([attack.mitre.org/techniques/T1070/001](https://attack.mitre.org/techniques/T1070/001/)).
- **Persistence timing.** For T1053.005 (Scheduled Task) and T1547.001 (Registry Run Keys / Startup Folder), the timeline exposes when the Task XML, `at`/`cron` entry, or `Run` key value was actually written versus its claimed metadata ([T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/)).

This workflow follows the SANS super-timeline analysis method ([SANS DFIR — super-timeline analysis](https://www.sans.org/blog/digital-forensic-sifting-super-timeline-analysis-and-creation/)).

## Attacker perspective
Attackers know timelines betray them, so they actively fight timestamp evidence. Concrete TTPs and their residue:

- **Timestomping (T1070.006).** Tooling (e.g. the Metasploit `timestomp` module, or PowerShell setting `[IO.File]::SetCreationTime`) rewrites the NTFS `$STANDARD_INFORMATION` M/A/C/B times so a malicious binary blends into an old system-file cluster. Weakness: the `$FILE_NAME` attribute is not writable by these user-mode techniques and is captured separately by Plaso, so the forged `$SI` MACB rarely matches `$FN`, and it almost never matches independent sources (Prefetch, `Amcache.hve`, Windows event logs, `$UsnJrnl`, browser history) that Plaso also harvests ([T1070.006](https://attack.mitre.org/techniques/T1070/006/), [plaso.readthedocs.io](https://plaso.readthedocs.io/en/latest/)).
- **Log clearing / file deletion (T1070.001, T1070.004).** Clearing the Windows event log (leaving Event ID 1102) or deleting a dropper does not erase the NTFS change journal (`$UsnJrnl:$J`), `$LogFile`, `$MFT` resident/unallocated entries, Registry shellbags, or Prefetch — all of which log2timeline parses, so deleted activity is frequently reconstructed ([T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/)).
- **Persistence footprints.** A scheduled task writes an XML under `C:\Windows\System32\Tasks\` and registers keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` (T1053.005); a Run-key implant writes to `HKCU\...\CurrentVersion\Run` (T1547.001). Both create hive write-times the timeline records even when the payload's own timestamps are forged ([T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/)).
- **Evasion limits.** The only robust evasion is anti-forensics against ALL sources simultaneously (kernel-level time hooks, wiping the change journal, disabling Prefetch/logging beforehand) — expensive, noisy, and itself an anomaly. The super-timeline's strength is cross-source correlation: it surfaces the inconsistency the intruder could not scrub everywhere at once.

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
Sample sha256 (`bodyfile.txt`): `ad0a859947384b0ad9e942aaa37633ba181b3f2c701d0d3e72ef3265a48fba8d`

## MITRE ATT&CK & DFIR phase
- **T1070.006** — Indicator Removal: Timestomp (detected via `$FILE_NAME` vs `$STANDARD_INFORMATION` discrepancies in the timeline) — https://attack.mitre.org/techniques/T1070/006/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs (residual journal/USN entries and Event ID 1102 recovered) — https://attack.mitre.org/techniques/T1070/001/
- **T1070.004** — Indicator Removal: File Deletion (deleted droppers reconstructed from `$UsnJrnl`/`$MFT`) — https://attack.mitre.org/techniques/T1070/004/
- **T1053.005** — Scheduled Task/Job: Scheduled Task; **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (persistence write times) — https://attack.mitre.org/techniques/T1053/005/ , https://attack.mitre.org/techniques/T1547/001/
- **DFIR phase:** Examination & Analysis (timeline reconstruction), supporting Identification of the earliest compromise indicator.

## Sources
Claim → source mapping (all URLs are official tool docs / repos, MITRE ATT&CK, SANS, or recognized project docs):

- Plaso is a framework that parses many artifacts into a `.plaso` storage file and exports it — Plaso official docs: https://plaso.readthedocs.io/en/latest/
- `log2timeline.py` collection engine, `--storage-file`, positional source, `--status_view` behavior, source auto-detection — Plaso "Using log2timeline": https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html
- `psort.py` sort/export, `-o l2tcsv`, `-w`, event-filter syntax, l2tcsv header fields, de-duplication — Plaso "Using psort": https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html and "Event filters": https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html
- Plaso date-based release/version scheme (banner format) — Plaso releases: https://github.com/log2timeline/plaso/releases
- `mactime` builds a MAC(b) timeline from a Sleuth Kit body file; `-b`, `-d` (comma-delimited) flags — Sleuth Kit `mactime` manual: https://www.sleuthkit.org/sleuthkit/man/mactime.html
- Sleuth Kit body file column layout (`MD5|name|inode|...|mtime|atime|ctime|crtime`) — Sleuth Kit wiki, Body file format: https://wiki.sleuthkit.org/index.php?title=Body_file
- Sleuth Kit version string / current releases — Sleuth Kit GitHub releases: https://github.com/sleuthkit/sleuthkit/releases
- Install packages on Kali/SIFT — Kali Tools Plaso: https://www.kali.org/tools/plaso/ ; Kali Tools Sleuth Kit: https://www.kali.org/tools/sleuthkit/
- Super-timeline analysis methodology — SANS DFIR "Digital Forensic SIFTing: Super Timeline Analysis and Creation": https://www.sans.org/blog/digital-forensic-sifting-super-timeline-analysis-and-creation/
- Security Onion ingestion/pivots (Zeek, Suricata, Elastic/Kibana) — Security Onion docs: https://docs.securityonion.net/en/2.4/ ; Zeek: https://docs.securityonion.net/en/2.4/zeek.html ; Suricata: https://docs.securityonion.net/en/2.4/suricata.html
- T1070.006 Timestomp (detection via `$SI` vs `$FN`) — MITRE ATT&CK: https://attack.mitre.org/techniques/T1070/006/
- T1070.001 Clear Windows Event Logs (Event ID 1102) — MITRE ATT&CK: https://attack.mitre.org/techniques/T1070/001/
- T1070.004 File Deletion — MITRE ATT&CK: https://attack.mitre.org/techniques/T1070/004/
- T1053.005 Scheduled Task (Tasks path / TaskCache) — MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/
- T1547.001 Registry Run Keys / Startup Folder — MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/

## Related modules
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- shares log2timeline as the core timeline engine.
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- applies plaso end-to-end in a full intrusion case.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); memory-side timeline correlation.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); pairs signatures with timeline findings.

<!-- cyberlab-enriched: v1 -->
