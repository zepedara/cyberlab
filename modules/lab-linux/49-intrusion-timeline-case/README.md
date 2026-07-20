# 49 * Scenario: intrusion timeline reconstruction -- LAB-LINUX

## Overview (plain language)
When an attacker breaks into a computer, they leave behind a trail: files get created, programs run, registry keys change, and logins happen. Timeline reconstruction is the detective work of putting all those events in the correct order so you can tell the story of what happened, when, and how. This module uses three tools to build that story from a disk image. Plaso (log2timeline) automatically gathers timestamps from hundreds of sources into one big timeline. The Sleuth Kit reads the raw filesystem so you can see files and their creation/modification/access times directly. RegRipper pulls meaningful facts out of Windows registry hives, like which programs auto-start or which USB devices were plugged in. Together they turn a confusing pile of data into a readable, minute-by-minute account of an intrusion.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso | Automated super-timeline creation (log2timeline/psort) across many artifact types |
| RegRipper | apt install regripper | Parse Windows registry hives into human-readable forensic findings |
| Sleuth Kit | apt install sleuthkit | Command-line filesystem forensics: list files, recover deleted data, produce timelines |

## Learning objectives
- Generate a Plaso storage file from a disk image and export a filtered CSV super-timeline.
- Use Sleuth Kit (`fls`/`mactime`) to produce a filesystem MAC-time bodyfile and timeline.
- Extract autostart and USB artifacts from a registry hive with RegRipper and place them on the timeline.
- Correlate events from all three tools to reconstruct the sequence of an intrusion.
- Identify the DFIR examination phase and map findings to MITRE ATT&CK techniques.

## Environment check
```bash
# Prove the three tools are installed on LAB-LINUX (SIFT)
log2timeline.py --version
psort.py --version
fls -V
mactime -V
rip.pl -h | head -n 3
```
Expected output: Plaso prints its version (e.g. `plaso - log2timeline version 20230717`), `fls`/`mactime` print The Sleuth Kit version banner, and `rip.pl -h` prints RegRipper usage text.

## Guided walkthrough
1. `fls` lists filename entries with inode/MAC times; piping to `mactime` builds a chronological timeline.
```bash
# Build a Sleuth Kit bodyfile from a raw image, then a mactime timeline
fls -r -m C: -o 2048 disk.raw > bodyfile.txt
mactime -b bodyfile.txt -d 2024-01-01 > sk_timeline.csv
head -n 5 sk_timeline.csv
```
Expected output: `bodyfile.txt` contains pipe-delimited MD5|name|inode|mode|... lines; `sk_timeline.csv` shows date-sorted rows of file activity.

2. `log2timeline.py` parses the image into a Plaso storage file; `psort.py` filters and exports it.
```bash
# Create the Plaso super-timeline, then export a date-scoped CSV
log2timeline.py --storage-file timeline.plaso disk.raw
psort.py -o l2tcsv -w super_timeline.csv timeline.plaso \
  "date > '2024-01-10 00:00:00' AND date < '2024-01-12 00:00:00'"
wc -l super_timeline.csv
```
Expected output: Plaso reports events extracted; `super_timeline.csv` holds l2tcsv rows for the scoped window.

3. `rip.pl` runs registry plugins to surface autostart and device artifacts.
```bash
# Extract autostart programs and USB device history from a registry hive
rip.pl -r NTUSER.DAT -p run
rip.pl -r SYSTEM -p usbstor
```
Expected output: RegRipper prints Run-key values (auto-start programs) and USBSTOR device entries with last-write timestamps.

## Hands-on exercise
Sample artifact: `exercise/intrusion_bodyfile.txt` — a **benign, inert Sleuth Kit bodyfile** (plain text, no executable content, no live malware). It is safely generated offline (no network egress) by the reproducible generator below, which fabricates a small MAC-time record simulating an attacker dropping `evil.exe` and modifying `hosts`.

Generator (run inside the module's `exercise/` dir):
```bash
cat > intrusion_bodyfile.txt <<'EOF'
0|C:/Windows/Temp/evil.exe|4128|r/rrwxrwxrwx|0|0|73216|1705032000|1705032000|1705032000|1705032000
0|C:/Windows/System32/drivers/etc/hosts|4130|r/rrwxrwxrwx|0|0|824|1705032600|1705032600|1704000000|1704000000
0|C:/Users/analyst/NTUSER.DAT|4200|r/rrwxrwxrwx|0|0|262144|1705033200|1705033200|1705033200|1704000000
EOF
sha256sum intrusion_bodyfile.txt
```
Tasks:
1. Convert the bodyfile into a human-readable timeline with `mactime`.
2. Identify the first-created suspicious file and its epoch/date.
3. Determine which file was modified but has an older creation time (indicating tampering).

## SOC analyst perspective
A defender uses timeline reconstruction during incident response to answer "patient zero and dwell time" questions. In Security Onion you may first spot an alert (e.g. a Zeek or Suricata detection) and pivot to the host's disk image, where Plaso and Sleuth Kit stitch endpoint events into an order that matches network telemetry. Correlating a Run-key value from RegRipper (ATT&CK T1547.001) with a suspicious `.exe` creation time and a subsequent outbound connection lets the analyst confirm persistence and lateral movement. Timelines also feed Security Onion case notes and help scope which hosts and time windows need containment, and provide defensible chronology for reporting.

## Attacker perspective
An attacker leaves timestamps everywhere: dropping a payload updates a file's creation/modification MAC times, writing a Run key changes a hive's LastWrite time, and plugging a USB device registers a USBSTOR entry. Sophisticated actors use timestomping (ATT&CK T1070.006) to alter `$STANDARD_INFORMATION` times so files appear old — but the `$FILE_NAME` attribute and journal often retain the real times, which Sleuth Kit and Plaso can surface, exposing the manipulation. Clearing event logs (T1070.001) removes some sources, yet registry LastWrite times and filesystem metadata frequently survive, giving investigators independent artifacts to rebuild the true sequence of events.

## Answer key
Expected findings from the sample (`exercise/intrusion_bodyfile.txt`):
```bash
mactime -b exercise/intrusion_bodyfile.txt -d 2024-01-01 | head
```
- First suspicious file created: `C:/Windows/Temp/evil.exe` at epoch `1705032000` = **2024-01-12 04:00:00 UTC** (all four MAC times equal → freshly dropped).
- Tampered file: `C:/Windows/System32/drivers/etc/hosts` — modified at `1705032600` but with an older creation time `1704000000`, indicating the attacker altered an existing system file.
- The `NTUSER.DAT` entry shows a modification (`1705033200`) newer than its birth time (`1704000000`), consistent with a Run-key persistence write that RegRipper's `run` plugin would reveal.

Sample sha256: reproduce with the generator's `sha256sum intrusion_bodyfile.txt`; the digest is held by the validator (regenerate deterministically from the provided heredoc, which produces identical bytes).

## MITRE ATT&CK & DFIR phase
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys (RegRipper `run`).
- **T1070.006** — Indicator Removal: Timestomp (detected via MAC-time inconsistencies).
- **T1070.001** — Indicator Removal: Clear Windows Event Logs.
- **T1091 / USBSTOR** — Replication/Device history (RegRipper `usbstor`).
- **DFIR phase:** Examination and Analysis (timeline reconstruction / correlation) following Identification.

## Sources
- SANS DFIR — "Digital Forensics SIFT'ing: Cheating Timelines with log2timeline": https://www.sans.org/blog/digital-forensics-sifting-cheating-timelines-with-log2timeline/
- Plaso documentation (log2timeline/psort): https://plaso.readthedocs.io/
- The Sleuth Kit `fls` / `mactime` documentation: https://sleuthkit.org/sleuthkit/docs.php
- RegRipper project: https://github.com/keydet89/RegRipper3.0
- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- MITRE ATT&CK techniques T1547.001, T1070.006, T1070.001: https://attack.mitre.org/techniques/T1547/001/