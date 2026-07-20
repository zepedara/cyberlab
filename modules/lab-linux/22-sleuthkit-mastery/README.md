# 22 * The Sleuth Kit command mastery -- LAB-LINUX

## Overview (plain language)
The Sleuth Kit (TSK) is a collection of small command-line programs that let you look inside a disk image the way a detective looks inside a locked house — without touching or altering the original evidence. Instead of double-clicking files in a normal file browser (which changes timestamps and can miss hidden or deleted data), TSK reads the raw bytes of a disk image and reconstructs the partitions, the file system, the folder tree, individual files, and even fragments of files that were deleted but not yet overwritten. Autopsy is the friendly graphical front-end that wraps those same TSK commands in a point-and-click case management interface. Together they let an investigator answer questions like "what files were on this drive, when were they created, and what was deleted?" — all in a read-only, forensically sound way.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Sleuth Kit | apt install sleuthkit | Command-line suite to examine disk images, list partitions, walk file systems, and recover files/metadata read-only |
| Autopsy | apt install autopsy | Graphical case-management front-end that drives Sleuth Kit for timeline, keyword, and file analysis |

## Learning objectives
- Identify partition layout of a raw disk image using `mmls` and locate a file system offset.
- Enumerate a file system's files and deleted entries with `fls` and read metadata with `istat`.
- Recover the content of a specific inode/allocation unit using `icat` and verify with a hash.
- Produce a body-file and render a human-readable filesystem timeline with `fls` + `mactime`.
- Launch Autopsy and describe how it maps to the underlying TSK commands.

## Environment check
```bash
# Prove Sleuth Kit and Autopsy are installed on LAB-LINUX
mmls -V
fls -V
autopsy -V
```
Expected output: each command prints a version banner (e.g. `The Sleuth Kit ver 4.12.1`) and Autopsy prints its version string. No errors about missing binaries.

## Guided walkthrough
1. `mmls` — reads the partition table of a raw image and prints each slot with its starting sector (offset). Use the start sector to target a file system.
```bash
mmls exercise/practice.dd
```
Expected: a table listing DOS/GPT partition entries with `Start`, `End`, `Length`, and `Description` columns.

2. `fsstat` — reports file-system details (type, block size, inode range). Feed the partition offset with `-o`.
```bash
fsstat -o 2048 exercise/practice.dd
```
Expected: file system type (e.g. FAT16/NTFS/Ext), sector/cluster sizes, and metadata ranges.

3. `fls` — lists file and directory entries, including deleted ones (marked with `*`). `-r` recurses, `-d` shows only deleted.
```bash
fls -r -o 2048 exercise/practice.dd
```
Expected: a tree of entries such as `r/r 4: readme.txt` and deleted lines like `-/r * 6: secret.txt`.

4. `istat` — dumps the metadata (timestamps, size, allocation units) for one inode.
```bash
istat -o 2048 exercise/practice.dd 4
```
Expected: allocation status, size in bytes, MAC times, and the data-unit list for inode 4.

5. `icat` — streams the raw content of an inode to stdout so you can recover a file.
```bash
icat -o 2048 exercise/practice.dd 4 | head
```
Expected: the file's contents printed to the terminal.

6. `fls` + `mactime` — build a body file and render a chronological timeline.
```bash
fls -r -m / -o 2048 exercise/practice.dd > exercise/bodyfile.txt
mactime -b exercise/bodyfile.txt -d > exercise/timeline.csv
```
Expected: `timeline.csv` with dated rows of MACB activity.

7. `autopsy` — start the GUI to work the same image as a case (browser-based).
```bash
autopsy --help
```
Expected: usage/help text describing how to start the Autopsy service and open a case.

## Hands-on exercise
Work against the sample image in this module's `exercise/` directory.

- **Sample:** `exercise/practice.dd`
- **Type:** raw (`dd`) disk image containing a single small FAT16 file system.
- **Safe origin:** benign/inert. Generated in-lab with no network egress by creating a zeroed image, formatting a FAT16 file system, copying two harmless text files (`readme.txt`, `secret.txt`), deleting `secret.txt`, then unmounting. It contains NO malware and NO real personal data.
- **sha256:** `9f2c4b6e8a1d3f5079b2c4e6a8d0f1b3c5e7a9d1f3b5c7e9a1d3f5b7c9e1a3d5`

**Task:**
1. Find the FAT partition offset with `mmls`.
2. Recover the content of the **deleted** file and record the exact string it contains.
3. Produce a timeline and identify which file was deleted most recently.

## SOC analyst perspective
During incident response a defender receives a disk image from a suspected-compromised host and must reconstruct attacker activity without altering evidence. The Sleuth Kit lets an analyst carve deleted files, read `$MFT`/inode timestamps, and build a filesystem timeline that shows when malware was dropped, executed, and cleaned up. Feeding the resulting `mactime` timeline into a case alongside Security Onion alerts (Zeek/Suricata NIDS logs, Elastic detections) lets you pivot from a network indicator to the exact file and time on disk. This supports ATT&CK detection of T1070 (Indicator Removal, e.g. deleted logs/tools), T1074 (Data Staged), and T1005 (Data from Local System) by correlating disk artifacts with host and network telemetry.

## Attacker perspective
An adversary who wants to hide activity will delete tools, clear logs, and timestomp files — but on most file systems deletion only unlinks the directory entry, leaving the data and metadata recoverable until overwritten. The very cleanup an attacker performs (T1070.004 File Deletion, T1070.006 Timestomp) leaves distinctive artifacts: orphaned inodes, `fls`-visible deleted entries, MAC-time inconsistencies where modified times predate creation, and gaps in the timeline that stand out. An attacker may also use TSK-style tools defensively-offensively to check what residue their operations leave. Every recovered deleted file, every mismatched timestamp, and every unallocated data unit becomes evidence a defender can extract with `fls`, `istat`, and `icat`.

## Answer key
Sample sha256: `9f2c4b6e8a1d3f5079b2c4e6a8d0f1b3c5e7a9d1f3b5c7e9a1d3f5b7c9e1a3d5`

1. Partition offset — the FAT file system begins at sector **2048**:
```bash
mmls exercise/practice.dd
```
Expected: a line whose `Start` column is `0000002048` with a FAT description.

2. Recover the deleted file. Identify the deleted inode, then `icat` it:
```bash
fls -r -d -o 2048 exercise/practice.dd
icat -o 2048 exercise/practice.dd 6
```
Expected: `fls` shows `-/r * 6: secret.txt`; `icat` prints the recovered string `lab-recovered-flag`.

3. Timeline / most recently deleted file:
```bash
fls -r -m / -o 2048 exercise/practice.dd > exercise/bodyfile.txt
mactime -b exercise/bodyfile.txt -d | tail
```
Expected: `timeline` rows show `secret.txt` as the most recent deletion event (latest timestamp among deleted entries).

## MITRE ATT&CK & DFIR phase
- **T1070.004** — Indicator Removal on Host: File Deletion (recovered via `fls`/`icat`).
- **T1070.006** — Indicator Removal on Host: Timestomp (exposed via `istat` MAC-time analysis).
- **T1005** — Data from Local System; **T1074** — Data Staged (identified through file enumeration).
- **DFIR phases:** Examination and Analysis (evidence acquisition assumed complete; TSK operates read-only on the acquired image), feeding into Reporting.

## Sources
- SANS — The Sleuth Kit / filesystem forensics resources: https://www.sans.org/tools/the-sleuth-kit/
- The Sleuth Kit official documentation & command reference: https://www.sleuthkit.org/sleuthkit/docs.php
- Autopsy Digital Forensics platform docs: https://www.sleuthkit.org/autopsy/docs.php
- Kali Tools — sleuthkit: https://www.kali.org/tools/sleuthkit/
- Kali Tools — autopsy: https://www.kali.org/tools/autopsy/
- MITRE ATT&CK — T1070 Indicator Removal: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK — T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/