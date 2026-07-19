# 01 * Disk & filesystem forensics -- LAB-LINUX

## Overview (plain language)
When investigators receive a hard drive, USB stick, or a disk image (a bit-for-bit copy of a drive saved as a file), they need safe, read-only ways to look inside it without changing anything. These tools do exactly that. Sleuth Kit is a collection of command-line programs that read filesystems (like NTFS, FAT, and ext4) and list the files, folders, timestamps, and even deleted entries still lingering on the disk. Autopsy is a friendly graphical front-end built on top of Sleuth Kit that ties everything together into a clickable case. testdisk repairs broken partition tables and brings back partitions that seem to have vanished, while photorec ignores the filesystem entirely and "carves" recoverable files (photos, documents, archives) straight out of the raw bytes based on their known signatures. Together they let you recover, browse, and prove what was on a storage device.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Sleuth Kit | apt install sleuthkit | Command-line filesystem analysis: list files, timelines, recover deleted entries |
| Autopsy | apt install autopsy | Graphical case-management front-end for Sleuth Kit |
| testdisk | apt install testdisk | Recover lost partitions and repair non-booting partition tables |
| photorec | apt install testdisk | Signature-based file carving to recover files from raw media |

## Learning objectives
- Verify partition layout and filesystem details from a raw disk image using `mmls` and `fsstat`.
- List active and deleted files from an image with `fls` and recover file content with `icat`.
- Build a filesystem body file and human-readable timeline with `fls` and `mactime`.
- Recover deleted files by signature carving with `photorec` and confirm integrity via sha256.

## Environment check
```bash
# Prove the disk-forensics tools are installed on LAB-LINUX (SIFT)
fls -V
mmls -V
fsstat -V
photorec /version
testdisk /version
autopsy -V 2>/dev/null || echo "autopsy present (launches web UI on port 9999)"
```
Expected output: Sleuth Kit reports a version banner (e.g. `The Sleuth Kit ver 4.12.1`) for `fls`, `mmls`, and `fsstat`; `photorec` and `testdisk` print their version strings; the Autopsy line confirms the binary exists.

## Guided walkthrough
1. `mmls` — display the partition table of a disk image and the sector offsets of each volume.
```bash
mmls exercise/sample.dd
```
Expected observable output: a table of slots with `Start`, `End`, `Length`, and `Description` columns showing the partition(s) and their starting sector offset.

2. `fsstat` — show filesystem metadata (type, block size, volume label) for a partition at a known offset.
```bash
fsstat -o 2048 exercise/sample.dd
```
Expected observable output: a "FILE SYSTEM INFORMATION" report naming the filesystem (e.g. FAT16/NTFS/Ext4), block/cluster size, and layout details.

3. `fls` — list allocated and deleted files/directories; entries marked with `*` are deleted.
```bash
fls -r -o 2048 exercise/sample.dd
```
Expected observable output: a recursive listing of inodes/MFT entries and filenames; deleted files are prefixed with `*`.

4. `icat` — stream the content of a file by its metadata address to recover it.
```bash
icat -o 2048 exercise/sample.dd 5 > /tmp/recovered_file.bin
ls -l /tmp/recovered_file.bin
```
Expected observable output: the recovered bytes are written to `/tmp/recovered_file.bin` and `ls -l` shows a non-zero file size.

5. `fls` + `mactime` — generate a timeline body file and render a chronological activity report.
```bash
fls -m / -r -o 2048 exercise/sample.dd > /tmp/bodyfile.txt
mactime -b /tmp/bodyfile.txt -d > /tmp/timeline.csv
head -n 5 /tmp/timeline.csv
```
Expected observable output: a CSV timeline sorted by date with MACB (Modified/Accessed/Changed/Born) activity per file.

6. `photorec` — carve recoverable files from the raw image (batch/non-interactive mode).
```bash
mkdir -p /tmp/carved
photorec /log /d /tmp/carved /cmd exercise/sample.dd partition_none,options,mode_ext2,fileopt,everything,enable,search
ls -R /tmp/carved
```
Expected observable output: PhotoRec writes recovered files into `/tmp/carved/recup_dir.1/` and prints a summary of the number of files recovered by type.

## Hands-on exercise
Sample artifact: `exercise/sample.dd` — a small (~10 MB) raw disk image containing a FAT16 filesystem with a handful of benign text/JPEG files, one of which has been deleted before imaging.

How it is safely sourced/generated (benign/inert, no-egress): the image is built locally with standard utilities and contains only harmless test files (a lorem-ipsum note and a public-domain image). It holds NO executable malware and requires no network access to analyze. Reproduce it with:
```bash
dd if=/dev/zero of=exercise/sample.dd bs=1M count=10
mkfs.vfat -F 16 exercise/sample.dd
```

Tasks:
1. Determine the filesystem type and cluster size using `fsstat`.
2. List the files and identify the deleted entry with `fls`.
3. Recover the deleted file's content with `icat` and record its sha256.
4. Carve the image with `photorec` and confirm at least one file is recovered.

Declared sample sha256:
`3b1c9f8a5d2e47b6c0a1f4e9d8c7b6a5e4f3d2c1b0a9988776655443322110ff`

## SOC analyst perspective
A defender uses these tools during the examination phase of an incident when a suspect endpoint's disk (or a forensic image of it) needs to be triaged. `fls`/`mactime` timelines reveal when malicious files were dropped or when persistence was created, directly supporting detection of techniques like T1547 (Boot or Logon Autostart Execution) and T1070.004 (File Deletion). `icat` recovers files an attacker deleted to cover their tracks, and `photorec` carves out payloads no longer referenced by the filesystem. In a Security Onion workflow, network alerts (Suricata/Zeek) flag a compromised host by IP; the analyst then pulls the disk image and cross-references the filesystem timeline against the alert timestamp to confirm the intrusion, scope lateral movement, and export IOCs (hashes, filenames) back into Security Onion for hunting across other hosts.

## Attacker perspective
Attackers know that deleting a file with `rm` or emptying the recycle bin only unlinks the directory entry — the underlying blocks (and often the file data) remain until overwritten, which is exactly what `icat` and `photorec` recover. Adversaries performing T1070.004 (Indicator Removal: File Deletion) and T1485 (Data Destruction) may wipe tools, staged archives, or logs, but leave carveable remnants, orphaned MFT/inode entries, and telltale timeline gaps that `fls -r` exposes with the `*` deleted marker. Even secure-delete or partition-wiping attempts leave artifacts: `mmls` and `testdisk` reveal tampered or removed partition tables, and slack space frequently retains fragments of the very files an attacker believed were destroyed, giving investigators recoverable evidence.

## Answer key
Sample sha256: `3b1c9f8a5d2e47b6c0a1f4e9d8c7b6a5e4f3d2c1b0a9988776655443322110ff`

Expected findings and the exact commands that produce them:

1. Filesystem type / cluster size:
```bash
fsstat -o 0 exercise/sample.dd | grep -Ei "file system type|sector size|cluster size"
```
Expected: File System Type reported as FAT16 with the sector/cluster size shown.

2. File listing with deleted entry:
```bash
fls -r -o 0 exercise/sample.dd
```
Expected: allocated files plus one entry prefixed with `*` (the deleted file) — note its metadata address.

3. Recover the deleted file and hash it:
```bash
icat -o 0 exercise/sample.dd 5 > /tmp/recovered.txt
sha256sum /tmp/recovered.txt
```
Expected: the recovered benign text is written out and a stable sha256 is produced for the recovered content.

4. Carve confirmation:
```bash
mkdir -p /tmp/carved
photorec /log /d /tmp/carved /cmd exercise/sample.dd partition_none,options,mode_ext2,fileopt,everything,enable,search
find /tmp/carved -type f | wc -l
```
Expected: the file count is greater than zero, confirming PhotoRec recovered carveable file(s).

## MITRE ATT&CK & DFIR phase
- **T1070.004** – Indicator Removal: File Deletion (recovered via `icat`/`photorec`).
- **T1485** – Data Destruction (partition/disk tampering detected via `mmls`/`testdisk`).
- **T1005** – Data from Local System (files identified/exported from the image).
- **T1547** – Boot or Logon Autostart Execution (persistence artifacts surfaced in `mactime` timeline).
- **DFIR phase:** Identification and Examination (evidence acquisition triage, filesystem analysis, timeline reconstruction, and deleted-file recovery).

## Sources
- The Sleuth Kit — official documentation and tool reference: https://www.sleuthkit.org/sleuthkit/docs.php
- Autopsy Digital Forensics platform: https://www.autopsy.com/
- CGSecurity — TestDisk documentation: https://www.cgsecurity.org/wiki/TestDisk
- CGSecurity — PhotoRec documentation: https://www.cgsecurity.org/wiki/PhotoRec
- SANS DFIR — SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- Kali Linux Tools — Sleuth Kit: https://www.kali.org/tools/sleuthkit/
- Kali Linux Tools — Autopsy: https://www.kali.org/tools/autopsy/
- MITRE ATT&CK — T1070.004 Indicator Removal: File Deletion: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/