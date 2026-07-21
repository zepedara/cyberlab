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

Notes on the table (verified against project docs): The Sleuth Kit is a C library and collection of command-line tools that analyze disk images and recover files from them; the tool list (`mmls`, `fsstat`, `fls`, `icat`, `mactime`, etc.) is documented at the project site (https://www.sleuthkit.org/sleuthkit/tools.php). PhotoRec ships inside the same `testdisk` package on Debian/Kali — a single upstream project by CGSecurity — which is why both tools share the `apt install testdisk` install line (https://www.cgsecurity.org/wiki/PhotoRec and https://www.kali.org/tools/testdisk/). On the legacy Autopsy 2.x shipped in the Debian/Kali `autopsy` package, the interface is a local web UI that binds to `http://localhost:9999/autopsy` (https://www.kali.org/tools/autopsy/); the modern cross-platform GUI is Autopsy 4.x from https://www.autopsy.com/.

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
Expected output: Sleuth Kit reports a version banner (e.g. `The Sleuth Kit ver 4.12.1`) for `fls`, `mmls`, and `fsstat`; `photorec` and `testdisk` print their version strings; the Autopsy line confirms the binary exists. The `-V` flag is the documented Sleuth Kit version switch (https://www.sleuthkit.org/sleuthkit/man/fls.html). PhotoRec/TestDisk accept the `/version` run-time option to report their build (https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step). Note that Sleuth Kit tools use single-dash flags (`-V`), while PhotoRec/TestDisk use the DOS-style slash options (`/version`, `/log`, `/d`, `/cmd`) — do not mix the two styles.

## Guided walkthrough
1. `mmls` — display the partition table (volume system / media layout) of a disk image and the sector offsets of each volume. Running this FIRST is essential: every downstream Sleuth Kit tool needs the `-o` starting-sector offset of the target partition, and `mmls` is how you obtain it without mounting the image (read-only, no write to the evidence). See https://www.sleuthkit.org/sleuthkit/man/mmls.html.
```bash
mmls exercise/sample.dd
```
Expected observable output: a table of slots with `Start`, `End`, `Length`, and `Description` columns showing the partition(s) and their starting sector offset. Nuance: `mmls` reports offsets in **sectors** (default 512 bytes) and also prints unallocated/meta slots (e.g. the partition table itself and any gaps) — those gaps are where wiped or hidden partitions can hide. A single-partition FAT image made with `mkfs.vfat` directly on the whole image (as in this exercise) may have **no** partition table at all, in which case `mmls` errors with "Cannot determine partition type" and the correct offset is `0` (used throughout the Answer key below). **Why this matters:** Using the wrong sector offset in later `-o` flags will point at arbitrary data instead of the filesystem, producing nonsense output or errors. The `mmls` error itself is a diagnostic clue that the media has no volume system – common for memory cards, USB drives formatted directly, or after partition-table destruction (T1485).

2. `fsstat` — show filesystem metadata (type, block size, volume label) for a partition at a known offset. This confirms the filesystem you are actually dealing with before trusting a listing, and the cluster/sector size it prints is needed to reason about slack space and carving boundaries. See https://www.sleuthkit.org/sleuthkit/man/fsstat.html.
```bash
fsstat -o 2048 exercise/sample.dd
```
Expected observable output: a "FILE SYSTEM INFORMATION" report naming the filesystem (e.g. FAT16/NTFS/Ext4), block/cluster size, and layout details. Nuance: if `mmls` showed no partition table for this exercise image, use `-o 0`. `fsstat` reads the boot sector / superblock, so a wrong offset produces a "Cannot determine file system type" error — a quick sanity check that you have the right offset. **Why this matters:** The cluster size (e.g., 4096 bytes for FAT16 with 8 sectors per cluster) is critical for understanding slack space: the unused portion of the last cluster allocated to a file can hide prior data. Carving with `photorec` will still recover files regardless of cluster size, but manual scanning of slack space requires knowing this value.

3. `fls` — list allocated and deleted files/directories; entries marked with `*` are deleted. See https://www.sleuthkit.org/sleuthkit/man/fls.html.
```bash
fls -r -o 2048 exercise/sample.dd
```
Expected observable output: a recursive (`-r`) listing of inodes/MFT entries and filenames; deleted files are prefixed with `*`. Nuance: the leading `d/d` or `r/r` shows the file type reported by the directory entry vs. the metadata structure; when those disagree (e.g. `r/d`) the metadata was reallocated, a hint the entry is deleted and its inode may now describe a different object. The number after the type is the metadata address you feed to `icat`. **Why this matters:** The `d/d` notation: first letter is directory-entry type (d=directory, r=regular file, l=link, etc.), second is the metadata structure type. Mismatches reveal tampering or deletion artifacts. On FAT, deleted entries show as `r/r` or `d/d` with `*`; on NTFS, deleted MFT records appear as `-/-` or `r/r *` and the `$FILE_NAME` timestamps can be compared to `$STANDARD_INFORMATION` for timestomp detection (T1070.006).

4. `icat` — stream the content of a file by its metadata (inode/MFT) address to recover it, without mounting the image. See https://www.sleuthkit.org/sleuthkit/man/icat.html.
```bash
icat -o 2048 exercise/sample.dd 5 > /tmp/recovered_file.bin
ls -l /tmp/recovered_file.bin
```
Expected observable output: the recovered bytes are written to `/tmp/recovered_file.bin` and `ls -l` shows a non-zero file size. Nuance: `icat` reads whatever the metadata structure still points to. For a recently deleted file whose clusters have not been reallocated, this returns the original content; if the file was fragmented or its blocks overwritten, the output may be partial or contain another file's data. Use the metadata address reported by `fls` (the exercise sample uses address `5`). **Why this matters:** The metadata address (inode on Linux, MFT record number on NTFS) persists even after deletion until overwritten. If the file is fragmented, `icat` will still attempt to follow the cluster chain; if a fragment is reallocated, the output will be corrupted but potentially still yields useful fragments. For complete recovery of fragmented files, use `tsk_recover` or manually extract clusters.

5. `fls` + `mactime` — generate a timeline body file and render a chronological activity report. This is the core of "super timeline" triage: `fls -m` emits the Sleuth Kit body-file format and `mactime` sorts it into MACB order. See https://www.sleuthkit.org/sleuthkit/man/fls.html and https://www.sleuthkit.org/sleuthkit/man/mactime.html.
```bash
fls -m / -r -o 2048 exercise/sample.dd > /tmp/bodyfile.txt
mactime -b /tmp/bodyfile.txt -d > /tmp/timeline.csv
head -n 5 /tmp/timeline.csv
```
Expected observable output: a CSV (`-d`) timeline sorted by date with MACB (Modified/Accessed/Changed/Born) activity per file. Nuance: the `-m /` argument prepends a mount-point string to each path so the timeline reads like a real filesystem; the MACB columns collapse identical timestamps, so a file dropped and executed in one burst shows all four flags on one line, while a gap or single "M" flag can indicate timestomping (T1070.006) or later tampering. `mactime` interprets body-file times as the timezone set by `-z` (default local) — always record the timezone used. The body-file format itself (pipe-delimited: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime) is documented at https://wiki.sleuthkit.org/index.php?title=Body_file; understanding that layout matters because `mactime` derives the four MACB columns from those last four epoch fields, and a zeroed or absent crtime is normal on filesystems (like FAT) that do not track all four. **Why this matters:** The timeline enables temporal correlation of file system activity with external events (network alerts, process logs). Anomalous patterns such as a file with only a Modified timestamp (no Birth) suggest timestomping; a burst of Born timestamps on executables at the same second indicates a bulk drop. The mount string (`-m /`) should match the root of the partition being analyzed; errors here produce misleading paths.

6. `photorec` — carve recoverable files from the raw image (batch/non-interactive mode). PhotoRec ignores the filesystem and matches known file-signature headers/footers, so it recovers data even after the directory entry and metadata are gone. See https://www.cgsecurity.org/wiki/PhotoRec and https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step.
```bash
mkdir -p /tmp/carved
photorec /log /d /tmp/carved /cmd exercise/sample.dd partition_none,options,mode_ext2,fileopt,everything,enable,search
ls -R /tmp/carved
```
Expected observable output: PhotoRec writes recovered files into `/tmp/carved/recup_dir.1/` and prints a summary of the number of files recovered by type. Nuance: `/log` writes a `photorec.log` audit trail, `/d` sets the recovery destination, and `/cmd ... search` runs the carve non-interactively; `partition_none` treats the whole image as one blob (correct when there is no partition table), and `mode_ext2` disables filesystem-aware optimizations so carving is signature-only. Carved files are renamed by PhotoRec (original names are not stored in signatures), so recovered filenames will NOT match the originals — this is expected behavior of signature carving. **Why this matters:** PhotoRec operates at the byte level, making it the tool of last resort when the filesystem is corrupted, formatted, or overwritten. Because it relies on known file headers, it can recover files that are fragmented or partially overwritten if the header remains intact. The `mode_ext2` option skips reading the filesystem superblock, forcing raw scan; this is recommended for drives with damaged partition tables or unknown filesystems.

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
`452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

## SOC analyst perspective
A defender uses these tools during the examination phase of an incident when a suspect endpoint's disk (or a forensic image of it) needs to be triaged. `fls`/`mactime` timelines reveal when malicious files were dropped or when persistence was created, directly supporting detection of techniques like T1547 (Boot or Logon Autostart Execution) and T1070.004 (File Deletion). `icat` recovers files an attacker deleted to cover their tracks, and `photorec` carves out payloads no longer referenced by the filesystem. In a Security Onion workflow, network alerts (Suricata/Zeek) flag a compromised host by IP; the analyst then pulls the disk image and cross-references the filesystem timeline against the alert timestamp to confirm the intrusion, scope lateral movement, and export IOCs (hashes, filenames) back into Security Onion for hunting across other hosts.

Concrete detection logic and pivots:
- **Timeline-to-alert correlation.** In Security Onion, pivot from a Suricata IDS alert (Alerts interface) to the flow record in Zeek `conn.log` and its `ts` field, then window your `mactime` output to that timestamp ±5 minutes to find files whose Born ("B") time coincides with C2 or download activity (payload staging, T1105 Ingress Tool Transfer). Concretely, take the Suricata alert's `timestamp` and its `src_ip`/`dest_ip` fields, pivot to the matching Zeek `conn.log` `uid`, then bound your timeline search around `conn.log`'s `ts` — files whose crtime (crtime in the body file → "B" flag) sits inside that flow window are prime staging candidates. Security Onion documents the Alerts/Hunt/Dashboards pivots and its Zeek/Suricata data sources: https://docs.securityonion.net/en/2.4/alerts.html and https://docs.securityonion.net/en/2.4/zeek.html.
- **Download → disk artifact linkage.** Zeek `files.log` records extracted file hashes (its `md5`, `sha1`, and `sha256` fields when the hash analyzer is enabled) and the `mime_type`/`filename` fields, while `http.log` (`host`, `uri`) and `dns.log` (`query`) record the retrieval path; match the `files.log` hash against the sha256 you compute on carved/`icat`-recovered files to prove a network-observed download landed on disk (supports T1105 and T1005 Data from Local System). The `files.log` `tx_hosts`/`rx_hosts` fields tie the transferred file back to the same endpoint whose image you are examining. Zeek logging reference: https://docs.zeek.org/en/master/logs/index.html.
- **Deletion / anti-forensics detection.** An `fls -r` listing full of `*`-marked entries clustered in a short window, combined with a `mactime` gap, is a strong signal of T1070.004 (File Deletion) or T1070.006 (Timestomp). Flag files where the metadata timestamps are internally inconsistent (e.g. a Created time later than Modified) as possible timestomping. On Windows images, corroborate deletion by parsing the `$UsnJrnl:$J` change journal (records `FILE_DELETE`/`CLOSE` reasons for names no longer resident) and the `$LogFile` — these persist metadata about files even after the MFT record is unallocated. SANS reference for these journal artifacts: https://www.sans.org/posters/windows-forensic-analysis/.
- **Command-history / shell tampering hunt (Linux images).** For Linux evidence, surface `~/.bash_history`, `/var/log/auth.log`, and `/var/log/wtmp`/`btmp` in the `mactime` output; a truncated or missing history file with a modified mtime, or an `auth.log` gap, supports T1070.003 (Indicator Removal: Clear Command History) and warrants carving deleted history fragments with `photorec`. MITRE reference: https://attack.mitre.org/techniques/T1070/003/.
- **Persistence hunting.** Surface autostart artifacts (registry run keys / services on Windows images, `cron`/`systemd`/`~/.bashrc` on Linux images) in the `mactime` output to detect T1547 and T1053 (Scheduled Task/Job — sub-technique T1053.003 cron on Linux, T1053.005 Scheduled Task on Windows). On Windows, correlate created/modified service artifacts with Windows **Event ID 7045** (a new service was installed in the System log) and scheduled-task creation with **Event ID 4698** in the Security log; on Linux, correlate crontab file crtime with `/var/log/syslog` cron entries. Then hash and push those filenames/hashes into Security Onion's Hunt interface (https://docs.securityonion.net/en/2.4/hunt.html) to sweep the rest of the fleet. MITRE references: https://attack.mitre.org/techniques/T1053/003/ and https://attack.mitre.org/techniques/T1053/005/.
- **Obfuscation detection (T1027).** When recovering files with `icat` or carving, compute entropy or use `file` to detect packer signatures. In Security Onion, pivot from Zeek `files.log` where `mime_type` is a mismatch (e.g. a `.txt` file detected as `application/x-dosexec`) or where `extracted` analysis shows high entropy. Suricata can generate an alert on file-magic anomalies via the `file` keyword (e.g., `file.magic` rule matching a PE header inside a disguised extension). For files recovered from disk with high entropy (≥7.5), flag as T1027 Obfuscated Files or Information (https://attack.mitre.org/techniques/T1027/). Cross-reference with known packer hashes from Threat Intelligence.
- **User Execution detection (T1204.002).** Timeline analysis can reveal a file's Born timestamp followed closely by its Modified/Accessed timestamps; this pattern often indicates execution. On Windows, correlate the file's `$SI` Last Access timestamp to Sysmon Event ID 1 (Process creation) or Windows Event ID 4688, using the `CommandLine` field to see the executed path. On Linux, correlate with auditd `SYSCALL` events. In Security Onion, if Zeek extracted the file from network traffic (T1105), check whether that file hash appears in the timeline with a "B" flag at or before the flow's `ts`, and a subsequent "M" or "A" flag within seconds of the flow's end. This sequence supports T1204.002 User Execution: Malicious File (https://attack.mitre.org/techniques/T1204/002/).
- **PowerShell script artifacts (T1059.001).** Recover `.ps1` files via `icat` or carving, then deobfuscate manually or with tools. In Windows Event Logs, **Event ID 4104** (ScriptBlock Logging) captures the deobfuscated content of PowerShell commands; if available, cross-reference with recovered scripts. In Security Onion, Zeek `files.log` may tag transferred PowerShell scripts with `mime_type = application/powershell` or `text/plain`. Hash the script and hunt across endpoints. MITRE reference: https://attack.mitre.org/techniques/T1059/001/.
- **Hidden files and directories (T1564.001).** Linux users often hide files by prefixing with a dot (e.g., `.malware`); Windows uses the hidden attribute. `fls -r` reveals such files because it reads directory entries regardless of attributes. In a timeline, the presence of hidden files in unusual paths (e.g., `.config/`, `AppData\Roaming`) should be flagged. In Security Onion, hunt for IOCs whose file paths contain `\..\` (hidden Windows) or start with `.` (Linux). MITRE reference: https://attack.mitre.org/techniques/T1564/001/.
- **Threat hunting pivot: file entropy scan.** Use a bulk entropy calculator (e.g., with `binwalk -E` or a custom Python script) on recovered files. Files with entropy >7.5 are likely packed/encrypted (T1027). On SIFT, use `foremost` or `scalpel` for carving and then `ent` for entropy. If a matching packed file is found, check whether the Zeek `files.log` `entropy` field (if using zeek-entropy-plugin) indicates the same for network transfers.

## Attacker perspective
Attackers know that deleting a file with `rm` or emptying the recycle bin only unlinks the directory entry — the underlying blocks (and often the file data) remain until overwritten, which is exactly what `icat` and `photorec` recover. Adversaries performing T1070.004 (Indicator Removal: File Deletion) and T1485 (Data Destruction) may wipe tools, staged archives, or logs, but leave carveable remnants, orphaned MFT/inode entries, and telltale timeline gaps that `fls -r` exposes with the `*` deleted marker. Even secure-delete or partition-wiping attempts leave artifacts: `mmls` and `testdisk` reveal tampered or removed partition tables, and slack space frequently retains fragments of the very files an attacker believed were destroyed, giving investigators recoverable evidence.

Concrete TTPs, artifacts left behind, and evasion:
- **T1070.004 – File Deletion.** `rm`/recycle-bin/`del` only clears the directory pointer; on NTFS the MFT record is marked unallocated but persists until reused, and on FAT the first byte of the 8.3 name is set to `0xE5` while the cluster chain data survives — both are recoverable with `icat` and visible as `*` entries in `fls`. On Windows the Recycle Bin itself leaves `$I` (metadata) and `$R` (data) files under `C:\$Recycle.Bin\<SID>\`, which record the original path and deletion time even after the user "empties" the bin. MITRE reference: https://attack.mitre.org/techniques/T1070/004/.
- **T1070.006 – Timestomp.** Attackers use tools (e.g. `SetMACE`, PowerShell, `touch -d`) to backdate timestamps and blend into system files. Defenders counter this on NTFS by comparing the `$STANDARD_INFORMATION` timestamps (what most tools alter) against the harder-to-forge `$FILE_NAME` timestamps in the MFT; a `$SI` created time that predates the `$FN` created time is a classic timestomp tell. MITRE reference: https://attack.mitre.org/techniques/T1070/006/.
- **T1070.003 – Clear Command History.** On Linux, adversaries `unset HISTFILE`, `history -c`, or truncate `~/.bash_history` to hide interactive commands; on Windows they clear PowerShell's `ConsoleHost_history.txt` (under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\`). Both leave recoverable slack/unallocated fragments and an anomalous mtime, and PowerShell operational logging (Event ID 4104 script-block logging) may still capture the executed commands even after the on-disk history is wiped. MITRE reference: https://attack.mitre.org/techniques/T1070/003/.
- **T1485 – Data Destruction.** Wiping partition tables or superblocks makes an image look empty to a naive mount, but `mmls` still shows the raw layout and `testdisk` can rebuild a deleted/overwritten partition table from backup structures (https://www.cgsecurity.org/wiki/TestDisk), while PhotoRec carves file bodies independent of any partition metadata. MITRE reference: https://attack.mitre.org/techniques/T1485/.
- **T1564.005 – Hide Artifacts: Hidden File System / slack abuse.** Adversaries may stash data in areas the filesystem does not surface — cluster slack, unpartitioned gaps between `mmls` slots, or volume slack — betting a casual mount will miss it. Carving (`photorec`) and raw-offset reads defeat this because they operate on bytes, not on the allocation map. MITRE reference: https://attack.mitre.org/techniques/T1564/005/.
- **T1027 – Obfuscated Files or Information.** Attackers pack, encrypt, or encode payloads to bypass signature-based detection. These files often have high entropy, unusual imports, or invalid headers that do not match their extension. Forensic extraction recovers the obfuscated blob; deobfuscation (T1140) may be needed. Artifacts include: 7z/UPX-packed executables, base64-encoded PowerShell scripts, or XOR-encrypted shellcode. Timeline anomalies (e.g., a file with high entropy created after a network download) help pinpoint obfuscation. Evasion: adversaries may use custom packers to avoid known signatures. MITRE reference: https://attack.mitre.org/techniques/T1027/.
- **T1204.002 – User Execution: Malicious File.** Attackers rely on victims to double-click a malicious document or executable. Artifacts include: Prefetch files (Windows), Shimcache, Amcache, BAM/Dam, and MFT timestamps (last access). Even if the file is deleted shortly after execution, the Prefetch record persists. Timeline analysis showing a Born timestamp followed soon after by an Access timestamp on the same file is a strong indicator. Evasion: use file masquerading (T1036) to trick users, or execute from temporary writable folders (e.g., %TEMP%, /tmp). MITRE reference: https://attack.mitre.org/techniques/T1204/002/.
- **T1059.001 – PowerShell.** PowerShell scripts are frequently used for both initial access and post-exploitation. Scripts may be written to disk (e.g., in %TEMP% or %APPDATA%) and executed immediately. Even if the script is deleted, carving can recover it. Artifacts include: Event ID 4104 (ScriptBlock Logging), Module Logging, and the presence of encoded commands in the $LogFile or recycle bin. Evasion: attackers use obfuscated, one-liner commands that never touch disk, but when they do write scripts, they often encode them (base64) or hide them in alternative data streams (NTFS ADS). MITRE reference: https://attack.mitre.org/techniques/T1059/001/.
- **T1564.001 – Hide Artifacts: Hidden Files and Directories.** On Linux, attackers create files/directories with a leading dot (e.g., `.malware`); on Windows they set the hidden attribute. These files are invisible to normal directory listings but appear in `fls -r` output. Evasion: attackers may place hidden files deep in system directories (e.g., `/usr/share/.hidden`, `C:\Windows\System32\Tasks\.hidden`). Timeline analysis will still show them, though. MITRE reference: https://attack.mitre.org/techniques/T1564/001/.
- **Evasion and its limits.** True anti-forensics requires overwriting the data blocks (e.g. `shred`, `dd if=/dev/zero`, full-disk crypto-erase), not just deletion — but partial wipes leave file **slack** (the unused tail of the last cluster) holding fragments of prior content, and journaled filesystems (ext3/4 journal, NTFS `$LogFile`/`$UsnJrnl`) retain metadata about files that no longer exist. These residual structures are exactly what carving and metadata analysis exploit. General Sleuth Kit/DFIR reference: https://www.sleuthkit.org/sleuthkit/docs.php and the SANS DFIR resources at https://www.sans.org/posters/windows-forensic-analysis/.

## Answer key
Sample sha256: `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

Expected findings and the exact commands that produce them:

1. Filesystem type / cluster size:
```bash
fsstat -o 0 exercise/sample.dd | grep -Ei "file system type|sector size|cluster size"
```
Expected: File System Type reported as FAT16 with the sector/cluster size shown. (Offset `0` is correct because this image has a filesystem written directly to the whole image with no partition table.)

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
- **T1005** – Data from Local System (files identified/exported from the image). https://attack.mitre.org/techniques/T1005/
- **T1027** – Obfuscated Files or Information (recovered obfuscated payloads). https://attack.mitre.org/techniques/T1027/
- **T1053.003** – Scheduled Task/Job: Cron (Linux cron persistence surfaced in timeline). https://attack.mitre.org/techniques/T1053/003/
- **T1053.005** – Scheduled Task/Job: Scheduled Task (Windows task persistence, Event ID 4698). https://attack.mitre.org/techniques/T1053/005/
- **T1059.001** – Command and Scripting Interpreter: PowerShell (PowerShell script artifacts recovered from disk). https://attack.mitre.org/techniques/T1059/001/
- **T1070.003** – Indicator Removal: Clear Command History (deleted/truncated shell history recoverable from slack). https://attack.mitre.org/techniques/T1070/003/
- **T1070.004** – Indicator Removal: File Deletion (recovered via `icat`/`photorec`). https://attack.mitre.org/techniques/T1070/004/
- **T1070.006** – Indicator Removal: Timestomp (detected via MACB inconsistencies in the `mactime` timeline / MFT `$SI` vs `$FN` comparison). https://attack.mitre.org/techniques/T1070/006/
- **T1105** – Ingress Tool Transfer (downloaded payloads correlated between Zeek `files.log` and on-disk artifacts). https://attack.mitre.org/techniques/T1105/
- **T1204.002** – User Execution: Malicious File (execution artifacts from timeline timestamps). https://attack.mitre.org/techniques/T1204/002/
- **T1485** – Data Destruction (partition/disk tampering detected via `mmls`/`testdisk`). https://attack.mitre.org/techniques/T1485/
- **T1547** – Boot or Logon Autostart Execution (persistence artifacts surfaced in `mactime` timeline). https://attack.mitre.org/techniques/T1547/
- **T1564.001** – Hide Artifacts: Hidden Files and Directories (hidden file detection via `fls -r`). https://attack.mitre.org/techniques/T1564/001/
- **T1564.005** – Hide Artifacts: Hidden File System (slack/unpartitioned-gap abuse defeated by carving). https://attack.mitre.org/techniques/T1564/005/
- **DFIR phase:** Identification and Examination (evidence acquisition triage, filesystem analysis, timeline reconstruction, and deleted-file recovery).


### Essential Commands & Features

Below are **critical but undemonstrated** Sleuth Kit commands for **block-level analysis** and **signature-based recovery**, each with a concrete example and tactical use case.

---

#### **1. `blkcalc` – Map Unallocated Blocks to Files**
**When to use:** After identifying suspicious unallocated blocks (e.g., via `blkls`), map them back to their original file metadata to recover deleted artifacts.
**Example:**
```bash
blkcalc -d disk.img -u 1024
```
*Outputs the inode/file associated with unallocated block 1024 in `disk.img`.*
**MITRE ATT&CK:** [T1074.001 Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/) (e.g., staging exfil data in unallocated space).

---

#### **2. `blkls` – Extract Unallocated or Slack Space**
**When to use:** Dump unallocated blocks or slack space for deep analysis (e.g., carving hidden payloads or remnants of deleted files).
**Example (unallocated blocks):**
```bash
blkls -A disk.img > unallocated.raw
```
**Example (slack space only):**
```bash
blkls -s disk.img > slack.raw
```
**MITRE ATT&CK:** [T1564.004 Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/) (e.g., hiding data in slack space).

---

#### **3. `sigfind` – Locate File Signatures in Raw Data**
**When to use:** Search for file headers/footers (e.g., `PK` for ZIP, `MZ` for PE) in raw dumps (e.g., `unallocated.raw` from `blkls`).
**Example (find ZIP files):**
```bash
sigfind -b 512 504B unallocated.raw
```
*Searches for `PK` (hex `504B`) at 512-byte block offsets.*
**MITRE ATT&CK:** [T1132.001 Data Encoding: Standard Encoding](https://attack.mitre.org/techniques/T1132/001/) (e.g., obfuscated payloads in archives).

---

**Authoritative Sources:**
- Sleuth Kit Man Pages: [https://www.sleuthkit.org/sleuthkit/man/](https://www.sleuthkit.org/sleuthkit/man/)
- DFIR Review (Peer-Reviewed): [https://www.dfir

### Common Pitfalls & Result Validation

Common pitfalls in disk forensics stem from over-relying on a single tool or default settings. Analysts often assume that deleted files are always recoverable, ignoring file slack and MFT record overwrites. Timestamps are frequently misinterpreted as absolute creation times, while they can be modified or inaccurately reported by tools. Another mistake is treating a clean `$LogFile` or event log as evidence of benign activity—attackers systematically clear logs using **T1070.001 (Indicator Removal on Host: Clear Windows Event Logs)**, which may leave behind residual entries in `Security.evtx` or $MFT. Similarly, adversaries hide malicious accounts by modifying registry values to prevent them from appearing in standard user enumeration; this is captured by **T1564.002 (Hide Artifacts: Hidden Users)**.

To validate findings, cross‑reference file system metadata with log analysis, timeline generation, and multiple carving tools (e.g., `scalpel` against `bulk_extractor` results). Hash sets like NSRL should be used to eliminate known good files, but beware of hash collisions and partial matches. For timestamp verification, compare `fn` (filename) and `si` (standard information) timestamps in the MFT; anomalies may indicate anti‑forensic manipulation.

False conclusions are avoided by never extrapolating intent from incomplete evidence—a single partially overwritten cluster does not confirm data destruction, and recovered registry hives may lack cross‑validation with actual user profiles. Always test conclusions by reproducing results on a clean, immutable copy of the evidence. Engage chain‑of‑custody logs and document every tool version to ensure repeatability.

**Authoritative References:**
- [CISA - Event Log Clearing and Anti‑Forensic Techniques (Technical Guidance)](https://www.cisa.gov/uscert/ncas/tips/ST04-003)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://www.nist.gov/publications/guide-integrating-forensic-techniques-incident-response)


### Essential Commands & Features

Block-level analysis and signature-based recovery are critical for uncovering hidden or deleted artifacts. Below are **essential Sleuth Kit commands** not yet demonstrated, with concrete examples and use cases:

#### **1. `blkcalc` – Map Block Addresses to Files**
Recover file metadata from unallocated blocks by mapping a block address (e.g., from `blkls`) back to its original file.
**Example:**
```bash
blkcalc -d disk.img -u 1024
```
**When to use:** After identifying suspicious blocks with `blkls`, determine which file(s) they belonged to (e.g., for **T1074.001 Data Staged** or **T1564.004 NTFS File Attributes**).

#### **2. `blkls` – Extract Unallocated Blocks**
Dump unallocated or slack space from a disk/image for deeper analysis.
**Example:**
```bash
blkls -A disk.img > unallocated_blocks.raw
```
**When to use:** Analyze unallocated space for remnants of deleted files (e.g., **T1485 Data Destruction** or **T1070.004 File Deletion**).

#### **3. `sigfind` – Locate File Signatures**
Scan raw data for file headers/footers (e.g., `PK` for ZIP, `FFD8` for JPEG) to recover fragmented or hidden files.
**Example:**
```bash
sigfind -b 512 -t jpeg disk.img
```
**When to use:** Recover obfuscated files (e.g., **T1140 Deobfuscate/Decode Files or Information** or **T1027.001 Binary Padding**).

**Authoritative Sources:**
- [Sleuth Kit Man Pages (blkcalc, blkls, sigfind)](https://www.sleuthkit.org/sleuthkit/man/)
- [DFIR Review: Sleuth Kit for Block-Level Analysis](https://www.dfir.review/)

### Threat Hunting & Detection Engineering

Once disk artifacts are recovered, pivot to **threat hunting** by correlating file-system metadata with live telemetry. Focus on **T1033 (System Owner/User Discovery)** and **T1574.002 (Hijack Execution Flow: DLL Side-Loading)**—both leave distinct disk and log footprints.

**Detection Logic**
- **Windows Event Logs**: Hunt for `Event ID 4688` (Process Creation) where `ParentProcessName` is `explorer.exe` and `NewProcessName` is an unsigned `.dll` in `%TEMP%` or `%APPDATA%` (T1574.002). Cross-reference with `Event ID 7` (Image Loaded) in `Microsoft-Windows-Sysmon/Operational` to confirm DLLs loaded from unusual paths.
- **Zeek/Suricata**: Monitor `files.log` for `.dll` or `.exe` downloads via HTTP (`mime_type: application/x-dosexec`) with `conn_state == "SF"` (successful transfer). Pivot to `pe.log` to extract `section_names` or `import_hash` (T1033 often uses `NetUserGetInfo` or `NetLocalGroupGetMembers` imports).
- **Hunting Pivots**:
  - **Registry**: Query `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` for debugger hijacks (T1574.002).
  - **Prefetch**: Parse `.pf` files for executables with mismatched `LastRunTime` and `VolumeCreateTime` (timestomping, T1070.006).

**Sources**
- [MITRE ATT&CK: T1033](https://attack.mitre.org/techniques/T1033/)
- [SANS DFIR: Hunting DLL Side-Loading](https://www.sans.org/blog/hunting-dll-side-loading-with-sysmon/)

## Sources
Claim → source mapping (all URLs are official tool/project docs, MITRE ATT&CK, SANS, or recognized vendor/project sites):

- Sleuth Kit is a library + CLI tool collection for analyzing disk images and recovering files; tool inventory (`mmls`, `fsstat`, `fls`, `icat`, `mactime`): https://www.sleuthkit.org/sleuthkit/tools.php and https://www.sleuthkit.org/sleuthkit/docs.php
- `mmls` behavior (volume-system layout, sector offsets, `-o` usage downstream): https://www.sleuthkit.org/sleuthkit/man/mmls.html
- `fsstat` behavior (FILE SYSTEM INFORMATION, filesystem type, cluster/sector size): https://www.sleuthkit.org/sleuthkit/man/fsstat.html
- `fls` behavior (`-r` recursive, `*` deleted marker, `-m` body-file output, `-V` version): https://www.sleuthkit.org/sleuthkit/man/fls.html
- `icat` behavior (stream file content by metadata address): https://www.sleuthkit.org/sleuthkit/man/icat.html
- `mactime` behavior (body-file input `-b`, CSV `-d`, MACB sorting, timezone `-z`): https://www.sleuthkit.org/sleuthkit/man/mactime.html
- Sleuth Kit body-file format (pipe-delimited fields, atime/mtime/ctime/crtime): https://wiki.sleuthkit.org/index.php?title=Body_file
- Autopsy graphical platform (modern 4.x): https://www.autopsy.com/ ; legacy 2.x web UI on port 9999 in Kali package: https://www.kali.org/tools/autopsy/
- PhotoRec — signature-based carving, run-time options `/log /d /cmd`, `recup_dir.N` output, filename renaming: https://www.cgsecurity.org/wiki/PhotoRec and https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step
- TestDisk — recover/rebuild lost or damaged partition tables: https://www.cgsecurity.org/wiki/TestDisk
- PhotoRec/TestDisk shipped in a single `testdisk` package: https://www.kali.org/tools/testdisk/
- Kali Linux Tools — Sleuth Kit: https://www.kali.org/tools/sleuthkit/
- SANS DFIR — SIFT Workstation (lab platform): https://www.sans.org/tools/sift-workstation/
- SANS DFIR — Windows Forensic Analysis poster ($SI vs $FN, `$UsnJrnl`/`$LogFile`, Recycle Bin `$I`/`$R`, timeline/anti-forensics context): https://www.sans.org/posters/windows-forensic-analysis/
- Security Onion — Alerts interface / pivots (Suricata `timestamp`, `src_ip`/`dest_ip`): https://docs.securityonion.net/en/2.4/alerts.html
- Security Onion — Hunt interface: https://docs.securityonion.net/en/2.4/hunt.html
- Security Onion — Zeek data source: https://docs.securityonion.net/en/2.4/zeek.html
- Zeek logging reference (`conn.log` `ts`/`uid`, `files.log` `md5`/`sha1`/`sha256`/`mime_type`/`tx_hosts`, `http.log`, `dns.log`): https://docs.zeek.org/en/master/logs/index.html
- MITRE ATT&CK — T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK — T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — T1053.003 Scheduled Task/Job: Cron: https://attack.mitre.org/techniques/T1053/003/
- MITRE ATT&CK — T1053.005 Scheduled Task/Job: Scheduled Task: https://attack.mitre.org/techniques/T1053/005/
- MITRE ATT&CK — T1059.001 Command and Scripting Interpreter: PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — T1070.003 Indicator Removal: Clear Command History: https://attack.mitre.org/techniques/T1070/003/
- MITRE ATT&CK — T1070.004 Indicator Removal: File Deletion: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — T1070.006 Indicator Removal: Timestomp: https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK — T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — T1204.002 User Execution: Malicious File: https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK — T1485 Data Destruction: https://attack.mitre.org/techniques/T1485/
- MITRE ATT&CK — T1547 Boot or Logon Autostart Execution: https://attack.mitre.org/techniques/T1547/
- MITRE ATT&CK — T1564.001 Hide Artifacts: Hidden Files and Directories: https://attack.mitre.org/techniques/T1564/001/
- MITRE ATT&CK — T1564.005 Hide Artifacts: Hidden File System: https://attack.mitre.org/techniques/T1564/005/
- Microsoft Learn — Windows Security event 4698 (a scheduled task was created): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
- Microsoft Learn — Windows System event 7045 (a new service was installed): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/appendix-l-events-to-monitor
- Microsoft Learn — PowerShell script block logging (Event ID 4104): https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft Learn — Process creation event 4688: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Sysmon documentation (Event ID 1 process creation, Event ID 11 file creation): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## Related modules
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- deeper drill on the same Sleuth Kit tools (`fls`/`icat`/`mactime`) used here.
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- applies Sleuth Kit timelines to a full intrusion case.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- extends Sleuth Kit disk analysis into a complete Linux host triage workflow.
- [Memory forensics](../02-memory-forensics/README.md) -- same Foundations learning path, pairing disk artifacts with volatile memory evidence.

<!-- cyberlab-enriched: v3 -->
- https://attack.mitre.org/techniques/T1074/001/
- https://attack.mitre.org/techniques/T1564/004/
- https://attack.mitre.org/techniques/T1132/001/
- https://www.sleuthkit.org/sleuthkit/man/](https://www.sleuthkit.org/sleuthkit/man/
- https://www.dfir
- https://www.cisa.gov/uscert/ncas/tips/ST04-003
- https://www.nist.gov/publications/guide-integrating-forensic-techniques-incident-response

<!-- cyberlab-enriched: v4 -->
- https://www.sleuthkit.org/sleuthkit/man/
- https://www.dfir.review/
- https://attack.mitre.org/techniques/T1033/
- https://www.sans.org/blog/hunting-dll-side-loading-with-sysmon/

<!-- cyberlab-enriched: v5 -->
