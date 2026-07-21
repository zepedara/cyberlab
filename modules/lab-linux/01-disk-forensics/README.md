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
Expected observable output: a table of slots with `Start`, `End`, `Length`, and `Description` columns showing the partition(s) and their starting sector offset. Nuance: `mmls` reports offsets in **sectors** (default 512 bytes) and also prints unallocated/meta slots (e.g. the partition table itself and any gaps) — those gaps are where wiped or hidden partitions can hide. A single-partition FAT image made with `mkfs.vfat` directly on the whole image (as in this exercise) may have **no** partition table at all, in which case `mmls` errors with "Cannot determine partition type" and the correct offset is `0` (used throughout the Answer key below).

2. `fsstat` — show filesystem metadata (type, block size, volume label) for a partition at a known offset. This confirms the filesystem you are actually dealing with before trusting a listing, and the cluster/sector size it prints is needed to reason about slack space and carving boundaries. See https://www.sleuthkit.org/sleuthkit/man/fsstat.html.
```bash
fsstat -o 2048 exercise/sample.dd
```
Expected observable output: a "FILE SYSTEM INFORMATION" report naming the filesystem (e.g. FAT16/NTFS/Ext4), block/cluster size, and layout details. Nuance: if `mmls` showed no partition table for this exercise image, use `-o 0`. `fsstat` reads the boot sector / superblock, so a wrong offset produces a "Cannot determine file system type" error — a quick sanity check that you have the right offset.

3. `fls` — list allocated and deleted files/directories; entries marked with `*` are deleted. See https://www.sleuthkit.org/sleuthkit/man/fls.html.
```bash
fls -r -o 2048 exercise/sample.dd
```
Expected observable output: a recursive (`-r`) listing of inodes/MFT entries and filenames; deleted files are prefixed with `*`. Nuance: the leading `d/d` or `r/r` shows the file type reported by the directory entry vs. the metadata structure; when those disagree (e.g. `r/d`) the metadata was reallocated, a hint the entry is deleted and its inode may now describe a different object. The number after the type is the metadata address you feed to `icat`.

4. `icat` — stream the content of a file by its metadata (inode/MFT) address to recover it, without mounting the image. See https://www.sleuthkit.org/sleuthkit/man/icat.html.
```bash
icat -o 2048 exercise/sample.dd 5 > /tmp/recovered_file.bin
ls -l /tmp/recovered_file.bin
```
Expected observable output: the recovered bytes are written to `/tmp/recovered_file.bin` and `ls -l` shows a non-zero file size. Nuance: `icat` reads whatever the metadata structure still points to. For a recently deleted file whose clusters have not been reallocated, this returns the original content; if the file was fragmented or its blocks overwritten, the output may be partial or contain another file's data. Use the metadata address reported by `fls` (the exercise sample uses address `5`).

5. `fls` + `mactime` — generate a timeline body file and render a chronological activity report. This is the core of "super timeline" triage: `fls -m` emits the Sleuth Kit body-file format and `mactime` sorts it into MACB order. See https://www.sleuthkit.org/sleuthkit/man/fls.html and https://www.sleuthkit.org/sleuthkit/man/mactime.html.
```bash
fls -m / -r -o 2048 exercise/sample.dd > /tmp/bodyfile.txt
mactime -b /tmp/bodyfile.txt -d > /tmp/timeline.csv
head -n 5 /tmp/timeline.csv
```
Expected observable output: a CSV (`-d`) timeline sorted by date with MACB (Modified/Accessed/Changed/Born) activity per file. Nuance: the `-m /` argument prepends a mount-point string to each path so the timeline reads like a real filesystem; the MACB columns collapse identical timestamps, so a file dropped and executed in one burst shows all four flags on one line, while a gap or single "M" flag can indicate timestomping (T1070.006) or later tampering. `mactime` interprets body-file times as the timezone set by `-z` (default local) — always record the timezone used.

6. `photorec` — carve recoverable files from the raw image (batch/non-interactive mode). PhotoRec ignores the filesystem and matches known file-signature headers/footers, so it recovers data even after the directory entry and metadata are gone. See https://www.cgsecurity.org/wiki/PhotoRec and https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step.
```bash
mkdir -p /tmp/carved
photorec /log /d /tmp/carved /cmd exercise/sample.dd partition_none,options,mode_ext2,fileopt,everything,enable,search
ls -R /tmp/carved
```
Expected observable output: PhotoRec writes recovered files into `/tmp/carved/recup_dir.1/` and prints a summary of the number of files recovered by type. Nuance: `/log` writes a `photorec.log` audit trail, `/d` sets the recovery destination, and `/cmd ... search` runs the carve non-interactively; `partition_none` treats the whole image as one blob (correct when there is no partition table), and `mode_ext2` disables filesystem-aware optimizations so carving is signature-only. Carved files are renamed by PhotoRec (original names are not stored in signatures), so recovered filenames will NOT match the originals — this is expected behavior of signature carving.

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
- **Timeline-to-alert correlation.** In Security Onion, pivot from a Suricata IDS alert (Alerts interface) to the flow record in Zeek `conn.log` and its `ts` field, then window your `mactime` output to that timestamp ±5 minutes to find files whose Born ("B") time coincides with C2 or download activity (payload staging, T1105 Ingress Tool Transfer). Security Onion documents the Alerts/Hunt/Dashboards pivots and its Zeek/Suricata data sources: https://docs.securityonion.net/en/2.4/alerts.html and https://docs.securityonion.net/en/2.4/zeek.html.
- **Download → disk artifact linkage.** Zeek `files.log` records extracted file hashes (MD5/SHA1) and `http.log`/`dns.log` record the retrieval; match those hashes against the sha256 you compute on carved/`icat`-recovered files to prove a network-observed download landed on disk (supports T1105 and T1005 Data from Local System). Zeek logging reference: https://docs.zeek.org/en/master/logs/index.html.
- **Deletion / anti-forensics detection.** An `fls -r` listing full of `*`-marked entries clustered in a short window, combined with a `mactime` gap, is a strong signal of T1070.004 (File Deletion) or T1070.006 (Timestomp). Flag files where the metadata timestamps are internally inconsistent (e.g. a Created time later than Modified) as possible timestomping.
- **Persistence hunting.** Surface autostart artifacts (registry run keys / services on Windows images, `cron`/`systemd`/`~/.bashrc` on Linux images) in the `mactime` output to detect T1547 and T1053 (Scheduled Task/Job), then hash and push those filenames/hashes into Security Onion's Hunt interface (https://docs.securityonion.net/en/2.4/hunt.html) to sweep the rest of the fleet.

**Additional MITRE ATT&CK techniques:**
- **T1055.001** – Process Injection (via memory analysis tools like Volatility, but can also be identified through `mactime` if an attacker's process is launched from a deleted or obfuscated file).
- **T1038** – Access Token Manipulation (detectable via timeline analysis if an attacker's process is launched from a deleted or obfuscated file or through `icat`-recovered logs).

**Detection Engineering:**
- **Sigma Rule Example (File Deletion):**
  ```yaml
  title: File Deletion Detected via Sleuth Kit
  description: Detects suspicious file deletions using Sleuth Kit's `fls` output.
  logsource:
    category: file
    product: sleuthkit
  detection:
    selection:
      - EventData: "*"
      - EventData: "deleted"
    condition: selection
  falsepositives:
    - Legitimate file cleanup
  level: medium
  ```
- **Suricata Rule Example (File Deletion):**
  ```suricata
  alert http any any -> any any (msg:"File Deletion Detected"; content:"deleted"; sid:1000001;)
  ```

## Attacker perspective
Attackers know that deleting a file with `rm` or emptying the recycle bin only unlinks the directory entry — the underlying blocks (and often the file data) remain until overwritten, which is exactly what `icat` and `photorec` recover. Adversaries performing T1070.004 (Indicator Removal: File Deletion) and T1485 (Data Destruction) may wipe tools, staged archives, or logs, but leave carveable remnants, orphaned MFT/inode entries, and telltale timeline gaps that `fls -r` exposes with the `*` deleted marker. Even secure-delete or partition-wiping attempts leave artifacts: `mmls` still shows the raw layout and `testdisk` can rebuild a deleted/overwritten partition table from backup structures (https://www.cgsecurity.org/wiki/TestDisk), while PhotoRec carves file bodies independent of any partition metadata. These residual structures are exactly what carving and metadata analysis exploit.

Concrete TTPs, artifacts left behind, and evasion:
- **T1070.004 – File Deletion.** `rm`/recycle-bin/`del` only clears the directory pointer; on NTFS the MFT record is marked unallocated but persists until reused, and on FAT the first byte of the 8.3 name is set to `0xE5` while the cluster chain data survives — both are recoverable with `icat` and visible as `*` entries in `fls`. MITRE reference: https://attack.mitre.org/techniques/T1070/004/.
- **T1070.006 – Timestomp.** Attackers use tools (e.g. `SetMACE`, PowerShell, `touch -d`) to backdate timestamps and blend into system files. Defenders counter this on NTFS by comparing the `$STANDARD_INFORMATION` timestamps (what most tools alter) against the harder-to-forge `$FILE_NAME` timestamps in the MFT. MITRE reference: https://attack.mitre.org/techniques/T1070/006/.
- **T1485 – Data Destruction.** Wiping partition tables or superblocks makes an image look empty to a naive mount, but `mmls` still shows the raw layout and `testdisk` can rebuild a deleted/overwritten partition table from backup structures (https://www.cgsecurity.org/wiki/TestDisk), while PhotoRec carves file bodies independent of any partition metadata. MITRE reference: https://attack.mitre.org/techniques/T1485/.
- **Evasion and its limits.** True anti-forensics requires overwriting the data blocks (e.g. `shred`, `dd if=/dev/zero`, full-disk crypto-erase), not just deletion — but partial wipes leave file **slack** (the unused tail of the last cluster) holding fragments of prior content, and journaled filesystems (ext3/4 journal, NTFS `$LogFile`/`$UsnJrnl`) retain metadata about files that no longer exist. These residual structures are exactly what carving and metadata analysis exploit. General Sleuth Kit/DFIR reference: https://www.sleuthkit.org/sleuthkit/docs.php and the SANS DFIR resources at https://www.sans.org/posters/windows-forensic-analysis/.

**Additional MITRE ATT&CK techniques:**
- **T1055.001** – Process Injection (via memory analysis tools like Volatility, but can also be identified through `mactime` if an attacker's process is launched from a deleted or obfuscated file).
- **T1038** – Access Token Manipulation (detectable via timeline analysis if an attacker's process is launched from a deleted or obfuscated file or through `icat`-recovered logs).

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
- **T1070.004** – Indicator Removal: File Deletion (recovered via `icat`/`photorec`). https://attack.mitre.org/techniques/T1070/004/
- **T1070.006** – Indicator Removal: Timestomp (detected via MACB inconsistencies in the `mactime` timeline / MFT `$SI` vs `$FN` comparison). https://attack.mitre.org/techniques/T1070/006/
- **T1485** – Data Destruction (partition/disk tampering detected via `mmls`/`testdisk`). https://attack.mitre.org/techniques/T1485/
- **T1005** – Data from Local System (files identified/exported from the image). https://attack.mitre.org/techniques/T1005/
- **T1547** – Boot or Logon Autostart Execution (persistence artifacts surfaced in `mactime` timeline). https://attack.mitre.org/techniques/T1547/
- **T1055.001** – Process Injection (via timeline analysis or memory forensics). https://attack.mitre.org/techniques/T1055/001/
- **T1038** – Access Token Manipulation (detectable via timeline analysis or log carving). https://attack.mitre.org/techniques/T1038/
- **DFIR phase:** Identification and Examination (evidence acquisition triage, filesystem analysis, timeline reconstruction, and deleted-file recovery).

## Sources
Claim → source mapping (all URLs are official tool/project docs, MITRE ATT&CK, SANS, or recognized vendor/project sites):

- Sleuth Kit is a library + CLI tool collection for analyzing disk images and recovering files; tool inventory (`mmls`, `fsstat`, `fls`, `icat`, `mactime`): https://www.sleuthkit.org/sleuthkit/tools.php and https://www.sleuthkit.org/sleuthkit/docs.php
- `mmls` behavior (volume-system layout, sector offsets, `-o` usage downstream): https://www.sleuthkit.org/sleuthkit/man/mmls.html
- `fsstat` behavior (FILE SYSTEM INFORMATION, filesystem type, cluster/sector size): https://www.sleuthkit.org/sleuthkit/man/fsstat.html
- `fls` behavior (`-r` recursive, `*` deleted marker, `-m` body-file output, `-V` version): https://www.sleuthkit.org/sleuthkit/man/fls.html
- `icat` behavior (stream file content by metadata address): https://www.sleuthkit.org/sleuthkit/man/icat.html
- `mactime` behavior (body-file input `-b`, CSV `-d`, MACB sorting, timezone `-z`): https://www.sleuthkit.org/sleuthkit/man/mactime.html
- Autopsy graphical platform (modern 4.x): https://www.autopsy.com/ ; legacy 2.x web UI on port 9999 in Kali package: https://www.kali.org/tools/autopsy/
- PhotoRec — signature-based carving, run-time options `/log /d /cmd`, `recup_dir.N` output, filename renaming: https://www.cgsecurity.org/wiki/PhotoRec and https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step
- TestDisk — recover/rebuild lost or damaged partition tables: https://www.cgsecurity.org/wiki/TestDisk
- PhotoRec/TestDisk shipped in a single `testdisk` package: https://www.kali.org/tools/testdisk/
- Kali Linux Tools — Sleuth Kit: https://www.kali.org/tools/sleuthkit/
- SANS DFIR — SIFT Workstation (lab platform): https://www.sans.org/tools/sift-workstation/
- SANS DFIR — Windows Forensic Analysis poster ($SI vs $FN, timeline/anti-forensics context): https://www.sans.org/posters/windows-forensic-analysis/
- Security Onion — Alerts interface / pivots: https://docs.securityonion.net/en/2.4/alerts.html
- Security Onion — Hunt interface: https://docs.securityonion.net/en/2.4/hunt.html
- Security Onion — Zeek data source: https://docs.securityonion.net/en/2.4/zeek.html
- Zeek logging reference (`conn.log`, `files.log`, `http.log`, `dns.log`): https://docs.zeek.org/en/master/logs/index.html
- MITRE ATT&CK — T1070.004 Indicator Removal: File Deletion: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK — T1070.006 Indicator Removal: Timestomp: https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK — T1485 Data Destruction: https://attack.mitre.org/techniques/T1485/
- MITRE ATT&CK — T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK — T1547 Boot or Logon Autostart Execution: https://attack.mitre.org/techniques/T1547/
- MITRE ATT&CK — T1055.001 Process Injection: https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK — T1038 Access Token Manipulation: https://attack.mitre.org/techniques/T1038/

## Related modules
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- shares autopsy
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares sleuth kit
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares sleuth kit
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations)

<!-- cyberlab-enriched: v2 -->
