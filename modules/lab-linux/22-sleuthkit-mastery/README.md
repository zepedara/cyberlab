# 22 * The Sleuth Kit command mastery -- LAB-LINUX

## Overview (plain language)
The Sleuth Kit (TSK) is a collection of small command-line programs that let you look inside a disk image the way a detective looks inside a locked house — without touching or altering the original evidence. Instead of double-clicking files in a normal file browser (which changes timestamps and can miss hidden or deleted data), TSK reads the raw bytes of a disk image and reconstructs the partitions, the file system, the folder tree, individual files, and even fragments of files that were deleted but not yet overwritten. Autopsy is the friendly graphical front-end that wraps those same TSK commands in a point-and-click case management interface. Together they let an investigator answer questions like "what files were on this drive, when were they created, and what was deleted?" — all in a read-only, forensically sound way. (Autopsy is described by its maintainers as a GUI that acts as a front end to The Sleuth Kit and other tools — see https://www.sleuthkit.org/autopsy/ .)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Sleuth Kit | apt install sleuthkit | Command-line suite to examine disk images, list partitions, walk file systems, and recover files/metadata read-only |
| Autopsy | apt install autopsy | Graphical case-management front-end that drives Sleuth Kit for timeline, keyword, and file analysis |

Sources for these tools and packages: The Sleuth Kit project page (https://www.sleuthkit.org/sleuthkit/) and Autopsy project page (https://www.sleuthkit.org/autopsy/); Kali package pages https://www.kali.org/tools/sleuthkit/ and https://www.kali.org/tools/autopsy/ .

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

Note on flags: TSK command-line tools accept `-V` to print the version banner (see the per-tool manual pages under https://www.sleuthkit.org/sleuthkit/man/ — e.g. `mmls` https://www.sleuthkit.org/sleuthkit/man/mmls.html and `fls` https://www.sleuthkit.org/sleuthkit/man/fls.html). The exact version string you see depends on your installed package; TSK 4.12.x is a real release line documented on the project's GitHub releases page (https://github.com/sleuthkit/sleuthkit/releases). If `autopsy -V` behaves differently on your build, `autopsy` with no arguments prints usage/startup text (Autopsy user docs: https://www.sleuthkit.org/autopsy/docs.php).

## Guided walkthrough
1. `mmls` — reads the **volume system / partition table** (DOS, GPT, BSD, Sun, Mac) of a raw image and prints each slot with its starting sector (offset). WHY: file-system tools like `fsstat`/`fls` need to know where a volume *begins* inside the whole-disk image, because a `dd` of a full disk contains a partition table followed by one or more volumes. `mmls` gives you that starting sector so you can pass it to `-o`. Nuance: `mmls` lists **unallocated** gaps too (slots labelled "Unallocated"), which can hide data between partitions. See https://www.sleuthkit.org/sleuthkit/man/mmls.html .
```bash
mmls exercise/practice.dd
```
Expected: a table listing partition entries with `Slot`, `Start`, `End`, `Length`, and `Description` columns. Values are in **sectors** (default 512 bytes each) unless overridden with `-b`.

2. `fsstat` — reports file-system details (type, block/cluster size, inode/FAT range, layout). WHY: confirms the volume type detected at the offset and gives you the block size and metadata ranges you'll reference later; a wrong `-o` offset produces a "Cannot determine file system type" error, which is your signal the offset is off. Feed the partition start sector with `-o`. See https://www.sleuthkit.org/sleuthkit/man/fsstat.html .
```bash
fsstat -o 2048 exercise/practice.dd
```
Expected: file system type (e.g. FAT16/NTFS/Ext), sector/cluster sizes, and metadata/content ranges. For a FAT volume it reports the FAT layout, cluster size, and the root-directory location.

3. `fls` — lists file and directory entries in a directory or across the volume, **including deleted ones** (the entry name is prefixed with `*`). WHY: this is your primary enumeration step — it surfaces both live and deleted directory entries with their metadata address (inode/MFT entry number) so you can target specific files. `-r` recurses into subdirectories, `-d` restricts output to deleted entries. Nuance: the two-letter type prefix (`r/r`, `d/d`) is "directory-entry type / metadata type"; a mismatch (e.g. `-/r`) indicates the directory entry is gone but the metadata was recovered — typical of deletion. See https://www.sleuthkit.org/sleuthkit/man/fls.html .
```bash
fls -r -o 2048 exercise/practice.dd
```
Expected: a tree of entries such as `r/r 4: readme.txt` and deleted lines like `-/r * 6: secret.txt`.

4. `istat` — dumps the metadata (allocation status, size, MAC(B) timestamps, and the list of allocated data units) for one metadata address. WHY: after `fls` gives you an inode number, `istat` tells you *when* the file was created/modified/accessed and *which blocks/clusters* hold its content — essential for both recovery and timestamp analysis. Nuance: on NTFS the timestamps come from `$STANDARD_INFORMATION` and `$FILE_NAME` attributes, which is exactly where timestomping discrepancies show up. See https://www.sleuthkit.org/sleuthkit/man/istat.html .
```bash
istat -o 2048 exercise/practice.dd 4
```
Expected: allocation status, size in bytes, MAC times, and the data-unit list for inode/metadata address 4.

5. `icat` — streams the raw content referenced by a metadata address to stdout so you can recover a file. WHY: this is the recovery step — it reads the data units listed by the file's metadata and writes the bytes out, which works even for deleted files as long as the metadata still points at not-yet-overwritten clusters. Nuance: piping to `head` avoids dumping binary to the terminal; for a full recovery redirect to a file. See https://www.sleuthkit.org/sleuthkit/man/icat.html .
```bash
icat -o 2048 exercise/practice.dd 4 | head
```
Expected: the file's contents printed to the terminal.

6. `fls` + `mactime` — build a **body file** and render a chronological timeline. WHY: `fls -m` emits pipe-delimited body-file records (the TSK 3.x+ body-file format), and `mactime` sorts those records by timestamp into a MAC(B)-ordered human-readable timeline, which is how you see the sequence of drop → execute → delete activity. Nuance: the `-m /` argument prepends a mount-point prefix to paths; `mactime -d` outputs comma-delimited (CSV) rows. See https://www.sleuthkit.org/sleuthkit/man/fls.html and https://www.sleuthkit.org/sleuthkit/man/mactime.html , and the body-file format reference https://wiki.sleuthkit.org/index.php?title=Body_file .
```bash
fls -r -m / -o 2048 exercise/practice.dd > exercise/bodyfile.txt
mactime -b exercise/bodyfile.txt -d > exercise/timeline.csv
```
Expected: `timeline.csv` with dated rows of MACB activity.

7. `autopsy` — start the GUI/case tool to work the same image as a case. WHY: Autopsy drives the same TSK engine under the hood but adds case management, keyword search, and timeline visualization; understanding the CLI helps you interpret what Autopsy shows. Nuance: modern Autopsy is primarily a Windows-based Java application, while the legacy `autopsy` package on Linux launches a local browser-based service — behavior depends on your distribution's package. See https://www.sleuthkit.org/autopsy/docs.php .
```bash
autopsy --help
```
Expected: usage/help text describing how to start the Autopsy service and open a case.

## Hands-on exercise
Work against the sample image in this module's `exercise/` directory.

- **Sample:** `exercise/practice.dd`
- **Type:** raw (`dd`) disk image containing a single small FAT16 file system.
- **Safe origin:** benign/inert. Generated in-lab with no network egress by creating a zeroed image, formatting a FAT16 file system, copying two harmless text files (`readme.txt`, `secret.txt`), deleting `secret.txt`, then unmounting. It contains NO malware and NO real personal data.
- **sha256:** `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

**Task:**
1. Find the FAT partition offset with `mmls`.
2. Recover the content of the **deleted** file and record the exact string it contains.
3. Produce a timeline and identify which file was deleted most recently.

## SOC analyst perspective
During incident response a defender receives a disk image from a suspected-compromised host and must reconstruct attacker activity without altering evidence. The Sleuth Kit lets an analyst carve deleted files, read `$MFT`/inode timestamps, and build a filesystem timeline that shows when malware was dropped, executed, and cleaned up.

**Concrete detection logic and pivots:**
- **Deleted-tool recovery → T1070.004 (File Deletion).** Run `fls -r -d -o $OFFSET $IMAGE` to enumerate every deleted directory entry, then `icat` the ones that match known-bad names or extensions. The presence of recently deleted executables/scripts in staging or temp paths is a strong signal of anti-forensic cleanup. MITRE: https://attack.mitre.org/techniques/T1070/004/ .
- **Timestamp anomalies → T1070.006 (Timestomp).** Use `istat -o $OFFSET $IMAGE $INODE` and compare timestamps. On NTFS, defenders correlate `$STANDARD_INFORMATION` vs `$FILE_NAME` times; a `$STANDARD_INFORMATION` created time that is *earlier* than or grossly inconsistent with the `$FILE_NAME` time (or sub-second precision zeroed out) suggests timestomping. MITRE: https://attack.mitre.org/techniques/T1070/006/ . SANS FOR508 filesystem timeline guidance and the SANS Windows Forensics posters describe MFT timestamp comparison (https://www.sans.org/posters/windows-forensic-analysis/).
- **Staging directories → T1074 / collection → T1005.** A `mactime` timeline that shows a burst of file *creations* in one directory shortly before an exfil-related network event is classic data staging. MITRE: https://attack.mitre.org/techniques/T1074/ and https://attack.mitre.org/techniques/T1005/ .
- **File and Directory Discovery → T1083.** The `fls` command enumerates the file system, mirroring an attacker's reconnaissance. A timeline showing rapid, sequential enumeration of directories like `C:\Users\`, `C:\Windows\System32\`, or `/etc/` can indicate post-exploitation discovery. MITRE: https://attack.mitre.org/techniques/T1083/ .
- **Ingress Tool Transfer → T1105.** A timeline entry showing a file creation in a temporary directory (e.g., `C:\Windows\Temp\` or `/tmp/`) followed by a `mactime` "B" (born) timestamp that aligns with a Zeek `files.log` entry for a file transfer over HTTP/SMB can confirm lateral movement or tool download. MITRE: https://attack.mitre.org/techniques/T1105/ .

**Security Onion pivots.** Feed the `mactime` timeline alongside network telemetry: pivot from a **Suricata** alert or a **Zeek** `files.log`/`conn.log` entry (file hash, transfer time, destination) in the Security Onion Elastic stack to the exact on-disk file and timestamp produced by TSK, tying the network indicator to the host artifact. Security Onion documents Zeek, Suricata, and the Elastic-based investigation workflow: https://docs.securityonion.net/ (see the Zeek and Suricata sections). Zeek log reference: https://docs.zeek.org/en/master/logs/index.html ; Suricata docs: https://docs.suricata.io/ .

**Detection Engineering Logic:**
- **Windows Event ID 4663 (File System Object Access)** can be correlated with `fls` output. A file accessed (Event ID 4663) with a `Process Name` of a suspicious binary (e.g., `powershell.exe`) and a `Access Mask` indicating `DELETE` access, followed by the absence of the file in a live directory listing but its presence in `fls -d` output, confirms T1070.004. Source: Microsoft Learn on Event ID 4663 (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663).
- **Zeek `files.log` field `seen.bytes` vs. `icat` recovered size.** If a file transferred over the network (logged in `files.log` with `tx_hosts` and `rx_hosts`) has a `seen.bytes` value, compare it to the size of a recovered deleted file from `icat`. A mismatch may indicate partial transfer or file corruption, which could be a sign of evasion. Source: Zeek documentation on `files.log` (https://docs.zeek.org/en/master/logs/files.html).
- **Suricata `fileinfo` keyword and file storage.** Suricata can extract files via the `file-store` feature. The hash of a file extracted by Suricata (e.g., SHA256) can be compared to the hash of a file recovered via `icat` to confirm the same artifact was both transferred and stored on disk. Source: Suricata File Extraction and Storage (https://docs.suricata.io/en/suricata-7.0.0/file-extraction/file-extraction.html).

## Attacker perspective
An adversary who wants to hide activity will delete tools, clear logs, and timestomp files — but on most file systems deletion only unlinks the directory entry, leaving the data and metadata recoverable until overwritten.

**Concrete TTPs and the artifacts they leave:**
- **T1070.004 File Deletion.** Deleting dropped tooling (`rm`, `del`, secure-delete utilities) removes the live directory entry but, on FAT/NTFS/ext, typically leaves recoverable metadata and unallocated data units. Artifacts: `fls`-visible deleted entries (`* ` prefix), orphaned inodes/MFT records, and file content still readable via `icat` until the clusters are reallocated. MITRE: https://attack.mitre.org/techniques/T1070/004/ .
- **T1070.006 Timestomp.** Rewriting timestamps (e.g. with tools that set `$STANDARD_INFORMATION` times) to blend a malicious file into surrounding "normal" files. Artifacts: MAC-time inconsistencies exposed by `istat` — e.g. a modified time predating the created time, `$STANDARD_INFORMATION`/`$FILE_NAME` mismatches on NTFS, or implausibly round timestamps. MITRE: https://attack.mitre.org/techniques/T1070/006/ .
- **T1074 Data Staged / T1005 Data from Local System.** Collecting and staging files before exfiltration leaves creation clusters and timeline bursts that survive later deletion. MITRE: https://attack.mitre.org/techniques/T1074/ and https://attack.mitre.org/techniques/T1005/ .
- **T1083 File and Directory Discovery.** Attackers often enumerate directories to locate valuable data. This leaves a trace in the `$MFT` or inode timestamps (`istat` accessed times) and in the `fls` timeline as a cluster of `a` (accessed) timestamps across many directories in a short period. MITRE: https://attack.mitre.org/techniques/T1083/ .
- **T1105 Ingress Tool Transfer.** Downloading tools to a victim host creates file system artifacts. Even if the file is deleted, `fls` can show the deleted entry in the download directory (e.g., `/tmp/`, `C:\Windows\Temp\`), and `icat` can recover the tool binary for analysis. MITRE: https://attack.mitre.org/techniques/T1105/ .

**Evasion and its limits.** To truly defeat recovery an attacker must overwrite the data (wiping/secure-delete) or destroy the volume — mere deletion is not enough, and even overwriting can leave slack-space fragments. An attacker may run TSK-style tools themselves to check what residue their operations leave. Every recovered deleted file, every mismatched timestamp, and every unallocated data unit becomes evidence a defender can extract with `fls`, `istat`, and `icat` (see TSK man pages linked in the walkthrough). Advanced attackers may use **T1027 Obfuscated Files or Information** (https://attack.mitre.org/techniques/T1027/) to hide malicious content within otherwise benign-looking files, but `icat` can still extract the raw bytes for further analysis. They may also use **T1564 Hide Artifacts** (https://attack.mitre.org/techniques/T1564/) by storing data in hidden or alternate data streams (ADS), which `fls` can reveal on NTFS volumes when used with the `-s` flag to display ADS streams.

## Answer key
Sample sha256: `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

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
- **T1070.004** — Indicator Removal: File Deletion (recovered via `fls`/`icat`). https://attack.mitre.org/techniques/T1070/004/
- **T1070.006** — Indicator Removal: Timestomp (exposed via `istat` MAC-time analysis). https://attack.mitre.org/techniques/T1070/006/
- **T1005** — Data from Local System (https://attack.mitre.org/techniques/T1005/); **T1074** — Data Staged (https://attack.mitre.org/techniques/T1074/), identified through file enumeration/timeline bursts.
- **T1083** — File and Directory Discovery (detected via `fls` timeline showing rapid directory access). https://attack.mitre.org/techniques/T1083/
- **T1105** — Ingress Tool Transfer (correlated via timeline file creation events and network logs). https://attack.mitre.org/techniques/T1105/
- **DFIR phases:** Examination and Analysis (evidence acquisition assumed complete; TSK operates read-only on the acquired image), feeding into Reporting. This maps to the classic DFIR/NIST SP 800-86 phases of Examination → Analysis → Reporting (https://csrc.nist.gov/pubs/sp/800/86/final).

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- Sleuth Kit tool suite, purpose, read-only operation — The Sleuth Kit project: https://www.sleuthkit.org/sleuthkit/ ; command docs index: https://www.sleuthkit.org/sleuthkit/docs.php
- TSK per-command behavior and flags:
  - `mmls` (volume/partition listing, sector offsets, `-b`): https://www.sleuthkit.org/sleuthkit/man/mmls.html
  - `fsstat` (file-system details, `-o`): https://www.sleuthkit.org/sleuthkit/man/fsstat.html
  - `fls` (file/deleted-entry listing, `-r`, `-d`, `-m`, `-o`, `-s` for ADS): https://www.sleuthkit.org/sleuthkit/man/fls.html
  - `istat` (metadata/MAC times/data units): https://www.sleuthkit.org/sleuthkit/man/istat.html
  - `icat` (content recovery to stdout): https://www.sleuthkit.org/sleuthkit/man/icat.html
  - `mactime` (body-file → timeline, `-b`, `-d`): https://www.sleuthkit.org/sleuthkit/man/mactime.html
- Body-file format used by `fls -m` / `mactime`: https://wiki.sleuthkit.org/index.php?title=Body_file
- TSK version/release line (e.g. 4.12.x) — GitHub releases: https://github.com/sleuthkit/sleuthkit/releases
- Autopsy as a GUI front-end to TSK, and startup/case docs: https://www.sleuthkit.org/autopsy/ and https://www.sleuthkit.org/autopsy/docs.php
- SANS — The Sleuth Kit tool page: https://www.sans.org/tools/the-sleuth-kit/
- SANS — Windows Forensic Analysis poster (MFT timestamp / `$STANDARD_INFORMATION` vs `$FILE_NAME` comparison, timeline analysis): https://www.sans.org/posters/windows-forensic-analysis/
- Kali packages: sleuthkit https://www.kali.org/tools/sleuthkit/ ; autopsy https://www.kali.org/tools/autopsy/
- MITRE ATT&CK techniques:
  - T1070 Indicator Removal: https://attack.mitre.org/techniques/T1070/
  - T1070.004 File Deletion: https://attack.mitre.org/techniques/T1070/004/
  - T1070.006 Timestomp: https://attack.mitre.org/techniques/T1070/006/
  - T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/
  - T1074 Data Staged: https://attack.mitre.org/techniques/T1074/
  - T1083 File and Directory Discovery: https://attack.mitre.org/techniques/T1083/
  - T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
  - T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
  - T1564 Hide Artifacts: https://attack.mitre.org/techniques/T1564/
- Security Onion / NIDS pivots:
  - Security Onion docs (Zeek, Suricata, Elastic investigation): https://docs.securityonion.net/
  - Zeek log reference: https://docs.zeek.org/en/master/logs/index.html
  - Zeek `files.log` documentation: https://docs.zeek.org/en/master/logs/files.html
  - Suricata docs: https://docs.suricata.io/
  - Suricata File Extraction and Storage: https://docs.suricata.io/en/suricata-7.0.0/file-extraction/file-extraction.html
- Windows Event Log correlation:
  - Microsoft Learn on Event ID 4663 (File System Object Access): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
- DFIR phase model — NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response): https://csrc.nist.gov/pubs/sp/800/86/final

## Related modules
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- shares autopsy for GUI-driven examination of the same images you analyze here on the CLI.
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares sleuth kit to build `mactime` timelines in a full intrusion narrative.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares sleuth kit as part of a complete Linux host triage workflow.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives), pairing memory forensics with the disk forensics covered here.

<!-- cyberlab-enriched: v2 -->
