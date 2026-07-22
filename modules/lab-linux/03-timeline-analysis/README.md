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
- **Credential dumping (T1003):** detect process access events to `lsass.exe` (Sysmon Event ID 10) or Windows Event ID 4663 (a handle was requested on an object) when the object is `lsass.exe`. In the timeline, look for the creation of a dump file (e.g., `lsass.dmp`) or the presence of Mimikatz-related files (e.g., `mimikatz.exe`, `kiwi.dll`). Plaso's `sysmon` and `winevtx` parsers can surface these events. Filter with `psort.py` using `sourcetype == 'sysmon' AND desc LIKE '%lsass%'` or `filename LIKE '%lsass.dmp%'`.
- **Impair defenses (T1562):** detect disabling of Windows Defender via registry changes (Event ID 4657 for registry modification to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1`) or by stopping services (`net stop WinDefend`). Plaso's registry parser captures these events. Look for `sourcetype == 'Windows Registry' AND data LIKE '%DisableAntiSpyware%'` or `desc LIKE '%WinDefend%'`.
- **Threat-hunting pivots:**
  - **Zeek `conn.log` correlation:** match file download/completion timestamps from Zeek `http.log` (field `ts`) to the `Date` column of a Plaso timeline to identify the initial ingress of a malicious payload. Use the `md5` or `sha1` from Zeek `files.log` to cross-reference with Plaso `filestat` events for that file.
  - **Suricata DNS alerts:** correlate DNS queries for known-bad domains (Suricata `dns.log` with `dns.type == 'query'`) with file creation times in the timeline to establish a bring-your-own-land (BYOL) tool download chain.
  - **Elastic/Kibana host events:** pivot from a high-severity Elastic rule (e.g., "Windows Event ID 1102 – Audit Log Cleared") to a Plaso timeline slice covering the same time range to find related file-system events like temporary file drops.
- **Detection-engineering logic:**
  - **Event ID 4663 (handle to lsass):** filter on `EventID == 4663` and `ObjectName == '\Device\HarddiskVolume?\Windows\System32\lsass.exe'` and `AccessMask == 0x1FFFFF` (full control). This is a strong indicator of credential dumping and can be mapped to T1003.
  - **Sysmon Event ID 1 (process creation) for `wbadmin`/`vssadmin`:** detect VSS deletion events (T1490) by filtering on `CommandLine` containing `'wbadmin delete catalog'` or `'vssadmin delete shadows'`. Plaso's `sysmon` parser captures these.
  - **Registry event for defender disable:** use `EventID == 4657` and `ObjectName == 'HKLM\...\DisableAntiSpyware'` and `NewValue == '0x00000001'` to detect T1562.001.

These detection strategies map to MITRE ATT&CK techniques T1070.006, T1070.001, T1074, T1003, T1562.001, and T1490.

## Attacker perspective
Attackers know timelines betray them, so they attempt anti-forensics. Concrete TTPs, the artifacts they leave, and evasion notes:
- **Timestomping (T1070.006):** tools like SetMACE, `timestomp`, or a simple `touch -d` set a file's SI timestamps to blend into OS-install dates (technique documented at https://attack.mitre.org/techniques/T1070/006/). Artifact: on NTFS the `$FILE_NAME` attribute timestamps are updated by the kernel and are far harder to forge, so SI-vs-FN divergence and an MFT sequence/record number inconsistent with an "old" born date remain. Evasion attempt: some tools also rewrite FN times via lower-level writes, but nanosecond-precision truncation (SI times ending in zeros) is itself an indicator noted in DFIR guidance (SANS FOR508, https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).
- **Clearing event logs (T1070.001):** `wevtutil cl`, `Clear-EventLog`, or `Remove-Item` on `.evtx` files (https://attack.mitre.org/techniques/T1070/001/). Artifact: Windows writes Event ID 1102 ("The audit log was cleared", https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102) and leaves a suspicious gap in the timeline; on Linux, truncated `/var/log` files show reset inode/size timings.
- **Wiping browser history:** deleting history/cache leaves the SQLite databases with unallocated/freed pages and shifts the file's own MACB times, which Plaso's browser and `filestat` parsers still record.
- **Credential dumping (T1003):** tools like Mimikatz (`sekurlsa::logonpasswords`), `procdump` on `lsass.exe`, or `comsvcs.dll` Minidump (https://attack.mitre.org/techniques/T1003/). Artifact: creation of a dump file (e.g., `lsass.dmp`), process access events to `lsass.exe` (Sysmon Event ID 10, Windows Event ID 4663 with AccessMask 0x1FFFFF), or presence of Mimikatz modules in memory (detectable by Plaso's prefetch parser if executed). Evasion attempt: attackers use crypters or reflective loading (T1620) to avoid writing Mimikatz to disk. However, Plaso's process-creation events (if Sysmon is enabled) still show the `rundll32.exe` or `powershell.exe` that loaded the dump code.
- **Impair defenses (T1562.001):** attackers disable Windows Defender via registry (`DisableAntiSpyware = 1`), stop the service (`net stop WinDefend`), or add exclusions (https://attack.mitre.org/techniques/T1562/001/). Artifact: registry modifications captured by Plaso's Registry parser; event log entries for service stop (Event ID 7036). Evasion attempt: attackers may use PowerShell script blocks to execute these changes without writing to disk, but the Windows Event Log still captures the script block (Event ID 4104) if PowerShell logging is enabled.

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
- **T1003** — Credential Dumping (detect via process access to lsass.exe, dump file creation, Mimikatz artifacts). https://attack.mitre.org/techniques/T1003/
- **T1070.006** — Indicator Removal: Timestomp (detect via MACB / SI-vs-FN inconsistencies in the super-timeline). https://attack.mitre.org/techniques/T1070/006/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs (gaps or missing log events; Event ID 1102). https://attack.mitre.org/techniques/T1070/001/
- **T1074** — Data Staged (staging directories revealed by clustered filesystem creation times). https://attack.mitre.org/techniques/T1074/
- **T1119** — Inhibit System Recovery (deletion or modification of backup files). https://attack.mitre.org/techniques/T1119/
- **T1490** — Inhibit System Recovery (VSS deletion via wbadmin/vssadmin). https://attack.mitre.org/techniques/T1490/
- **T1562.001** — Impair Defenses: Disable or Modify Tools (registry disabling of Windows Defender). https://attack.mitre.org/techniques/T1562/001/
- **T1059.003** — Command and Scripting Interpreter: PowerShell (execution of PowerShell scripts or commands). https://attack.mitre.org/techniques/T1059/003/
- **DFIR phase:** Examination / Analysis (timeline reconstruction and event correlation).

### Essential Commands & Features

When conducting timeline analysis with **Plaso**, mastering parser selection and filtering is critical for efficiency. Below are two **undemonstrated but highly useful** commands and features:

#### 1. **List and Select Parsers with `--parsers`**
Plaso supports **100+ parsers**, but enabling all can slow processing. Use `--parsers` to list available parsers or specify only those relevant to your investigation (e.g., `winreg`, `prefetch`, `sqlite/chrome_history`). This is particularly useful when targeting **T1005 (Data from Local System)** or **T1560 (Archive Collected Data)**.

**Example (List all parsers):**
```bash
log2timeline.py --parsers list
```
**Example (Process only Windows Registry and Chrome history):**
```bash
log2timeline.py --parsers winreg,sqlite/chrome_history timeline.plaso /evidence/
```

#### 2. **Filter `psort.py` Output by Sourcetype/Parser**
After generating a timeline, use `psort.py` with `--sourcetype` or `--parser` to isolate events from specific sources (e.g., `WEBHIST` for browser activity or `REG` for registry changes). This is invaluable for investigating **T1213 (Data from Information Repositories)**.

**Example (Extract only Chrome history events):**
```bash
psort.py -o l2tcsv --sourcetype WEBHIST timeline.plaso -w chrome_events.csv
```
**Example (Filter for Windows Registry events):**
```bash
psort.py -o l2tcsv --parser winreg timeline.plaso -w registry_events.csv
```

**Authoritative Sources:**
- [Plaso Parser Documentation (GitLab)](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html#specifying-parsers)
- [DFIR Review: Plaso Filtering Techniques (OSDFCon)](https://www.osdfcon.org/presentations/2021/Elizabeth-Schweinsberg_Plaso-Filtering.pdf)

### Threat Hunting & Detection Engineering
To enhance timeline analysis, threat hunting, and detection engineering, focus on identifying potential indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) aligned with MITRE ATT&CK techniques such as [T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482) and [T1622: Debugger Evasion](https://attack.mitre.org/techniques/T1622). Analyze Windows Event IDs related to domain trust modifications (e.g., ID 4662 for object access events) and debugger-related events. Utilize log sources like Windows Event Logs, PowerShell logs, and network capture data from tools like Zeek or Suricata to detect suspicious patterns. For example, inspecting Zeek's `http.log` for unusual user-agent strings or Suricata's `dns.log` for potential DNS tunneling attempts can serve as threat-hunting pivots. By integrating these detection logic elements and continuously monitoring for TTPs, defenders can improve their ability to detect and respond to threats. For further guidance on enhancing detection capabilities, refer to resources like the [CybOK](https://www.cybok.org/) knowledge base or the [NIST Special Publication 800-150](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf) for an understanding of cybersecurity and infrastructure resilience.


### Essential Commands & Features

Beyond basic log2timeline and psort operations, mastering these **undemonstrated** Plaso commands and flags will significantly enhance your timeline analysis efficiency:

#### **1. `psort.py` Advanced Filters**
- **`--slice`**: Extract events within a specific time window (critical for **T1071.001 Application Layer Protocol: Web Protocols** analysis).
  ```bash
  psort.py -o jsonl --slice "2023-05-15 14:00:00,2023-05-15 15:00:00" timeline.plaso
  ```
- **`--analysis`**: Run built-in analyzers (e.g., `browser_search`, `viper`) to detect **T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**.
  ```bash
  psort.py --analysis browser_search timeline.plaso
  ```
- **`--output-format json`**: Export to JSON for SIEM ingestion or scripting.
  ```bash
  psort.py --output-format json timeline.plaso > timeline.json
  ```

#### **2. `pinfo.py`**
Inspect storage metadata (e.g., hashes, parsers used) to validate evidence integrity:
```bash
pinfo.py timeline.plaso
```

#### **3. `image_export.py`**
Extract files from disk images for deeper forensic analysis (e.g., hunting **T1105 Ingress Tool Transfer** artifacts):
```bash
image_export.py --partitions all --signatures EXE,ZIP disk.E01 /output/dir
```

**Sources**:
- [Plaso CLI Reference (GitLab)](https://plaso.readthedocs.io/en/latest/sources/user/Using-the-tools.html)
- [DFIR Review: Plaso Filters for ATT&CK Techniques](https://www.dfir.review/2022/03/15/plaso-filters-for-mitre-attck/)

### Adversary Emulation & Red-Team Perspective

From an attacker’s perspective, timeline analysis is a double-edged sword: it reveals their actions but also offers opportunities for manipulation. Adversaries abuse timeline artifacts to blend in with legitimate activity or erase their tracks. A common tactic is **timestomping** (MITRE ATT&CK **T1070.006: Indicator Removal: Timestomp**), where attackers modify file timestamps (e.g., `$MFT` entries or `$STANDARD_INFORMATION` attributes) to mimic benign files or disrupt forensic reconstruction. For example, an attacker might alter the timestamps of a dropped payload to match those of a system binary, complicating detection during timeline analysis.

Another technique is **process hollowing** (MITRE ATT&CK **T1055.012: Process Injection: Process Hollowing**), where malicious code is injected into a suspended legitimate process (e.g., `svchost.exe`). This leaves minimal timeline artifacts, as the parent process appears normal, but the injected memory may contain traces of execution (e.g., `Prefetch` files, `Amcache.hve` entries, or `UserAssist` keys). Attackers may also leverage **T1564.003: Hide Artifacts: Hidden Window** to execute commands without visible console windows, reducing the likelihood of timeline entries tied to interactive sessions.

Evasion considerations include:
- **Disabling logging**: Clearing `Event Logs` (e.g., `wevtutil cl`) or disabling `Sysmon` to limit timeline artifacts.
- **Fileless techniques**: Using PowerShell (e.g., **T1059.001: Command and Scripting Interpreter: PowerShell**) to execute in-memory, avoiding disk-based timeline traces.
- **Time-based evasion**: Scheduling tasks (e.g., `schtasks`) to run during periods of high system activity, masking malicious events in noise.

**Sources**:
- [MITRE ATT&CK: T1070.006](https://attack.mitre.org/techniques/T1070/006/)
- [FireEye: Red Team Techniques for Evading Detection](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)


### Essential Commands & Features

Beyond basic timeline generation, mastering these **undemonstrated** Plaso/Log2Timeline commands and features will significantly enhance your analysis efficiency and depth:

#### **1. `psort.py` Advanced Filters**
- **`--slice`**: Extract events within a specific time window (e.g., during an intrusion). *Use when*: Isolating activity around a known compromise time (e.g., **T1566.001: Spearphishing Attachment**).
  ```bash
  psort.py -o jsonl --slice "2023-10-01 14:00:00,2023-10-01 15:00:00" timeline.plaso
  ```
- **`--analysis`**: Run built-in analyzers (e.g., `browser_search`, `windows_services`). *Use when*: Detecting **T1078.003: Local Accounts** via anomalous service creation.
  ```bash
  psort.py --analysis windows_services timeline.plaso
  ```
- **`--output-format json`**: Export to JSON for external tools (e.g., Timesketch). *Use when*: Collaborating or automating analysis pipelines.

#### **2. `pinfo.py` for Storage Inspection**
Inspect Plaso storage files for metadata (e.g., parsers used, collection time). *Use when*: Validating evidence integrity or troubleshooting parsing issues.
```bash
pinfo.py timeline.plaso
```

#### **3. Plaso Parallel Processing (`par`)**
Leverage multi-core processing for faster timeline generation. *Use when*: Processing large datasets (e.g., **T1113: Screen Capture** artifacts from multiple hosts).
```bash
log2timeline.py --workers 4 timeline.plaso evidence.raw
```

**Authoritative Sources**:
- [Plaso Advanced Usage (GitLab)](https://plaso.readthedocs.io/en/latest/sources/user/Advanced-usage.html)
- [DFIR Review: Plaso Performance Tuning](https://www.dfir.review/2022/03/15/plaso-performance-tuning/)

### Detection Signatures & Reference Artifacts

```yara
rule Detect_SystemInfo_Script {
    meta:
        description = "Detects benign scripts that invoke systeminfo and timeline analysis commands for educational timeline analysis exercise."
        author = "Defensive Training Module"
        reference = "https://yara.readthedocs.io/en/stable/writingrules.html"
        hash = "abcd1234ef567890ab1234cd567890ef12345678ab1234cd567890ef12345678ab"
    strings:
        $s1 = "systeminfo" nocase
        $s2 = "timeline" nocase
    condition:
        filesize < 100KB and 1 of ($s1, $s2)
}
```

```yaml
title: Detection of SystemInfo Command Usage via Command Line
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'systeminfo'
    condition: selection
```

**Reference artifacts / IOCs**

| Artifact Type | Indicator |
|---------------|-----------|
| File SHA256   | `abcd1234ef567890ab1234cd567890ef12345678ab1234cd567890ef12345678ab` |
| Filename      | `analyze_timeline.ps1` |
| Host artifact | Process creation event with command line containing `systeminfo` (e.g., Sysmon Event ID 1) |
| Network artifact | Connection to 192[.]0[.]2[.]2 (documentation-only IP) over TCP/443 for downloading a benign timeline analysis script |
| Domain        | timeline-analysis[.]local (non‑routable, lab‑internal) |

**MITRE ATT&CK Techniques Covered**
- [T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)

**Authoritative Sources**
- YARA documentation: <https://yara.readthedocs.io/en/stable/writingrules.html>
- Sigma specification & rule format: <https://github.com/SigmaHQ/sigma-specification>

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
- Microsoft Learn — Event 4663 "An attempt was made to access an object": https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
- Microsoft Learn — Event 4657 "A registry value was modified": https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657
- Sysmon — Event ID 10 (ProcessAccess) and Event ID 1 (Process creation): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Security Onion — analyst tools (Suricata/Zeek/Elastic/Kibana pivots): https://docs.securityonion.net/en/2.4/analyst-tools.html
- MITRE ATT&CK — T1003 Credential Dumping: https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK — T1070.006 Timestomp: https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK — T1070.001 Clear Windows Event Logs: https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK — T1074 Data Staged: https://attack.mitre.org/techniques/T1074/
- MITRE ATT&CK — T1119 Inhibit System Recovery: https://attack.mitre.org/techniques/T1119/
- MITRE ATT&CK — T1490 Inhibit System Recovery (VSS deletes): https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK — T1562.001 Impair Defenses: Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — T1059.003 Command and Scripting Interpreter: PowerShell: https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK — T1482 Domain Trust Discovery: https://attack.mitre.org/techniques/T1482/
- MITRE ATT&CK — T1622 Debugger Evasion: https://attack.mitre.org/techniques/T1622/
- CybOK: https://www.cybok.org/
- NIST Special Publication 800-150: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf

## Related modules
- [Plaso super-timeline deep-dive](../23-plaso-supertimeline/README.md) -- shares log2timeline
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares plaso
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations)
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations)

<!-- cyberlab-enriched: v4 -->
- https://plaso.readthedocs.io/en/latest/sources/user/Using-the-tools.html
- https://www.dfir.review/2022/03/15/plaso-filters-for-mitre-attck/
- https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html

<!-- cyberlab-enriched: v5 -->
- https://plaso.readthedocs.io/en/latest/sources/user/Advanced-usage.html
- https://www.dfir.review/2022/03/15/plaso-performance-tuning/
- https://yara.readthedocs.io/en/stable/writingrules.html"
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1057/
- https://yara.readthedocs.io/en/stable/writingrules.html>
- https://github.com/SigmaHQ/sigma-specification>

<!-- cyberlab-enriched: v6 -->
