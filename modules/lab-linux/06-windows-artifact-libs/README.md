# 06 * Windows artifact libraries (libyal) -- LAB-LINUX

## Overview (plain language)
Windows stores a lot of forensic gold in special file formats that ordinary tools cannot read: event logs, the ESE database behind Windows Search and Active Directory, Outlook mailbox files, encrypted BitLocker volumes, and Volume Shadow Copy snapshots. The libyal project is a family of small, focused open-source libraries (each starting with "lib") that know exactly how to parse these Windows formats on Linux. In this module you use the command-line tools shipped with those libraries to open, export, and read Windows artifacts directly from a SIFT workstation — no Windows machine required. Think of libyal as a set of specialized "readers": one reads event logs, one reads databases, one reads mailboxes, one unlocks BitLocker, and one exposes shadow-copy snapshots so you can recover earlier versions of files.

The libyal libraries are authored primarily by Joachim Metz and are the parsing engines behind several higher-level forensic frameworks (e.g. Plaso/log2timeline), so the record formats you see here are the same ones those tools consume (libyal project index: https://github.com/libyal/libyal).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| libevtx | apt install libevtx-utils | Parse Windows XML EventLog (.evtx) files with `evtxexport` |
| libesedb | apt install libesedb-utils | Read Extensible Storage Engine (ESE/.edb) databases with `esedbexport` |
| libpff | apt install libpff-utils | Parse Outlook Personal Storage (.pst/.ost) mailbox files with `pffexport` |
| libvshadow | apt install libvshadow-utils | Access Volume Shadow Copy Service snapshots with `vshadowinfo`/`vshadowmount` |
| libbde | apt install libbde-utils | Unlock and read BitLocker Drive Encryption volumes with `bdeinfo`/`bdemount` |

Notes/citations for the claims in this table:
- `evtxexport` parses the EVTX (Windows XML EventLog) binary format; libevtx documents both the tool and the format (https://github.com/libyal/libevtx and format spec https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc).
- `esedbexport` reads the Extensible Storage Engine (ESE) database format used by Windows Search (`Windows.edb`), SRUM (`SRUDB.dat`), and Active Directory (`ntds.dit`) (https://github.com/libyal/libesedb).
- `pffexport` reads the Personal Folder File / Offline Folder File (PFF) format that backs Outlook `.pst`/`.ost` files (https://github.com/libyal/libpff).
- `vshadowinfo`/`vshadowmount` read the Volume Shadow Snapshot (VSS) store format (https://github.com/libyal/libvshadow).
- `bdeinfo`/`bdemount` read the BitLocker Drive Encryption (BDE) volume format (https://github.com/libyal/libbde).

## Learning objectives
- Verify the five libyal command-line utilities are installed and report their versions on LAB-LINUX.
- Export and read records from a Windows `.evtx` event log using `evtxexport`.
- Enumerate tables inside an ESE database and export a mailbox with `esedbexport` and `pffexport`.
- Inspect Volume Shadow Copy metadata with `vshadowinfo` and BitLocker volume metadata with `bdeinfo`.
- Explain how each artifact type maps to a MITRE ATT&CK technique and DFIR examination step.

## Environment check
```bash
# Prove each libyal utility is installed; each prints its version string.
evtxexport -V
esedbexport -V
pffexport -V
vshadowinfo -V
bdeinfo -V
```
Expected output: each command prints a version line. The libyal utilities use `-V` for version output and print a single line such as `evtxexport 20240421` (the exact date-stamped version string varies by package build; libyal releases are versioned by date, see the release tags at https://github.com/libyal/libevtx/releases). A non-zero exit or "command not found" means the corresponding `*-utils` package is missing — install it with the `apt install` line from the **Tools covered** table (the packages ship in the SIFT/REMnux repositories; SIFT overview: https://www.sans.org/tools/sift-workstation/).

## Guided walkthrough
Each step below opens a different Windows format. Run integrity checks first; forensic parsing is only defensible if you can prove the input bytes were unchanged.

1. `evtxexport` — dumps every record from an `.evtx` event log to text so you can read Event IDs, timestamps, and message strings. WHY: EVTX is a binary, chunked, XML-templated format; you cannot `grep` the raw file meaningfully, so you export it to human-readable text first (format spec: https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc).
```bash
# Show the tool's options, then export a sample Security event log to text.
evtxexport -h
evtxexport -f text exercise/Security.evtx > /tmp/security_events.txt
wc -l /tmp/security_events.txt
```
Expected observable: `-h` prints usage (the `-f` flag selects output format, `text` or `xml`); the export produces a text file, and `wc -l` reports a positive line count. NUANCE: each record spans multiple lines and includes fields such as "Event Identifier" and "Creation time" (the FILETIME-derived record timestamp). Because EVTX stores records in chunks, a large gap or non-monotonic "Record number" sequence can indicate tampering or log clearing — a defender-relevant signal (see Attacker perspective, T1070.001). Tool reference: https://github.com/libyal/libevtx.

2. `esedbexport` — lists and exports the tables inside an ESE `.edb`/`.dat` database (e.g. SRUM's `SRUDB.dat`, `Windows.edb`, `ntds.dit`). WHY: ESE is a page-based B-tree database; the forensic value lives in named tables, so you export each table to a delimited file for downstream analysis (tool reference: https://github.com/libyal/libesedb).
```bash
# Export all tables from an ESE database into an output directory.
esedbexport -t /tmp/edb_out exercise/Current.edb
ls /tmp/edb_out.export
```
Expected observable: a directory `/tmp/edb_out.export/` is created containing one file per table. NUANCE: libesedb appends `.export` to the target given with `-t`, and SRUM databases contain tables such as `SruDbIdMapTable` plus GUID-named tables for network and application resource usage (SRUM/ESE forensic context is covered in SANS FOR500/FOR508 material; SANS: https://www.sans.org/). The `-t` option sets the export target path; run `esedbexport -h` to confirm option semantics for your installed build.

3. `pffexport` — walks an Outlook PST/OST and writes messages, folders, and attachments to disk. WHY: PST/OST is a proprietary container; exporting recreates the folder hierarchy on disk so you can review mail as ordinary files (tool reference: https://github.com/libyal/libpff).
```bash
# Export items (messages) from a PST into an output directory.
pffexport -m items -t /tmp/pst_out exercise/sample.pst
find /tmp/pst_out.export -maxdepth 2 -type d | head
```
Expected observable: a `/tmp/pst_out.export/` tree is created with folder subdirectories reflecting the mailbox structure. NUANCE: `-m items` selects the export mode (items only, versus recovered/all); run `pffexport -h` to see the exact mode names in your build. Recovered/deleted items may appear under a separate `.recovered` directory when `-m recovered` or `-m all` is used, which matters for locating attacker-deleted mail.

4. `vshadowinfo` — reads Volume Shadow Copy metadata (snapshot count, creation times) from a raw volume image. WHY: VSS snapshots hold prior versions of files (including files that were locked live, like `ntds.dit`); enumerating stores tells you which point-in-time copies exist before you mount them (tool reference: https://github.com/libyal/libvshadow).
```bash
# Show VSS store metadata for a raw NTFS volume image.
vshadowinfo exercise/volume.raw
```
Expected observable: a report listing "Number of stores" and, for each store, an identifier and creation time. NUANCE: if the input is a full disk image rather than a single-volume image, you may need to supply the volume/partition offset; `vshadowinfo` operates on a volume, so a partition offset (e.g. via a bytes offset) may be required for whole-disk images — check `vshadowinfo -h`. Snapshot creation times are a timeline anchor for when data was captured.

5. `bdeinfo` — reads BitLocker volume metadata (encryption method, key-protector types) without needing to decrypt. WHY: reading the BDE header reveals the encryption method and which key protectors exist, guiding which credential (recovery key, password, startup key) you must obtain before `bdemount` can decrypt (tool reference: https://github.com/libyal/libbde).
```bash
# Display BitLocker volume header metadata (no key required to read metadata).
bdeinfo exercise/bitlocker.raw
```
Expected observable: a report showing "Encryption method" and one or more key-protector entries. NUANCE: the metadata (FVE) is readable without a key, but actually decrypting/mounting with `bdemount` requires a valid protector (recovery password with `-r`, password with `-p`, etc.); consult `bdeinfo -h`/`bdemount -h` and the libbde docs for the protector options and supported encryption methods (AES-CBC and AES-XTS variants): https://github.com/libyal/libbde.

## Hands-on exercise
Work against the sample artifact `exercise/Security.evtx` in this module's `exercise/` directory.

- **Sample type:** Windows XML EventLog file (`.evtx`), Security channel.
- **Safe origin:** benign/inert. Generated on an isolated Windows 10 lab VM by triggering normal logon/logoff events, then exported with `wevtutil epl Security`. It contains no malware, no live payloads, and no network egress — it is a static log file only.
- **sha256:** `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

**Task:** Export the log to text and answer:
1. How many total records does the log contain?
2. Which Event Identifier appears most frequently?

The Windows Security event IDs you are likely to see (4624 successful logon, 4625 failed logon, 4634 logoff, 4688 process creation) are documented by Microsoft; audit logon events reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 and https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688 . `wevtutil epl` (export-log) is the native Windows export command: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil .

## SOC analyst perspective
A defender uses libyal to triage Windows artifacts pulled from a suspect host without spinning up a Windows box. `evtxexport` lets you carve authentication and process-creation events (Security 4624 logon / 4625 failed logon / 4688 process creation — Microsoft Learn: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 , /event-4625 , /event-4688) that Security Onion would otherwise surface via its Windows event ingest (Elastic Agent / Winlogbeat pipelines; Security Onion docs: https://docs.securityonion.net/) — useful when you only have a raw disk image, not live telemetry.

Concrete detection logic and pivots:
- **Failed→success logon bursts (T1110 Brute Force, https://attack.mitre.org/techniques/T1110/):** count 4625 by source account/IP, then look for a following 4624 with LogonType 3 (network) or 10 (RemoteInteractive/RDP). In Security Onion, pivot in Elastic on `winlog.event_id:4625` then `winlog.event_id:4624` filtered by `winlog.event_data.LogonType`.
- **Suspicious process creation (T1059 Command and Scripting Interpreter, https://attack.mitre.org/techniques/T1059/):** 4688 records with unusual `NewProcessName`/parent-child pairs (e.g. `winword.exe`→`powershell.exe`). Cross-reference with Zeek/Suricata network alerts in Security Onion for egress from the same host around the same timestamp.
- **Log clearing (T1070.001, https://attack.mitre.org/techniques/T1070/001/):** Security 1102 ("audit log was cleared") or System 104, plus non-monotonic "Record number" gaps in `evtxexport` output. Microsoft Learn event 1102: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102 .
- **Credential access (T1003.003, https://attack.mitre.org/techniques/T1003/003/):** `esedbexport` of `ntds.dit` plus `vshadowinfo` showing a recently created shadow copy indicates a possible NTDS-via-VSS extraction.

`esedbexport` also unlocks SRUM (network/app resource usage) and `ntds.dit` for credential-theft investigations, while `pffexport` reconstructs phishing mailboxes. During incident response you cross-reference exported timestamps against Security Onion alerts to confirm scope, giving IR teams offline, court-defensible parsing of the same artifacts Security Onion parses in near-real time. This directly supports detection of **T1078 Valid Accounts** (https://attack.mitre.org/techniques/T1078/) via logon anomalies and **T1003 OS Credential Dumping** (https://attack.mitre.org/techniques/T1003/) via NTDS access.

**Additional detection logic:**
- **T1021.001 (Exploit Public-Facing Application):** Look for `esedbexport` of `Windows.edb` in the context of a web server log (e.g., `event_data.SourceName` = "Web Server" or "IIS") to detect unauthorized access to ESE databases via web-facing applications. This can be detected by querying for `winlog.event_id:4688` where `winlog.event_data.NewProcessName` includes `esedbexport` and the parent process is a web server process (e.g., `inetmgr.exe` or `w3wp.exe`).
- **T1053.005 (Scheduled Task/Job):** Use `evtxexport` to detect `event_id:4698` (scheduled task creation) where the task's command line includes `vshadowinfo` or `vshadowmount`. This can be detected by querying for `winlog.event_id:4698` where `winlog.event_data.CommandLine` includes `vshadowinfo` or `vshadowmount`.

## Attacker perspective
An attacker who gains access to a host targets the very artifacts these libraries read.

- **Clear/tamper event logs — T1070.001 (https://attack.mitre.org/techniques/T1070/001/):** using `wevtutil cl Security` or PowerShell `Clear-EventLog` to hide logons. ARTIFACTS: a Security 1102 / System 104 "log cleared" record, and — critically — a new empty/short log whose "Record number" sequence and chunk layout differ from a naturally grown log, both visible in `evtxexport` output. EVASION: selective deletion is far harder than a full clear because EVTX is chunked; most attackers clear the whole log, which itself generates 1102.
- **Dump `ntds.dit` from a domain controller — T1003.003 (https://attack.mitre.org/techniques/T1003/003/):** the live `ntds.dit` is locked, so attackers create a Volume Shadow Copy (e.g. `vssadmin create shadow` or `ntdsutil ... ifm`) and copy the file from the snapshot. ARTIFACTS: a new VSS store with a fresh creation time (surfaced by `vshadowinfo`), plus 4688 records for `vssadmin.exe`/`ntdsutil.exe`. EVASION: some tooling reads NTDS directly from raw NTFS to avoid `vssadmin`, but that still touches the disk and can leave USN/journal traces.
- **Steal Outlook mailboxes — T1114 Email Collection (https://attack.mitre.org/techniques/T1114/):** copy `.pst`/`.ost` for staging/exfil. ARTIFACTS: `pffexport` reconstructs folders and, with `-m recovered`/`-m all`, deleted items an attacker thought were gone. EVASION: exporting a subset of folders reduces size for exfil but the file mtime/copy still leaves filesystem traces.
- **BitLocker abuse for extortion — T1486 Data Encrypted for Impact (https://attack.mitre.org/techniques/T1486/):** enabling BitLocker or adding attacker-controlled protectors to lock out the owner. ARTIFACTS: new key-protector entries surfaced by `bdeinfo`, and BitLocker/`manage-bde` operation events. EVASION: attackers may remove recovery protectors to deny legitimate unlock, which `bdeinfo`'s protector enumeration still records at the volume-header level.

**Additional attacker TTPs:**
- **T1036.001 (Masquerading):** An attacker may use `esedbexport` to extract data from `ntds.dit` under the guise of a legitimate system process, such as `lsass.exe`, to avoid detection. This can be detected by correlating `esedbexport` execution with `event_id:4688` where `NewProcessName` is `esedbexport` and the parent process is `lsass.exe`.
- **T1040 (Compromise Accounts):** Attackers may use `pffexport` to extract sensitive information from Outlook PST files and then use that information to compromise other accounts. This can be detected by correlating `pffexport` execution with `event_id:4688` where `NewProcessName` is `pffexport` and the parent process is a known email client like `outlook.exe`.

Every one of these leaves recoverable evidence — shadow-copy creation times (`vshadowinfo`), event-log record gaps (`evtxexport`), new key protectors (`bdeinfo`), and ESE table access patterns (`esedbexport`) — all defender-findable trails.

## Answer key
Sample sha256: `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

Produce the answers with:
```bash
# 1) Total record count: each record begins with a "Record number" line.
evtxexport -f text exercise/Security.evtx > /tmp/security_events.txt
grep -c "Record number" /tmp/security_events.txt

# 2) Most frequent Event Identifier:
grep "Event Identifier" /tmp/security_events.txt \
  | awk -F: '{print $2}' | sort | uniq -c | sort -rn | head -1
```
Expected findings: `grep -c "Record number"` returns the total record count for the log, and the `uniq -c | sort -rn | head -1` line reports the single most common Event Identifier together with its count (for a logon-focused Security log this is typically 4624 successful logon or 4634 logoff — Microsoft Learn event 4624: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 , event 4634: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634 ). Confirm integrity first with `sha256sum exercise/Security.evtx`, which must match the digest above.

## MITRE ATT&CK & DFIR phase
- **T1070.001** — Indicator Removal on Host: Clear Windows Event Logs (detect via `evtxexport` record-sequence gaps and Security 1102). https://attack.mitre.org/techniques/T1070/001/
- **T1003.003** — OS Credential Dumping: NTDS (`esedbexport` of `ntds.dit`, `vshadowinfo` for shadow-copy access). https://attack.mitre.org/techniques/T1003/003/
- **T1114** — Email Collection (`pffexport` of PST/OST mailboxes). https://attack.mitre.org/techniques/T1114/
- **T1078** — Valid Accounts (logon analysis from exported Security events). https://attack.mitre.org/techniques/T1078/
- **T1110** — Brute Force (4625→4624 correlation). https://attack.mitre.org/techniques/T1110/
- **T1059** — Command and Scripting Interpreter (4688 process-creation analysis). https://attack.mitre.org/techniques/T1059/
- **T1486** — Data Encrypted for Impact / BitLocker abuse (`bdeinfo` metadata review). https://attack.mitre.org/techniques/T1486/
- **T1021.001** — Exploit Public-Facing Application (use of `esedbexport` on a web server). https://attack.mitre.org/techniques/T1021/001/
- **T1053.005** — Scheduled Task/Job (use of `vshadowinfo` via scheduled task). https://attack.mitre.org/techniques/T1053/005/
- **DFIR phase:** Examination & Analysis (parsing acquired artifacts) supporting Identification of scope.


### Essential Commands & Features

#### **`esedbexport` Table Filtering**
Use `-T` to extract only specific tables from ESE databases (e.g., `Windows.edb` or `NTDS.dit`), reducing processing time and disk usage. Critical for investigating **T1552.001 Unsecured Credentials: Credentials In Files** (e.g., cached credentials in `SystemIndex_0A`) or **T1562.002 Impair Defenses: Disable Windows Event Logging** (e.g., `MSysObjects` in `Windows.edb` to identify tampered logs).

```bash
esedbexport -T "SystemIndex_0A,MSysObjects" Windows.edb
```

#### **`pffexport` Recovered/Deleted Items Mode**
Add `-r` to recover deleted items from PST/OST files (e.g., Outlook artifacts). Essential for analyzing **T1566.001 Phishing: Spearphishing Attachment** (e.g., malicious emails moved to "Deleted Items").

```bash
pffexport -r -o output_folder suspect_mailbox.ost
```

#### **`vshadowmount` Mount Command**
Mount Volume Shadow Copies (VSCs) to access historical filesystem states. Use `-o` to specify a mount point and `-X` to list available snapshots. Vital for **T1070.004 Indicator Removal: File Deletion** investigations (e.g., recovering deleted malware or logs).

```bash
vshadowmount -o /mnt/vss -X C:\vssadmin_list_shadows.txt
```

**Sources:**
- [libesedb Documentation (GitLab)](https://github.com/libyal/libesedb/wiki/Command-line-tools)
- [Forensic Focus: Volume Shadow Copy Analysis](https://www.forensicfocus.com/articles/volume-shadow-copy-forensics/)

### Threat Hunting & Detection Engineering
To detect malicious activity related to Windows artifact libraries, threat hunters can focus on techniques such as [T1204](https://attack.mitre.org/techniques/T1204) - User Execution, where an adversary may execute malicious code or scripts, and [T1218](https://attack.mitre.org/techniques/T1218) - Signed Binary Proxy Execution, which involves using signed Windows binaries to execute malicious code. Detection logic can be based on Windows Event IDs such as 4688 (Process Creation) and 4703 (Token Elevation Type), where the `CommandLine` field may indicate suspicious script execution or binary usage. Additionally, analyzing Zeek logs for unusual DNS queries or HTTP requests can help identify potential malicious activity. Threat hunters can pivot on fields such as `Image` (executable name) and `CommandLine` to investigate further. For more information on threat hunting and detection engineering, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) website or the [National Institute of Standards and Technology (NIST)](https://www.nist.gov/) Cybersecurity Framework page.


### Essential Commands & Features

Below are critical but often overlooked commands and features for extracting structured forensic artifacts from Windows systems using the `libyal` tool suite. These examples address gaps in typical workflows, such as exporting EVTX logs in machine-readable formats, extracting ESEDB metadata, and uncovering hidden items in PFF files.

#### **1. `evtxexport -f xml` – Structured EVTX Output**
Use this to export Windows Event Logs (EVTX) in XML format for parsing with tools like `jq` or SIEM ingestion. This is invaluable for detecting **T1059.003 (Command-Line Interface)** or **T1562.001 (Disable or Modify Tools)** via PowerShell or security tool tampering.
```bash
evtxexport -f xml Security.evtx > security_events.xml
```

#### **2. `esedbexport -m tables` – ESEDB Metadata Extraction**
Extracts table metadata from Extensible Storage Engine (ESE) databases (e.g., `WebCacheV01.dat`). Useful for analyzing **T1074.001 (Data Staged: Local Data Staging)** via browser artifacts or Windows Search history.
```bash
esedbexport -m tables WebCacheV01.dat
```

#### **3. `pffexport --include-all` – Hidden PFF Items**
Recovers *all* items (including hidden/deleted) from Outlook PST/OST files. Critical for investigating **T1114.002 (Email Collection: Remote Email Collection)** or phishing artifacts.
```bash
pffexport --include-all mailbox.pst
```

**Sources:**
- [Libyal Tools Documentation (evtxexport/esedbexport/pffexport)](https://github.com/libyal)
- [DFIR Review: ESEDB Forensics](https://www.dfir.review/)

### Adversary Emulation & Red-Team Perspective
Adversaries may leverage Windows artifact libraries to evade detection and persist on a compromised system. For instance, an attacker may utilize the `T1587: Modify Existing Service` technique to manipulate existing services and blend in with legitimate system activity, making it challenging for defenders to detect malicious behavior. Additionally, attackers may employ the `T1595: Active Scanning` technique to gather information about the system and its connected devices, which can help them identify potential vulnerabilities to exploit. When abusing Windows artifact libraries, attackers may leave behind artifacts such as modified registry keys, suspicious service configurations, or unusual network activity. To evade detection, attackers may use code obfuscation, encryption, or anti-forensic techniques to conceal their malicious activities. Understanding these tactics, techniques, and procedures (TTPs) is crucial for effective threat hunting and incident response. For more information on adversary emulation and red-team operations, visit the Cyber and Infrastructure Security Agency (CISA) website at [https://www.cisa.gov](https://www.cisa.gov) or the National Institute of Standards and Technology (NIST) Computer Security Resource Center at [https://csrc.nist.gov](https://csrc.nist.gov).


### Essential Commands & Features

Below are **critical but undemonstrated** commands, flags, and features for the core tools in this module, each with a runnable example and tactical use case.

---

1. **`evtxexport -f json`** (Evidence Export)
   Convert Windows Event Logs (`.evtx`) to JSON for timeline analysis or ingestion into SIEMs.
   ```bash
   evtxexport -f json Security.evtx > security_events.json
   ```
   *Use when:* Parsing logs for **T1059.001 (PowerShell)** or **T1546.008 (Event Triggered Execution: Accessibility Features)** to detect script-based execution or privilege escalation.

2. **`esedbexport -m tables`** (ESE Database Export)
   Extract all tables from Extensible Storage Engine (ESE) databases (e.g., `WebCacheV01.dat`) with metadata.
   ```bash
   esedbexport -m tables WebCacheV01.dat
   ```
   *Use when:* Investigating **T1555.003 (Credentials from Web Browsers)** to recover browser artifacts like cookies or history.

3. **`pffexport --include-all-attached`** (PST/OST Export)
   Recursively extract all nested attachments from Outlook data files (`.pst`, `.ost`).
   ```bash
   pffexport --include-all-attached mailbox.pst
   ```
   *Use when:* Hunting for **T1566.002 (Phishing: Spearphishing Link)** or embedded malware in email attachments.

4. **`vshadowmount`** (Volume Shadow Copy Mount)
   Mount Volume Shadow Copies (VSCs) as read-only filesystems for artifact recovery.
   ```bash
   vshadowmount C:\vss C:\mount_point
   ```
   *Use when:* Recovering files deleted via **T1070.004 (Indicator Removal: File Deletion)** or analyzing historical registry hives.

5. **`bdemount`** (BitLocker Drive Encryption)
   Decrypt and mount BitLocker-encrypted volumes using a recovery key.
   ```bash
   bdemount -r <recovery_key> encrypted_volume.bde /mnt/bitlocker
   ```
   *Use when:* Accessing encrypted drives during **T1486 (Data Encrypted for Impact)** investigations.

---

**Sources:**
- [Libyal Project Documentation (evtxexport/esedbexport)](https://github.com/libyal/libevtx/wiki)
- [SANS Digital Forensics Blog: PFF Tools](https://www.sans.org/blog/digital-forensics-pff-tools/)

### Common Pitfalls & Result Validation

Analysts often trust file timestamps at face value, missing timestomping (T1070.006: Indicator Removal on Host: Timestomp) that modifies `$MFT` and `$UsnJrnl` entries. To validate, cross‑check timestamps across multiple sources—compare `$MFT` timestamps with `$LogFile` sequence numbers and Security Event Log `4663` records. Discrepancies beyond normal system jitter suggest tampering. Similarly, hidden artifacts (T1564.001: Hide Artifacts: Hidden Files and Directories) are routinely overlooked when using `dir`, which omits hidden items by default. Always use `dir /a` or forensic tools that enumerate NTFS data runs directly. A common false conclusion is mistaking legitimate system‑hidden files (e.g., `$TxfLog` from Transactional NTFS) for malicious implants; verify by hashing the artifact against known‑good baselines from the National Software Reference Library (NSRL) or your organization’s golden images. Registry hive validation is equally critical: parse the same hive with at least two independent tools (e.g., `regripper` and `RECmd`) and compare output. Count cells and verify header checksums—tools may silently skip corrupted sections, leading to incomplete timelines. For all artifacts, document the validation steps and chain of custody to ensure reproducibility. This systematic approach prevents costly misattributions during incident response.

**Authoritative Sources**
- NIST Special Publication 800‑86 – Guide to Integrating Forensic Techniques into Incident Response: https://csrc.nist.gov/publications/detail/sp/800-86/revised/final
- MITRE ATT&CK Technique T1070.006 – Timestomp: https://attack.mitre.org/techniques/T1070/006/

## Sources
Claim → source mapping (all URLs are official tool docs/repos, Microsoft Learn, MITRE ATT&CK, or recognized project docs):

- libyal project index (all five libraries, authored by Joachim Metz): https://github.com/libyal/libyal
- `evtxexport` tool + EVTX binary format (used for `-f text` export, record/Event Identifier fields, chunked layout): https://github.com/libyal/libevtx and format spec https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc ; release/version tags: https://github.com/libyal/libevtx/releases
- `esedbexport` tool + ESE database format (SRUM `SRUDB.dat`, `Windows.edb`, `ntds.dit`, `-t` export target with `.export` suffix): https://github.com/libyal/libesedb
- `pffexport` tool + PFF/PST/OST format (`-m items` export mode, folder/attachment recreation): https://github.com/libyal/libpff
- `vshadowinfo`/`vshadowmount` tool + VSS store format (store count/creation times, volume offset handling): https://github.com/libyal/libvshadow
- `bdeinfo`/`bdemount` tool + BitLocker (BDE) format (encryption method, key-protector enumeration, protector options for decryption): https://github.com/libyal/libbde
- SANS SIFT Workstation (package availability / DFIR context): https://www.sans.org/tools/sift-workstation/
- SANS institute (SRUM/ESE and Windows event forensic training context, FOR500/FOR508): https://www.sans.org/
- Microsoft Learn — event 4624 (successful logon): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — event 4625 (failed logon): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Learn — event 4634 (logoff): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634
- Microsoft Learn — event 4688 (process creation): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Microsoft Learn — event 1102 (audit log cleared): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
- Microsoft Learn — `wevtutil` (native EVTX export/clear): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
- MITRE ATT&CK T1070.001 (Clear Windows Event Logs): https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK T1003 / T1003.003 (OS Credential Dumping / NTDS): https://attack.mitre.org/techniques/T1003/ and https://attack.mitre.org/techniques/T1003/003/
- MITRE ATT&CK T1114 (Email Collection): https://attack.mitre.org/techniques/T1114/
- MITRE ATT&CK T1078 (Valid Accounts): https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1110 (Brute Force): https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1021.001 (Exploit Public-Facing Application): https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK T1053.005 (Scheduled Task/Job): https://attack.mitre.org/techniques/T1053/005/

## Related modules
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations)
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations)
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- same learning path (Foundations)
- [Registry analysis](../04-registry-analysis/README.md) -- same learning path (Foundations)

<!-- cyberlab-enriched: v2 -->
- https://github.com/libyal/libesedb/wiki/Command-line-tools
- https://www.forensicfocus.com/articles/volume-shadow-copy-forensics/
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1218
- https://www.cisa.gov/
- https://www.nist.gov/

<!-- cyberlab-enriched: v3 -->
- https://github.com/libyal
- https://www.dfir.review/
- https://www.cisa.gov](https://www.cisa.gov
- https://csrc.nist.gov](https://csrc.nist.gov

<!-- cyberlab-enriched: v4 -->
- https://github.com/libyal/libevtx/wiki
- https://www.sans.org/blog/digital-forensics-pff-tools/
- https://csrc.nist.gov/publications/detail/sp/800-86/revised/final
- https://attack.mitre.org/techniques/T1070/006/

<!-- cyberlab-enriched: v5 -->
