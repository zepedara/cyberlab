# 49 * Scenario: intrusion timeline reconstruction -- LAB-LINUX

## Overview (plain language)
When an attacker breaks into a computer, they leave behind a trail: files get created, programs run, registry keys change, and logins happen. Timeline reconstruction is the detective work of putting all those events in the correct order so you can tell the story of what happened, when, and how. This module uses three tools to build that story from a disk image. Plaso (log2timeline) automatically gathers timestamps from hundreds of sources into one big timeline. The Sleuth Kit reads the raw filesystem so you can see files and their creation/modification/access times directly. RegRipper pulls meaningful facts out of Windows registry hives, like which programs auto-start or which USB devices were plugged in. Together they turn a confusing pile of data into a readable, minute-by-minute account of an intrusion.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso | Automated super-timeline creation (log2timeline/psort) across many artifact types |
| RegRipper | apt install regripper | Parse Windows registry hives into human-readable forensic findings |
| Sleuth Kit | apt install sleuthkit | Command-line filesystem forensics: list files, recover deleted data, produce timelines |

> Note on install: Plaso's own maintainers recommend the [GIFT PPA / official install methods](https://plaso.readthedocs.io/en/latest/sources/user/Installation-instructions.html) or Docker over distro `apt` packages, which can lag behind releases. On the SANS SIFT Workstation and REMnux, Plaso, The Sleuth Kit, and RegRipper are pre-installed (see [SIFT](https://www.sans.org/tools/sift-workstation/) and [remnux.org tools](https://docs.remnux.org/discover-the-tools)).

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

Notes on the commands above (each flag verified against tool docs):
- `log2timeline.py --version` and `psort.py --version` — the `--version` argument is documented for the Plaso frontends ([Plaso log2timeline.py docs](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html), [psort.py docs](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html)).
- `fls -V` and `mactime -V` — `-V` prints The Sleuth Kit version for both tools ([TSK fls man page](https://www.sleuthkit.org/sleuthkit/man/fls.html), [TSK mactime man page](https://www.sleuthkit.org/sleuthkit/man/mactime.html)).
- `rip.pl -h` — RegRipper's CLI (`rip.pl`) prints usage/help; see the [RegRipper repo](https://github.com/keydet89/RegRipper3.0). On some packagings the executable is `rip.pl`/`rip`; confirm with the packaged docs.

## Guided walkthrough
1. `fls` walks the filename layer of a filesystem and prints file/directory entries with their inode and MAC times; the `-m` option emits output in the **bodyfile** (TSK 3.x `mactime`) format, which `mactime` then sorts into a chronological timeline. We run this first because filesystem metadata is the most direct, least-abstracted timeline source and is available even when higher-level logs are missing.
```bash
# Build a Sleuth Kit bodyfile from a raw image, then a mactime timeline
IMAGE=disk.raw
fls -r -m C: -o 2048 "$IMAGE" > bodyfile.txt
mactime -b bodyfile.txt -d 2024-01-01 > sk_timeline.csv
head -n 5 sk_timeline.csv
```
Why each flag matters (per the [fls man page](https://www.sleuthkit.org/sleuthkit/man/fls.html)):
- `-r` recurses into subdirectories so you capture the whole tree, not just the root.
- `-m C:` prepends the mount point string (here `C:`) to each path in the bodyfile so the resulting timeline paths read like Windows paths.
- `-o 2048` is the **sector offset** to the start of the partition within the image. `2048` is a common first-partition offset but is image-specific — confirm it with `mmls "$IMAGE"` before trusting it, or `fls` will read the wrong volume.

For `mactime` (per the [mactime man page](https://www.sleuthkit.org/sleuthkit/man/mactime.html)):
- `-b bodyfile.txt` supplies the bodyfile to sort.
- `-d` produces comma-delimited (CSV) output; the trailing `2024-01-01` restricts the timeline to on/after that date. Output is in the host/`TZ` timezone unless you pass `-z`.

Expected output: `bodyfile.txt` contains pipe-delimited lines in TSK bodyfile format — `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` (the MD5 field is `0` when hashing is not requested). `sk_timeline.csv` shows date-sorted rows with a MACB column indicating which of the four timestamps fired for each entry.

2. `log2timeline.py` runs Plaso's parsers/plugins across the image and writes events into a `.plaso` storage file (an SQLite database); `psort.py` then post-processes, sorts, de-duplicates, filters, and exports that storage file. We separate collection (`log2timeline.py`) from output (`psort.py`) so you can extract once and re-query many time windows/output formats without re-parsing the image.
```bash
# Create the Plaso super-timeline, then export a date-scoped CSV
IMAGE=disk.raw
log2timeline.py --storage-file timeline.plaso "$IMAGE"
psort.py -o l2tcsv -w super_timeline.csv timeline.plaso \
  "date > '2024-01-10 00:00:00' AND date < '2024-01-12 00:00:00'"
wc -l super_timeline.csv
```
Why each flag matters (per [Using log2timeline.py](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html) and [Using psort.py](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html)):
- `--storage-file timeline.plaso` names the output storage file; the positional argument is the source (image, device, or directory). Plaso auto-detects storage-media images and iterates volumes/partitions.
- `psort.py -o l2tcsv` selects the classic l2t CSV output module; `-w super_timeline.csv` writes to that file.
- The trailing quoted string is a Plaso **event filter** expression restricting the export to a time window (see [Plaso filters / event-filters docs](https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html)). Scoping keeps a super-timeline (often millions of rows) manageable.

Expected output: `log2timeline.py` prints a processing summary (sources parsed, events extracted, warnings). `super_timeline.csv` holds l2tcsv rows for the scoped window; the l2tcsv header is `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`.

3. `rip.pl` runs RegRipper plugins against a single registry hive to surface autostart and device artifacts. The registry is a rich, timestamped artifact store (key LastWrite times) that survives log clearing, so we mine it independently and merge findings onto the timeline.
```bash
# Extract autostart programs and USB device history from a registry hive
rip.pl -r NTUSER.DAT -p run
rip.pl -r SYSTEM -p usbstor
```
Why each flag matters (per the [RegRipper repo](https://github.com/keydet89/RegRipper3.0)):
- `-r NTUSER.DAT` / `-r SYSTEM` names the hive file to parse. Autostart Run/RunOnce keys live under both `NTUSER.DAT` (per-user `HKCU`) and `SOFTWARE` (`HKLM`); the `usbstor` data lives in `SYSTEM` (`ControlSet00x\Enum\USBSTOR`).
- `-p run` / `-p usbstor` selects a specific plugin. `run` reports the RuneKey persistence values; `usbstor` enumerates USB mass-storage device history with the subkey LastWrite times.

Expected output: RegRipper prints the plugin's findings — for `run`, the Run/RunOnce values (auto-start program paths) with the key LastWrite time; for `usbstor`, device class/serial entries with their LastWrite timestamps. Note that a Run key's LastWrite reflects the *last* modification to the key, not necessarily the moment a specific value was added.

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
A defender uses timeline reconstruction during incident response to answer "patient zero and dwell time" questions. In Security Onion you typically start from an alert and pivot to the host disk image, then use Plaso/Sleuth Kit to stitch endpoint events into an order that matches network telemetry ([Security Onion docs](https://docs.securityonion.net/)).

Concrete detection logic and pivots:
- **Suricata alerts → host pivot.** A Suricata signature firing (e.g. malware C2 or exploit) gives you a timestamp and a host IP. In Security Onion, Suricata alerts and Zeek metadata are indexed in Elasticsearch and browsable via the Alerts/Dashboards interfaces ([Suricata in Security Onion](https://docs.securityonion.net/en/2.4/suricata.html)).
- **Zeek connection correlation.** Pivot on the host IP in `conn.log` (Zeek) around the payload's creation time to find the outbound connection that followed execution — this ties the filesystem crtime of `evil.exe` to a network event ([Zeek in Security Onion](https://docs.securityonion.net/en/2.4/zeek.html); [Zeek conn.log reference](https://docs.zeek.org/en/master/logs/conn.html)).
- **Registry persistence (T1547.001).** A Run-key value from RegRipper's `run` plugin, correlated with the `.exe` crtime and a subsequent outbound connection, confirms Registry Run Key/Startup Folder persistence ([ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)). Microsoft's autoruns/registry references confirm the Run/RunOnce key locations ([Microsoft Learn: Run and RunOnce registry keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)).
- **Timestomp signal (T1070.006).** Watch for files where crtime is *later* than mtime, or where `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps disagree — Plaso surfaces both via the NTFS `$MFT` parser, letting you flag manipulation ([ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/)).
- **USB introduction (T1091).** RegRipper `usbstor` LastWrite times placed on the timeline show when a device was first connected, relevant to removable-media replication ([ATT&CK T1091](https://attack.mitre.org/techniques/T1091/)).
- **PowerShell abuse (T1059.001).** Correlate file creation times of scripts executed via PowerShell (e.g., `evil.ps1`) with Windows Event ID 4104 (ScriptBlock Logging) in `Microsoft-Windows-PowerShell/Operational`. Look for `-EncodedCommand` or `-NoProfile -ExecutionPolicy Bypass` in `ScriptBlockText` field. Sysmon Event ID 1 (Process creation) with `Image` containing `powershell.exe` or `pwsh.exe` and `CommandLine` containing suspicious base64 strings can also be used ([ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/); [Microsoft Learn: ScriptBlock Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)).
- **Token manipulation (T1134.002).** On Windows, Event ID 4688 (Process Creation) with `TokenElevationType` = `%%1936` (full token) and parent process not expected for that child can indicate privilege escalation via token duplication. Correlate with Event ID 4672 (Special Privileges Assigned) for SeBackupPrivilege or SeDebugPrivilege usage. Sysmon Event ID 10 (Process Access) with `TargetImage` = `lsass.exe` and `GrantedAccess` = `0x1438` (full memory read/write) is a strong indicator ([ATT&CK T1134.002](https://attack.mitre.org/techniques/T1134/002/); [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).
- **Zeek HTTP beaconing.** In `http.log`, look for repeated `GET` requests to the same URI with small response sizes (<1KB) and consistent `user_agent` strings (e.g., `Mozilla/5.0 (Windows NT 6.1; WOW64)`). Pivot on `host` and `uri` columns to identify C2 patterns ([Zeek http.log reference](https://docs.zeek.org/en/master/logs/http.html)).

Timelines also feed Security Onion case notes, help scope which hosts and time windows need containment, and provide a defensible chronology for reporting.

## Attacker perspective
An attacker leaves timestamps everywhere: dropping a payload updates a file's creation/modification MAC times, writing a Run key changes a hive's LastWrite time, and plugging a USB device registers a USBSTOR entry.

Concrete TTPs, artifacts, and evasion:
- **Timestomping (T1070.006).** Adversaries modify file timestamps to blend malware in with existing files, often overwriting `$STANDARD_INFORMATION` (`$SI`) times to look old ([ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/)). The catch: on NTFS the `$FILE_NAME` (`$FN`) attribute and the `$UsnJrnl`/`$LogFile` often retain the true times, and `$SI` timestamps rewritten by user-mode tools frequently lose sub-second precision — both signals Sleuth Kit's `$MFT` handling and Plaso's NTFS parser can surface (see [SANS DFIR Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/) and [The Sleuth Kit docs](https://www.sleuthkit.org/sleuthkit/docs.php)).
- **Registry Run-key persistence (T1547.001).** Writing to `HKCU\...\Run` or `HKLM\...\Run` leaves the payload path *and* updates the containing key's LastWrite time, an artifact RegRipper `run` reads directly ([ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)).
- **Clearing event logs (T1070.001).** Adversaries run `wevtutil cl` or use APIs to wipe `.evtx` logs to destroy the login/process trail ([ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)). But this leaves its own tells (a `1102` "log cleared" record before the gap), and registry LastWrite times and filesystem `$MFT` metadata survive, giving investigators independent artifacts to rebuild the true sequence of events.
- **PowerShell execution (T1059.001).** Attackers often run encoded PowerShell commands to download a second stage. This leaves Event ID 4104 entries with `ScriptBlockText` containing base64 strings, and Sysmon Event ID 1 with `powershell.exe -EncodedCommand`. The timeline will show `evil.ps1` script file creation just before the event logs occur ([ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)).
- **Service creation (T1543.003).** Malware may install itself as a service to survive reboots. This creates a `SYSTEM\CurrentControlSet\Services\[MalwareName]` registry key with a LastWrite time, and Windows Event ID 4697 (Service Installed) if logging is enabled. The service binary's file creation time can be cross-referenced ([ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)).
- **Scheduled task registration (T1053.005).** Attackers use `schtasks` or COM to create periodic tasks. This leaves artifacts in `%SystemRoot%\Tasks\` (XML files) and Event ID 4698 (Scheduled Task Created). The task XML's `Date` field and the file's `crtime` provide timing clues ([ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)).
- **Evasion: Alternate Data Streams (T1564.004).** Malware can hide inside NTFS ADS, making `fls` show the stream as `filename:stream`. Plaso's NTFS parser can detect these. The timeline will show the parent file modified but no visible child file ([ATT&CK T1564.004](https://attack.mitre.org/techniques/T1564/004/)).

## Answer key
Expected findings from the sample (`exercise/intrusion_bodyfile.txt`):
```bash
mactime -b exercise/intrusion_bodyfile.txt -d 2024-01-01 | head
```
- First suspicious file created: `C:/Windows/Temp/evil.exe` at epoch `1705032000` = **2024-01-12 04:00:00 UTC** (all four MAC times equal → freshly dropped).
- Tampered file: `C:/Windows/System32/drivers/etc/hosts` — modified at `1705032600` but with an older creation time `1704000000`, indicating the attacker altered an existing system file.
- The `NTUSER.DAT` entry shows a modification (`1705033200`) newer than its birth time (`1704000000`), consistent with a Run-key persistence write that RegRipper's `run` plugin would reveal.

Note: the bodyfile column order is `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` ([TSK mactime man page](https://www.sleuthkit.org/sleuthkit/man/mactime.html)), so the last field is the creation (crtime) time and the second-to-last is ctime; the epoch-to-UTC conversions above assume UTC (`mactime -z UTC`).

Sample sha256: reproduce with the generator's `sha256sum intrusion_bodyfile.txt`; the digest is held by the validator (regenerate deterministically from the provided heredoc, which produces identical bytes).

## MITRE ATT&CK & DFIR phase
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (RegRipper `run`) — https://attack.mitre.org/techniques/T1547/001/
- **T1070.006** — Indicator Removal: Timestomp (detected via MAC-time / `$SI` vs `$FN` inconsistencies) — https://attack.mitre.org/techniques/T1070/006/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs — https://attack.mitre.org/techniques/T1070/001/
- **T1091** — Replication Through Removable Media / device history (RegRipper `usbstor`) — https://attack.mitre.org/techniques/T1091/
- **T1059.001** — Command and Scripting Interpreter: PowerShell — https://attack.mitre.org/techniques/T1059/001/
- **T1134.002** — Access Token Manipulation: Create Process with Token — https://attack.mitre.org/techniques/T1134/002/
- **T1543.003** — Create or Modify System Process: Windows Service — https://attack.mitre.org/techniques/T1543/003/
- **T1053.005** — Scheduled Task/Job: Scheduled Task — https://attack.mitre.org/techniques/T1053/005/
- **T1564.004** — Hide Artifacts: NTFS Extended Attributes / Alternate Data Streams — https://attack.mitre.org/techniques/T1564/004/
- **DFIR phase:** Examination and Analysis (timeline reconstruction / correlation) following Identification.

### Threat Hunting & Detection Engineering

Once the 49-intrusion timeline is reconstructed, pivot to **proactive threat hunting** and **detection engineering** to identify similar adversary tradecraft. Focus on **T1059.001 (PowerShell)** and **T1134.002 (Token Manipulation)**—two techniques frequently observed in post-exploitation phases.

**Detection Logic:**
- **PowerShell Script Block Logging (Event ID 4104)** in Windows Event Logs (`Microsoft-Windows-PowerShell/Operational`) captures deobfuscated commands. Hunt for encoded commands (`-EncodedCommand`) or suspicious cmdlets like `Invoke-WebRequest -Uri <C2_URL>`. Pivot on `ScriptBlockText` fields containing base64 strings or unusual parameter combinations (e.g., `-NoProfile -ExecutionPolicy Bypass`). Also monitor **Event ID 4103** (Module Logging) for `Invoke-Expression` usage.
- **Process Creation Events (Event ID 4688)** with `TokenElevationType` set to `%%1936` (TokenElevationTypeFull) may indicate **T1134.002** if the parent process (e.g., `lsass.exe`) is unexpected. Correlate with **Event ID 4672** (Special Privileges Assigned) to identify token theft attempts. **Sysmon Event ID 10** (Process Access) with `TargetImage` = `lsass.exe` and `GrantedAccess` = `0x1438` is a strong indicator.
- **Zeek/Suricata:** Hunt for **HTTP requests to uncommon URIs** (e.g., `/admin/get.php`) with `user_agent` fields mimicking legitimate tools (e.g., `Mozilla/5.0 (Windows NT)`). Use Zeek’s `http.log` to pivot on `status_code=200` responses with small payloads (e.g., `<1KB`), a hallmark of C2 beaconing.
- **Service Creation (T1543.003):** Query Windows Event ID 4697 (Service Installed) and cross-reference with file creation times from the timeline. Look for services with `ImagePath` pointing to `%TEMP%` or `%APPDATA%`.
- **Scheduled Task (T1053.005):** Hunt for Event ID 4698 (Scheduled Task Created) and check the task XML for `Command` fields launching suspicious executables. Compare with file system timeline to see if the binary was created shortly before the task.

**Threat-Hunting Pivots:**
- **Sysmon Event ID 10 (Process Access)** targeting `lsass.exe` with `GrantedAccess` values like `0x1438` (read/write memory) or `0x1410` (query information). Pivot on `CallTrace` to identify the calling process.
- **Suricata’s `fileinfo` log** for executables downloaded via HTTP with mismatched MIME types (e.g., `.jpg` extension but `PE32` magic bytes). Correlate with Zeek `http.log` `uri` and `md5` fields.
- **Zeek `ssl.log`** for self-signed certificates or unusual `ja3` fingerprints associated with known C2 frameworks.

**Sources:**
- [CISA Alert AA23-347A: Threat Hunting for PowerShell Abuse](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a)
- [MITRE ATT&CK: Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134/)
- [Sysmon Documentation (Microsoft)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Zeek HTTP log reference](https://docs.zeek.org/en/master/logs/http.html)
- [Suricata File Extraction & fileinfo log](https://suricata.readthedocs.io/en/latest/output/log-files.html#fileinfo-log)

### Adversary Emulation & Red-Team Perspective

To effectively emulate an adversary in the context of the 49-intrusion-timeline-case, consider the tactics, techniques, and procedures (TTPs) involved in exploiting system vulnerabilities. An attacker may utilize techniques such as **T1204 (User Execution)** to trick users into executing malicious code via spearphishing attachments or drive-by downloads. The artifact left includes `.lnk` files in `%USERPROFILE%\Recent` or `%TEMP%\` with suspicious target paths, and event logs showing Office macros (Event ID 1003 for Excel). Alternatively, **T1550 (Use Alternate Authentication Material)** can be used for pass-the-hash (T1550.002) or pass-the-ticket (T1550.003). Artifacts include NTLM authentication events in the Security log (Event ID 4624 with LogonType = 9 or 3) and Kerberos ticket cache files in `%USERPROFILE%\AppData\Local\Microsoft\Windows\Caches`. Tools like Mimikatz create registry entries in `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets` or traces in `%TEMP%\mimikatz.log`. To evade detection, adversaries may clear ARP cache (T1070.006), disable Windows Defender (T1562.001), or use process injection (T1055.001) to hide payloads within legitimate processes. The timeline reconstruction with Plaso and Sleuth Kit can capture all these artifact timestamps: file creation of injected dll, LastWrite of modified registry keys, and event log clearing events. Understanding these TTPs and the resulting artifacts is crucial for developing effective detection and response strategies.

**Sources:**
- [MITRE ATT&CK: User Execution (T1204)](https://attack.mitre.org/techniques/T1204/)
- [MITRE ATT&CK: Use Alternate Authentication Material (T1550)](https://attack.mitre.org/techniques/T1550/)
- [Microsoft Security Logging for Kerberos and NTLM](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [SANS Windows Forensic Analysis Poster (Timestamps & Artifacts)](https://www.sans.org/posters/windows-forensic-analysis/)

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- Plaso `log2timeline.py`/`psort.py` usage, `--version`, `--storage-file`, `-o l2tcsv`, `-w`, event filters:
  - https://plaso.readthedocs.io/
  - https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html
  - https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html
  - https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html
  - Recommended install methods: https://plaso.readthedocs.io/en/latest/sources/user/Installation-instructions.html
- The Sleuth Kit `fls` (`-r`, `-m`, `-o`, `-V`), `mactime` (`-b`, `-d`, `-z`, `-V`) and bodyfile format:
  - https://www.sleuthkit.org/sleuthkit/man/fls.html
  - https://www.sleuthkit.org/sleuthkit/man/mactime.html
  - https://www.sleuthkit.org/sleuthkit/docs.php
- RegRipper (`rip.pl`, `-r`, `-p`, `run`/`usbstor` plugins):
  - https://github.com/keydet89/RegRipper3.0
- Windows Run / RunOnce registry key behavior (autostart persistence):
  - https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
- SANS DFIR — log2timeline / super-timelining and Windows forensic timestamps:
  - https://www.sans.org/blog/digital-forensics-sifting-cheating-timelines-with-log2timeline/
  - https://www.sans.org/posters/windows-forensic-analysis/
- SANS SIFT Workstation (pre-installed tooling):
  - https://www.sans.org/tools/sift-workstation/
- REMnux tools listing:
  - https://docs.remnux.org/discover-the-tools
- Security Onion (Suricata/Zeek/Elastic pivots):
  - https://docs.securityonion.net/
  - https://docs.securityonion.net/en/2.4/suricata.html
  - https://docs.securityonion.net/en/2.4/zeek.html
- Zeek `conn.log` fields (network correlation):
  - https://docs.zeek.org/en/master/logs/conn.html
- Zeek `http.log` fields:
  - https://docs.zeek.org/en/master/logs/http.html
- PowerShell ScriptBlock Logging and Event IDs 4104/4103:
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Sysmon Event ID 1, 10 and usage:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Security Events 4688, 4672, 4697, 4698, 4624:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing
- Suricata fileinfo log:
  - https://suricata.readthedocs.io/en/latest/output/log-files.html#fileinfo-log
- MITRE ATT&CK techniques:
  - T1547.001 — https://attack.mitre.org/techniques/T1547/001/
  - T1070.006 — https://attack.mitre.org/techniques/T1070/006/
  - T1070.001 — https://attack.mitre.org/techniques/T1070/001/
  - T1091 — https://attack.mitre.org/techniques/T1091/
  - T1059.001 — https://attack.mitre.org/techniques/T1059/001/
  - T1134.002 — https://attack.mitre.org/techniques/T1134/002/
  - T1543.003 — https://attack.mitre.org/techniques/T1543/003/
  - T1053.005 — https://attack.mitre.org/techniques/T1053/005/
  - T1564.004 — https://attack.mitre.org/techniques/T1564/004/
  - T1204 — https://attack.mitre.org/techniques/T1204/
  - T1550 — https://attack.mitre.org/techniques/T1550/
  - T1550.002 — https://attack.mitre.org/techniques/T1550/002/
- CISA Alert AA23-347A:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a

## Related modules
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares sleuth kit
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- shares sleuth kit
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- shares plaso
- [Registry analysis](../04-registry-analysis/README.md) -- shares regripper

<!-- cyberlab-enriched: v2 -->

<!-- cyberlab-enriched: v3 -->
