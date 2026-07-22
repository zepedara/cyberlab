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
- **Service creation (T1543.003).** Hunt for Windows Event ID 4697 (Service Installed) and correlate with the service binary's file creation time from the timeline. Look for services with `ImagePath` pointing to `%TEMP%` or `%APPDATA%` ([ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/); [Microsoft Learn: Event ID 4697](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)).
- **Scheduled task registration (T1053.005).** Hunt for Event ID 4698 (Scheduled Task Created) and check the task XML for `Command` fields launching suspicious executables. Compare with file system timeline to see if the binary was created shortly before the task ([ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/); [Microsoft Learn: Event ID 4698](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)).
- **Obfuscated files (T1027).** Detect encoded PowerShell scripts via Event ID 4104 `ScriptBlockText` containing long base64 strings or `Invoke-Expression`. Correlate with file creation of `.ps1` files in `%TEMP%` with anomalous entropy (high Shannon entropy >7.5) using Plaso's file system parser ([ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)).
- **Masquerading (T1036).** Identify renamed system binaries (e.g., `svch0st.exe`) by comparing file names in the timeline against known-good hashes (e.g., Microsoft's hash catalog). Look for executables in user writeable directories (`%APPDATA%`, `%TEMP%`) with names similar to legitimate system processes ([ATT&CK T1036](https://attack.mitre.org/techniques/T1036/)).
- **Lateral Tool Transfer (T1570).** Correlate file creation of remote administration tools (e.g., `PsExec.exe`, `Mimikatz.exe`) with network connections to internal IPs in Zeek `conn.log`. Look for `SERVICE` field `smb` or `rpc` and `orig_bytes` > 1MB, indicating file transfer. The timeline will show the tool's creation time and subsequent SMB/WinRM connections ([ATT&CK T1570](https://attack.mitre.org/techniques/T1570/)).
- **Data from Local System (T1005).** Hunt for file access events (Windows Event ID 4663) targeting sensitive files like `C:\Windows\NTDS\ntds.dit` or `C:\Windows\System32\config\SAM`. Correlate with the creation of `vssadmin` shadow copies or `ntdsutil` execution in the timeline. Plaso's Windows Event Log parser can extract these events ([ATT&CK T1005](https://attack.mitre.org/techniques/T1005/)).
- **Process Injection (T1055.001).** Hunt for Windows Event ID 4688 (Process Creation) where the parent process is a known injection vector (e.g., `rundll32.exe`, `regsvr32.exe`) and the child process is a system binary (e.g., `svchost.exe`). Correlate with the creation time of a suspicious DLL in `%TEMP%` or `%APPDATA%` from the timeline. Sysmon Event ID 8 (CreateRemoteThread) with `StartAddress` pointing to a non-image region can also indicate injection ([ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/); [Sysmon Event ID 8](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-8-createremotethread)).
- **Exfiltration Over C2 Channel (T1041).** Hunt for Zeek `conn.log` entries where a host makes repeated outbound connections to a single external IP on non-standard ports (e.g., 8443, 8080) with consistent `orig_bytes` sizes (e.g., 512KB chunks). Correlate with file deletion events (Windows Event ID 4660) of sensitive documents just before the network traffic. The timeline can show the file deletion timestamp preceding the exfiltration connection ([ATT&CK T1041](https://attack.mitre.org/techniques/T1041/); [Zeek conn.log reference](https://docs.zeek.org/en/master/logs/conn.html)).

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
- **Obfuscated files (T1027).** Attackers encode payloads in base64 or XOR to evade signature detection. This leaves artifacts like high-entropy files in `%TEMP%` and encoded PowerShell commands in Event ID 4104 logs. The timeline will show the encoded file creation and subsequent execution events ([ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)).
- **Masquerading (T1036).** Renaming malicious executables to resemble legitimate system files (e.g., `lsass.exe` vs `lsass.exe`) can bypass casual inspection. This leaves a file with a suspicious name in a non-standard location (e.g., `C:\Windows\Temp\svchost.exe`) and a creation timestamp that can be correlated with process execution events ([ATT&CK T1036](https://attack.mitre.org/techniques/T1036/)).
- **Process injection (T1055).** Injecting malicious code into a legitimate process (e.g., `explorer.exe`) leaves artifacts in memory and may create a child process with unexpected parent-child relationships. The timeline may show the injection DLL's file creation and subsequent process creation events with anomalous parent PIDs ([ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)).
- **Lateral Tool Transfer (T1570).** Attackers copy tools like `PsExec` or `Mimikatz` to target systems over SMB or RDP. This leaves file creation events on the remote host and network connections in Zeek `conn.log`. To evade, they may rename the tool (T1036) or use living-off-the-land binaries (T1218) like `wmic` for lateral movement, which leaves fewer file artifacts but still creates process execution events ([ATT&CK T1570](https://attack.mitre.org/techniques/T1570/)).
- **Data from Local System (T1005).** Adversaries may steal local files like `SAM`, `SYSTEM`, or `ntds.dit` for credential harvesting. They use tools like `vssadmin` to create shadow copies or `reg save` to export registry hives. This leaves file creation events for the stolen data and command-line artifacts in Windows Event Logs (Event ID 4688). The timeline will show the tool execution and subsequent file writes ([ATT&CK T1005](https://attack.mitre.org/techniques/T1005/)).
- **Process Injection via DLL Search Order Hijacking (T1574.001).** Attackers place a malicious DLL in a directory searched before the legitimate one (e.g., `C:\ProgramData\` before `C:\Windows\System32\`). This leaves a file creation event for the DLL and a process creation event for the legitimate executable that loads it. The timeline can show the DLL creation time just before the executable launch ([ATT&CK T1574.001](https://attack.mitre.org/techniques/T1574/001/)).
- **Exfiltration Over C2 Channel (T1041).** Attackers exfiltrate data over existing C2 channels (e.g., HTTPS, DNS) to blend with normal traffic. They may chunk data into small packets and send at regular intervals. This leaves network connections in Zeek `conn.log` with consistent `orig_bytes` sizes and periodic timing. The timeline can correlate file access/deletion events with these outbound connections ([ATT&CK T1041](https://attack.mitre.org/techniques/T1041/)).

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
- **T1027** — Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- **T1036** — Masquerading — https://attack.mitre.org/techniques/T1036/
- **T1055** — Process Injection — https://attack.mitre.org/techniques/T1055/
- **T1570** — Lateral Tool Transfer — https://attack.mitre.org/techniques/T1570/
- **T1005** — Data from Local System — https://attack.mitre.org/techniques/T1005/
- **T1055.001** — Process Injection: Dynamic-link Library Injection — https://attack.mitre.org/techniques/T1055/001/
- **T1041** — Exfiltration Over C2 Channel — https://attack.mitre.org/techniques/T1041/
- **T1574.001** — Hijack Execution Flow: DLL Search Order Hijacking — https://attack.mitre.org/techniques/T1574/001/
- **DFIR phase:** Examination and Analysis (timeline reconstruction / correlation) following Identification.

### Threat Hunting & Detection Engineering

Once the 49-intrusion timeline is reconstructed, pivot to **proactive threat hunting** and **detection engineering** to identify similar adversary tradecraft. Focus on **T1059.001 (PowerShell)** and **T1134.002 (Token Manipulation)**—two techniques frequently observed in post-exploitation phases.

**Detection Logic:**
- **PowerShell Script Block Logging (Event ID 4104)** in Windows Event Logs (`Microsoft-Windows-PowerShell/Operational`) captures deobfuscated commands. Hunt for encoded commands (`-EncodedCommand`) or suspicious cmdlets like `Invoke-WebRequest -Uri <C2_URL>`. Pivot on `ScriptBlockText` fields containing base64 strings or unusual parameter combinations (e.g., `-NoProfile -ExecutionPolicy Bypass`). Also monitor **Event ID 4103** (Module Logging) for `Invoke-Expression` usage.
- **Process Creation Events (Event ID 4688)** with `TokenElevationType` set to `%%1936` (TokenElevationTypeFull) may indicate **T1134.002** if the parent process (e.g., `lsass.exe`) is unexpected. Correlate with **Event ID 4672** (Special Privileges Assigned) to identify token theft attempts. **Sysmon Event ID 10** (Process Access) with `TargetImage` = `lsass.exe` and `GrantedAccess` = `0x1438` is a strong indicator.
- **Zeek/Suricata:** Hunt for **HTTP requests to uncommon URIs** (e.g., `/admin/get.php`) with `user_agent` fields mimicking legitimate tools (e.g., `Mozilla/5.0 (Windows NT)`). Use Zeek’s `http.log` to pivot on `status_code=200` responses with small payloads (e.g., `<1KB`), a hallmark of C2 beaconing.
- **Service Creation (T1543.003):** Query Windows Event ID 4697 (Service Installed) and cross-reference with file creation times from the timeline. Look for services with `ImagePath` pointing to `%TEMP%` or `%APPDATA%`.
- **Scheduled Task (T1053.005):** Hunt for Event ID 4698 (Scheduled Task Created) and check the task XML for `Command` fields launching suspicious executables. Compare with file system timeline to see if the binary was created shortly before the task.
- **Lateral Tool Transfer (T1570):** Hunt for SMB connections (`service` = `smb` in Zeek `conn.log`) with large `orig_bytes` (>1MB) followed by file creation events for known lateral movement tools (e.g., `PsExec.exe`, `Mimikatz.exe`). Correlate with Windows Event ID 5145 (Network Share Object) for file access.
- **Data from Local System (T1005):** Hunt for file access events (Windows Event ID 4663) targeting sensitive files like `C:\Windows\NTDS\ntds.dit` or `C:\Windows\System32\config\SAM`. Correlate with the creation of `vssadmin` shadow copies or `ntdsutil` execution in the timeline. Plaso's Windows Event Log parser can extract these events.
- **Process Injection (T1055.001):** Hunt for Windows Event ID 4688 (Process Creation) where the parent process is a known injection vector (e.g., `rundll32.exe`, `regsvr32.exe`) and the child process is a system binary (e.g., `svchost.exe`). Correlate with the creation time of a suspicious DLL in `%TEMP%` or `%APPDATA%` from the timeline. Sysmon Event ID 8 (CreateRemoteThread) with `StartAddress` pointing to a non-image region can also indicate injection.
- **Exfiltration Over C2 Channel (T1041):** Hunt for Zeek `conn.log` entries where a host makes repeated outbound connections to a single external IP on non-standard ports (e.g., 8443, 8080) with consistent `orig_bytes` sizes (e.g., 512KB chunks). Correlate with file deletion events (Windows Event ID 4660) of sensitive documents just before the network traffic. The timeline can show the file deletion timestamp preceding the exfiltration connection.

**Threat-Hunting Pivots:**
- **Sysmon Event ID 10 (Process Access)** targeting `lsass.exe` with `GrantedAccess` values like `0x1438` (read/write memory) or `0x1410` (query information). Pivot on `CallTrace` to identify the calling process.
- **Suricata’s `fileinfo` log** for executables downloaded via HTTP with mismatched MIME types (e.g., `.jpg` extension but `PE32` magic bytes). Correlate with Zeek `http.log` `uri` and `md5` fields.
- **Zeek `ssl.log`** for self-signed certificates or unusual `ja3` fingerprints associated with known C2 frameworks.
- **Windows Event ID 4688 (Process Creation)** with `ParentProcessName` containing `rundll32.exe` and `CommandLine` containing `javascript:` or `vbscript:` to detect **T1218.011** (Signed Binary Proxy Execution: Rundll32). Correlate with timeline entries for script file creation in `%TEMP%`.
- **Zeek `files.log`** for files transferred over SMB with `filename` matching known lateral movement tools (e.g., `PsExec.exe`, `Mimikatz.exe`). Pivot on `tx_hosts` and `rx_hosts` to map internal movement.

**Sources:**
- [CISA Alert AA23-347A: Threat Hunting for PowerShell Abuse](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a)
- [MITRE ATT&CK: Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134/)
- [Sysmon Documentation (Microsoft)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Zeek HTTP log reference](https://docs.zeek.org/en/master/logs/http.html)
- [Suricata File Extraction & fileinfo log](https://suricata.readthedocs.io/en/latest/output/log-files.html#fileinfo-log)
- [MITRE ATT&CK: Process Injection (T1055.001)](https://attack.mitre.org/techniques/T1055/001/)
- [MITRE ATT&CK: Exfiltration Over C2 Channel (T1041)](https://attack.mitre.org/techniques/T1041/)
- [Zeek conn.log reference](https://docs.zeek.org/en/master/logs/conn.html)
- [Windows Security Auditing Events (Microsoft)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)

### Adversary Emulation & Red-Team Perspective

To effectively emulate an adversary in the context of the 49-intrusion-timeline-case, consider the tactics, techniques, and procedures (TTPs) involved in exploiting system vulnerabilities. An attacker may utilize techniques such as **T1204 (User Execution)** to trick users into executing malicious code via spearphishing attachments or drive-by downloads. The artifact left includes `.lnk` files in `%USERPROFILE%\Recent` or `%TEMP%\` with suspicious target paths, and event logs showing Office macros (Event ID 1003 for Excel). Alternatively, **T1550 (Use Alternate Authentication Material)** can be used for pass-the-hash (T1550.002) or pass-the-ticket (T1550.003). Artifacts include NTLM authentication events in the Security log (Event ID 4624 with LogonType = 9 or 3) and Kerberos ticket cache files in `%USERPROFILE%\AppData\Local\Microsoft\Windows\Caches`. Tools like Mimikatz create registry entries in `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets` or traces in `%TEMP%\mimikatz.log`. To evade detection, adversaries may clear ARP cache (T1070.006), disable Windows Defender (T1562.001), or use process injection (T1055.001) to hide payloads within legitimate processes. The timeline reconstruction with Plaso and Sleuth Kit can capture all these artifact timestamps: file creation of injected dll, LastWrite of modified registry keys, and event log clearing events. Understanding these TTPs and the resulting artifacts is crucial for developing effective detection and response strategies.

**Sources:**
- [MITRE ATT&CK: User Execution (T1204)](https://attack.mitre.org/techniques/T1204/)
- [MITRE ATT&CK: Use Alternate Authentication Material (T1550)](https://attack.mitre.org/techniques/T1550/)
- [Microsoft Security Logging for Kerberos and NTLM](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [SANS Windows Forensic Analysis Poster (Timestamps & Artifacts)](https://www.sans.org/posters/windows-forensic-analysis/)

### Essential Commands & Features

Beyond the basics, these three Plaso components unlock deeper investigative capabilities when building an intrusion timeline.

**`pinfo` – Inspect Storage File Metadata**  
Before querying a timeline, verify the processing provenance. `pinfo` reports the Plaso version, parser count, and number of events, ensuring the storage file isn’t truncated or from an unknown build.  

Example:  
`pinfo /cases/breach.plaso`  

Use this when you inherit a timeline from another analyst or re-run a collection – it catches mismatched toolchains early.  

**`psort` – Time-Range & Parser Filtering**  
Focus analysis on windows that matter. `psort` can slice by absolute time or relative offsets, and include/exclude specific parsers to reduce noise.  

Example (events between 2025-01-10 14:00 and 15:00, only from Windows Registry parsers):  
`psort -o dynamic -w output.csv -q "date > '2025-01-10 14:00:00' AND date < '2025-01-10 15:00:00' AND parser CONTAINS 'winreg'" /cases/breach.plaso`  

This isolates lateral movement (T1078 – Valid Accounts) or initial access (T1566.001 – Spearphishing Attachment) indicators that often cluster in narrow intervals.  

**`image_export` – File Carving from Disk Images**  
When a timeline event references a suspicious file path, carve the raw data from the source image without mounting it.  

Example:  
`image_export -f "/Users/jdoe/AppData/Local/Temp/evil.exe" -w /output_dir disk.dd`  

Use this to retrieve attacker‑dropped payloads (T1203 – Exploitation for Client Execution) for hash extraction or static analysis.  

For advanced `psort` filtering: [Forensic Focus – Using Plaso for Timeline Analysis](https://www.forensicfocus.com/articles/using-plaso-for-timeline-analysis/)  
For `image_export` carving workflows: [HECF Blog – Timeline Analysis with Plaso](https://www.hecfblog.com/2017/03/daily-blog-892-timeline-analysis-with.html)

### Common Pitfalls & Result Validation

When reconstructing an intrusion timeline, analysts often fall into **time-zone mismatches** or **timestamp misinterpretation**, particularly with tools like `log2timeline` or `Timesketch`. A common error is assuming all timestamps are in UTC, when logs may use local system time or epoch formats (e.g., Windows Event Logs vs. Linux syslog). Always validate time sources by cross-referencing with known events (e.g., system boot times) and document the timezone offset. Another pitfall is **overlooking deleted artifacts**; tools like `fls` (The Sleuth Kit) may miss files if the MFT is fragmented or wiped. Validate findings by correlating file system metadata with registry hives (e.g., `NTUSER.DAT`) or prefetch files to confirm execution.

False conclusions often arise from **ignoring context**. For example, detecting **T1027 (Obfuscated Files or Information)** via encoded PowerShell scripts may lead to false positives if benign scripts (e.g., admin tools) use similar techniques. Validate by checking script provenance (e.g., signed vs. unsigned) and correlating with **T1569.002 (System Services: Service Execution)** to confirm malicious service creation. Similarly, **T1036 (Masquerading)**—where adversaries rename binaries—can mislead analysts if file hashes alone are trusted. Cross-check with process execution trees (e.g., `pslist` or EDR telemetry) to verify parent-child relationships.

**Sources:**
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf)
- [DFIR Review: Timestamp Analysis Pitfalls](https://www.dfir.review/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- COM Hijacking via TreatAs** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_treatas_persistence.yml; license: Detection Rule License / DRL):

```yaml
title: COM Hijacking via TreatAs
id: dc5c24af-6995-49b2-86eb-a9ff62199e82
status: test
description: Detect modification of TreatAs key to enable "rundll32.exe -sta" command
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md
    - https://www.youtube.com/watch?v=3gz1QmiMhss&t=1251s
author: frack113
date: 2022-08-28
modified: 2025-07-11
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1546.015
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: 'TreatAs\(Default)'
    filter_office:
        Image|startswith: 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\'
        Image|endswith: '\OfficeClickToRun.exe'
    filter_office2:
        Image:
            - 'C:\Program Files\Microsoft Office\root\integration\integrator.exe'
            - 'C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe'
    filter_svchost:
        # Example of target object by svchost
        # TargetObject: HKLM\SOFTWARE\Microsoft\MsixRegistryCompatibility\Package\Microsoft.Paint_11.2208.6.0_x64__8wekyb3d8bbwe\User\SOFTWARE\Classes\CLSID\{0003000A-0000-0000-C000-000000000046}\TreatAs\(Default)
        # TargetObject: HKU\S-1-5-21-1000000000-000000000-000000000-0000_Classes\CLSID\{0003000A-0000-0000-C000-000000000046}\TreatAs\(Default)
        Image: 'C:\Windows\system32\svchost.exe'
    filter_misexec:
        # This FP has been seen during installation/updates
        Image:
            - 'C:\Windows\system32\msiexec.exe'
            - 'C:\Windows\SysWOW64\msiexec.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate use
level: medium
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_osx_pyagent_persistence.yar, author: John Lambert @JohnLaTwC):

```yara
rule Persistence_Agent_MacOS {
    meta:
        description = "Detects a Python agent that establishes persistence on macOS"
        author = "John Lambert @JohnLaTwC"
        reference = "https://ghostbin.com/paste/mz5nf"
        hash = "4288a81779a492b5b02bad6e90b2fa6212fa5f8ee87cc5ec9286ab523fc02446 cec7be2126d388707907b4f9d681121fd1e3ca9f828c029b02340ab1331a5524 e1cf136be50c4486ae8f5e408af80b90229f3027511b4beed69495a042af95be"

        id = "9c69af3c-ee85-58ac-8b78-66760addc117"
    strings:
        $h1 = "#!/usr/bin/env python"
        $s_1= "<plist" ascii fullword
        $s_2= "ProgramArguments" ascii fullword
        $s_3= "Library" ascii fullword
        $sinterval_1= "StartInterval" ascii fullword
        $sinterval_2= "RunAtLoad" ascii fullword

        //<plist
        $e_1 = /(AHAAbABpAHMAdA|cGxpc3|PABwAGwAaQBzAHQA|PHBsaXN0|wAcABsAGkAcwB0A|xwbGlzd)/ ascii

        //ProgramArguments
        $e_2 =/(AAcgBvAGcAcgBhAG0AQQByAGcAdQBtAGUAbgB0AHMA|AHIAbwBnAHIAYQBtAEEAcgBnAHUAbQBlAG4AdABzA|Byb2dyYW1Bcmd1bWVudH|cm9ncmFtQXJndW1lbnRz|UAByAG8AZwByAGEAbQBBAHIAZwB1AG0AZQBuAHQAcw|UHJvZ3JhbUFyZ3VtZW50c)/ ascii
        //Library
        $e_4 = /(AGkAYgByAGEAcgB5A|aWJyYXJ5|TABpAGIAcgBhAHIAeQ|TGlicmFye|wAaQBiAHIAYQByAHkA|xpYnJhcn)/ ascii

        //StartInterval
        $einterval_a = /(AHQAYQByAHQASQBuAHQAZQByAHYAYQBsA|dGFydEludGVydmFs|MAdABhAHIAdABJAG4AdABlAHIAdgBhAGwA|N0YXJ0SW50ZXJ2YW|U3RhcnRJbnRlcnZhb|UwB0AGEAcgB0AEkAbgB0AGUAcgB2AGEAbA)/ ascii
        $einterval_b = /(AHUAbgBBAHQATABvAGEAZA|dW5BdExvYW|IAdQBuAEEAdABMAG8AYQBkA|J1bkF0TG9hZ|UgB1AG4AQQB0AEwAbwBhAGQA|UnVuQXRMb2Fk)/ ascii

    condition:
        uint32(0) == 0x752f2123
        and $h1 at 0
        and filesize < 120KB
        and
        (
            (all of ($s_*) and 1 of ($sinterval*))
            or
            (all of ($e_*) and 1 of ($einterval*))
        )

}
```

**Real-world context (MITRE T1547.001 -- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1547/001/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `49_intrusion_timeline_case_benign_sample.txt` |
| sample sha256 | `dadd427cf9df86c0b3f38857d5b25a7acc366d2c78c9d5374369bcdee4bd2af7` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 49-intrusion-timeline-case -- for detection-rule testing only
' |
### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1547 (Boot or Logon Autostart Execution)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1547/
- **Threat actors documented using it:** APT42 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

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
  - T1027 — https://attack.mitre.org/techniques/T1027/
  - T1036 — https://attack.mitre.org/techniques/T1036/
  - T1055 — https://attack.mitre.org/techniques/T1055/
  - T1570 — https://attack.mitre.org/techniques/T1570/
  - T1005 — https://attack.mitre.org/techniques/T1005/
  - T1204 — https://attack.mitre.org/techniques/T1204/
  - T1550 — https://attack.mitre.org/techniques/T1550/
  - T1550.002 — https://attack.mitre.org/techniques/T1550/002/
  - T1055.001 — https://attack.mitre.org/techniques/T1055/001/
  - T1041 — https://attack.mitre.org/techniques/T1041/
  - T1574.001 — https://attack.mitre.org/techniques/T1574/001/
- CISA Alert AA23-347A:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
- Forensic Focus – Using Plaso for Timeline Analysis:
  - https://www.forensicfocus.com/articles/using-plaso-for-timeline-analysis/
- HECF Blog – Timeline Analysis with Plaso:
  - https://www.hecfblog.com/2017/03/daily-blog-892-timeline-analysis-with.html
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response:
  - https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
- DFIR Review: Timestamp Analysis Pitfalls:
  - https://www.dfir.review/

## Related modules
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares sleuth kit
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- shares sleuth kit
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- shares plaso
- [Registry analysis](../04-registry-analysis/README.md) -- shares regripper

<!-- cyberlab-enriched: v6 -->
