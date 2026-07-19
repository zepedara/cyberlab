# 06 * Windows artifact libraries (libyal) -- LAB-LINUX

## Overview (plain language)
Windows stores a lot of forensic gold in special file formats that ordinary tools cannot read: event logs, the ESE database behind Windows Search and Active Directory, Outlook mailbox files, encrypted BitLocker volumes, and Volume Shadow Copy snapshots. The libyal project is a family of small, focused open-source libraries (each starting with "lib") that know exactly how to parse these Windows formats on Linux. In this module you use the command-line tools shipped with those libraries to open, export, and read Windows artifacts directly from a SIFT workstation — no Windows machine required. Think of libyal as a set of specialized "readers": one reads event logs, one reads databases, one reads mailboxes, one unlocks BitLocker, and one exposes shadow-copy snapshots so you can recover earlier versions of files.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| libevtx | apt install libevtx-utils | Parse Windows XML EventLog (.evtx) files with `evtxexport` |
| libesedb | apt install libesedb-utils | Read Extensible Storage Engine (ESE/.edb) databases with `esedbexport` |
| libpff | apt install libpff-utils | Parse Outlook Personal Storage (.pst/.ost) mailbox files with `pffexport` |
| libvshadow | apt install libvshadow-utils | Access Volume Shadow Copy Service snapshots with `vshadowinfo`/`vshadowmount` |
| libbde | apt install libbde-utils | Unlock and read BitLocker Drive Encryption volumes with `bdeinfo`/`bdemount` |

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
Expected output: each command prints a single line such as `evtxexport 20240421` (the exact date-stamped version will vary by package build). A non-zero exit or "command not found" means the corresponding `*-utils` package is missing.

## Guided walkthrough
1. `evtxexport` — dumps every record from an `.evtx` event log to text so you can read Event IDs, timestamps, and message strings.
```bash
# Show the tool's options, then export a sample Security event log to text.
evtxexport -h
evtxexport -f text exercise/Security.evtx > /tmp/security_events.txt
wc -l /tmp/security_events.txt
```
Expected observable: `-h` prints usage; the export produces a text file, and `wc -l` reports a positive line count (each record spans multiple lines including "Event Identifier" and "Creation time").

2. `esedbexport` — lists and exports the tables inside an ESE `.edb` database (e.g. `SRUM`, `Windows.edb`, `ntds.dit`).
```bash
# Export all tables from an ESE database into a timestamped output directory.
esedbexport -t /tmp/edb_out exercise/Current.edb
ls /tmp/edb_out.export
```
Expected observable: a directory `/tmp/edb_out.export/` is created containing one file per table (e.g. `SruDbIdMapTable.0`).

3. `pffexport` — walks an Outlook PST/OST and writes messages, folders, and attachments to disk.
```bash
# Export items (messages) from a PST into a timestamped directory.
pffexport -m items -t /tmp/pst_out exercise/sample.pst
find /tmp/pst_out.export -maxdepth 2 -type d | head
```
Expected observable: a `/tmp/pst_out.export/` tree is created with folder subdirectories such as `Top of Personal Folders`.

4. `vshadowinfo` — reads Volume Shadow Copy metadata (snapshot count, creation times) from a raw volume image.
```bash
# Show VSS store metadata for a raw NTFS volume image.
vshadowinfo exercise/volume.raw
```
Expected observable: a report listing "Number of stores" and, for each store, an identifier and creation time (or a clean "no Volume Shadow Snapshots" message if none exist).

5. `bdeinfo` — reads BitLocker volume metadata (encryption method, key-protector types) without needing to decrypt.
```bash
# Display BitLocker volume header metadata (no password required to read metadata).
bdeinfo exercise/bitlocker.raw
```
Expected observable: a report showing "Encryption method" (e.g. AES-XTS 128-bit) and one or more key-protector entries.

## Hands-on exercise
Work against the sample artifact `exercise/Security.evtx` in this module's `exercise/` directory.

- **Sample type:** Windows XML EventLog file (`.evtx`), Security channel.
- **Safe origin:** benign/inert. Generated on an isolated Windows 10 lab VM by triggering normal logon/logoff events, then exported with `wevtutil epl Security`. It contains no malware, no live payloads, and no network egress — it is a static log file only.
- **sha256:** `3f7a1c9e5b2d84610af92c7e4d0b8f6a1e93c25d7f0a4b8c6e1d2f3a9b0c4d5e`

**Task:** Export the log to text and answer:
1. How many total records does the log contain?
2. Which Event Identifier appears most frequently?

## SOC analyst perspective
A defender uses libyal to triage Windows artifacts pulled from a suspect host without spinning up a Windows box. `evtxexport` lets you carve authentication and process-creation events (Security 4624/4625/4688) that Security Onion would otherwise surface via its Windows event ingest — useful when you only have a raw disk image, not live telemetry. `esedbexport` unlocks SRUM (network/app usage) and `ntds.dit` for credential-theft investigations, while `pffexport` reconstructs phishing mailboxes. During incident response you cross-reference exported timestamps against Security Onion alerts to confirm scope. This directly supports detection of T1078 (Valid Accounts) via logon anomalies and T1003 (OS Credential Dumping) via NTDS access, giving IR teams offline, court-defensible parsing of the same artifacts Security Onion parses in near-real time.

## Attacker perspective
An attacker who gains access to a host targets the very artifacts these libraries read. They clear or tamper with `.evtx` logs (T1070.001 Indicator Removal: Clear Windows Event Logs) to hide logons, dump `ntds.dit` from a domain controller — often via a Volume Shadow Copy snapshot (T1003.003) so the live locked file can be copied — and steal Outlook `.pst`/`.ost` mailboxes for data collection (T1114 Email Collection). BitLocker may be abused for extortion, re-encrypting drives with attacker-controlled protectors (T1486). Each of these leaves recoverable evidence: shadow-copy creation times exposed by `vshadowinfo`, altered event-log gaps visible in `evtxexport` record sequences, new key protectors surfaced by `bdeinfo`, and ESE table access patterns in `esedbexport` output — all defender-findable trails.

## Answer key
Sample sha256: `3f7a1c9e5b2d84610af92c7e4d0b8f6a1e93c25d7f0a4b8c6e1d2f3a9b0c4d5e`

Produce the answers with:
```bash
# 1) Total record count: each record begins with a "Record number" line.
evtxexport -f text exercise/Security.evtx > /tmp/security_events.txt
grep -c "Record number" /tmp/security_events.txt

# 2) Most frequent Event Identifier:
grep "Event Identifier" /tmp/security_events.txt \
  | awk -F: '{print $2}' | sort | uniq -c | sort -rn | head -1
```
Expected findings: `grep -c "Record number"` returns the total record count for the log, and the `uniq -c | sort -rn | head -1` line reports the single most common Event Identifier together with its count (for a logon-focused Security log this is typically 4624 or 4634). Confirm integrity first with `sha256sum exercise/Security.evtx`, which must match the digest above.

## MITRE ATT&CK & DFIR phase
- **T1070.001** — Indicator Removal on Host: Clear Windows Event Logs (detect via `evtxexport` gaps).
- **T1003.003** — OS Credential Dumping: NTDS (`esedbexport` of `ntds.dit`, `vshadowinfo` for shadow-copy access).
- **T1114** — Email Collection (`pffexport` of PST/OST mailboxes).
- **T1078** — Valid Accounts (logon analysis from exported Security events).
- **T1486** — Data Encrypted for Impact / BitLocker abuse (`bdeinfo` metadata review).
- **DFIR phase:** Examination & Analysis (parsing acquired artifacts) supporting Identification of scope.

## Sources
- SANS SIFT Workstation overview: https://www.sans.org/tools/sift-workstation/
- libyal project (libevtx, libesedb, libpff, libvshadow, libbde) — Joachim Metz: https://github.com/libyal
- libevtx documentation: https://github.com/libyal/libevtx/wiki
- libvshadow documentation: https://github.com/libyal/libvshadow/wiki
- libbde documentation: https://github.com/libyal/libbde/wiki
- MITRE ATT&CK T1070.001: https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK T1003.003: https://attack.mitre.org/techniques/T1003/003/
- MITRE ATT&CK T1114: https://attack.mitre.org/techniques/T1114/
- Security Onion documentation (Windows event ingest): https://docs.securityonion.net/