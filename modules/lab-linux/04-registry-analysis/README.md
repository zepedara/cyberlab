# 04 * Registry analysis -- LAB-LINUX

## Overview (plain language)
The Windows Registry is a giant built-in database where Windows and its programs store settings — things like which programs run at startup, what USB devices were plugged in, recently opened files, and account details. When investigators grab a Windows disk image, they pull out the raw "registry hive" files (SYSTEM, SOFTWARE, NTUSER.DAT, and others). These files are not plain text, so you need special tools to read them. The tools in this module — RegRipper and libregf-tools — let you open those hive files on a Linux analysis box and turn them into readable reports, without ever booting the suspect Windows machine. RegRipper runs a big library of plugins that automatically extract the forensically interesting settings, while libregf-tools lets you browse and export individual keys and values by hand.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| RegRipper | apt install regripper | Plugin-driven parser that extracts forensic artifacts from Windows Registry hives into text reports |
| libregf-tools | apt install libregf-utils | Low-level utilities (regfinfo, regfexport, regfmount) to inspect and export raw Windows Registry hive files |

## Learning objectives
- Verify RegRipper and libregf-tools are installed and runnable on LAB-LINUX.
- Use `regfinfo` and `regfexport` to inspect the structure and contents of a raw registry hive.
- Run RegRipper against a hive and select relevant plugins to extract persistence and system artifacts.
- Interpret extracted keys (e.g. Run keys, computer name) and map them to MITRE ATT&CK techniques.

## Environment check
```bash
# Prove RegRipper is present (prints usage/version banner)
rip.pl -h

# Prove libregf-tools are present
regfinfo -V
regfexport -V
```
Expected output: `rip.pl -h` prints the RegRipper usage banner listing options like `-r`, `-f`, `-p`. `regfinfo -V` and `regfexport -V` each print a version line such as `regfinfo 20240421` confirming libregf-tools is installed.

## Guided walkthrough
1. `regfinfo` — reports hive metadata (type, version, root key) to confirm the file is a valid hive.
```bash
regfinfo exercise/SYSTEM_sample.hive
```
Expected: a summary showing the file signature `regf`, major/minor version, and the root key, proving the hive parses cleanly.

2. `regfexport` — dumps the full key/value tree as text so you can grep for specific keys.
```bash
regfexport exercise/SYSTEM_sample.hive > /tmp/system_dump.txt
grep -i "ComputerName" /tmp/system_dump.txt | head
```
Expected: lines showing the `ControlSet\Control\ComputerName\ComputerName` value with the host name string.

3. `rip.pl` with a targeted plugin — RegRipper's `compname` plugin pulls the computer name in one step.
```bash
rip.pl -r exercise/SYSTEM_sample.hive -p compname
```
Expected: RegRipper prints the plugin header, the source key path, and the recovered computer name value.

## Hands-on exercise
Task: Using the benign sample hive in this module's `exercise/` directory, determine (a) the computer name stored in the SYSTEM hive and (b) confirm the hive parses as a valid `regf` file.

Sample declaration:
- Type: Windows Registry SYSTEM hive fragment (raw `regf` file).
- Safe origin: Generated inside a disposable Windows sandbox VM by exporting a stock SYSTEM hive, then trimmed for size. It is benign/inert data only — it contains no executable code, no malware, and no network egress occurs when parsing it.
- Filename: `exercise/SYSTEM_sample.hive`
- sha256: `9f2c4a7e1b8d6f30c5a9e2740b13d8f6a71c904e5b28d3f6019a7c4e82b5d6f1`

Steps: run `regfinfo` to confirm the signature, then use either `regfexport | grep ComputerName` or `rip.pl -p compname` to recover the computer name.

## SOC analyst perspective
Registry analysis is a core examination step during Windows incident response. Defenders parse SYSTEM/SOFTWARE/NTUSER hives to hunt persistence: RegRipper's `run`, `services`, and `winlogon` plugins surface autostart entries that map to MITRE ATT&CK T1547.001 (Registry Run Keys) and T1543.003 (Windows Service). In a Security Onion workflow, an alert (e.g. Sysmon Event ID 13 registry-value-set forwarded through the Elastic stack) points you at a suspect host; you then pull the hive from the disk image and confirm the malicious key with RegRipper offline. Correlating the extracted key path, value data, and hive last-write time against Security Onion timeline data lets you scope the intrusion and build detections for the observed persistence key across the estate.

## Attacker perspective
Attackers routinely abuse the Registry for persistence and defense evasion. They write payload paths into `...\CurrentVersion\Run` (T1547.001), create malicious services (T1543.003), stash encoded payloads in obscure values (T1112 Modify Registry / T1027 fileless storage), and toggle security settings. These actions leave durable artifacts: the modified key path, the value data (often a suspicious binary path or base64 blob), and — crucially — the hive/key last-write timestamps that libregf's `regfexport` and RegRipper preserve. Because these writes persist on disk in the hive files, an analyst using RegRipper or `regfexport` can recover the exact malicious value and its write time even after the attacker deletes the on-disk payload.

## Answer key
Expected findings:
- The hive is a valid `regf` file (regfinfo prints the `regf` signature and version), confirming (b).
- The computer name value is recoverable via the SYSTEM hive.

Exact commands:
```bash
regfinfo exercise/SYSTEM_sample.hive
rip.pl -r exercise/SYSTEM_sample.hive -p compname
regfexport exercise/SYSTEM_sample.hive | grep -i "ComputerName"
sha256sum exercise/SYSTEM_sample.hive
```
`regfinfo` confirms the `regf` signature; `rip.pl -p compname` and the `regfexport | grep` both return the ComputerName value from `ControlSet001\Control\ComputerName\ComputerName`. The `sha256sum` output must equal `9f2c4a7e1b8d6f30c5a9e2740b13d8f6a71c904e5b28d3f6019a7c4e82b5d6f1`.

## MITRE ATT&CK & DFIR phase
- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1543.003 — Create or Modify System Process: Windows Service
- T1112 — Modify Registry
- T1027 — Obfuscated Files or Information (encoded data stored in registry values)
- DFIR phase: Examination / Analysis (offline parsing of acquired hives), feeding Identification and Scoping.

## Sources
- RegRipper (Harlan Carvey), tool background and usage — https://github.com/keydet89/RegRipper3.0
- SANS DFIR, Windows Registry forensics resources — https://www.sans.org/blog/digital-forensics-registry/
- libregf / libregf-tools documentation (Joachim Metz, libyal) — https://github.com/libyal/libregf
- REMnux / SIFT Windows artifact tooling reference — https://digital-forensics.sans.org/community/downloads
- MITRE ATT&CK T1547.001 — https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1112 — https://attack.mitre.org/techniques/T1112/