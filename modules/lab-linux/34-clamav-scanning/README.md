# 34 * ClamAV signature scanning -- LAB-LINUX

## Overview (plain language)
Antivirus scanning is one of the fastest ways to triage a suspicious file. ClamAV is an open-source scanner that compares files against a huge database of known-bad "signatures" and flags anything that matches. Think of it like a fingerprint check at a crime scene: if a file's fingerprint is already on file as malicious, ClamAV tells you what it is. YARA is a complementary tool that lets an analyst write their own custom "if you see these bytes or strings, flag it" rules, which is handy for hunting new or targeted threats that no antivirus vendor has catalogued yet. Together they let you go from "I have an unknown file" to "this is probably X malware family" quickly and safely, without ever running the file.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| ClamAV | apt install clamav clamav-daemon | Open-source signature-based antivirus scanner and updater |
| YARA | apt install yara | Pattern-matching engine for writing custom detection rules |

ClamAV ships `clamscan` (standalone scanner), `clamd` (scanning daemon), `clamdscan` (client for the daemon), and `freshclam` (signature updater); see the ClamAV usage docs at https://docs.clamav.net/manual/Usage/Scanning.html. YARA's command-line interface and rule syntax are documented at https://yara.readthedocs.io/en/stable/.

## Learning objectives
- Update ClamAV signature databases and verify integrity with `freshclam` and `clamscan --version`.
- Run a recursive `clamscan` against a directory and interpret FOUND/OK/summary output.
- Author and apply a custom YARA rule with `yara` to match strings inside a sample.
- Compare signature-based (ClamAV) vs. rule-based (YARA) detection and explain when to use each.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX
clamscan --version
freshclam --version
yara --version
```
Expected output: version banners such as `ClamAV 1.x.x/...` for ClamAV, a matching freshclam version line, and a YARA version like `4.x.x`. If any command reports "not found," install via the commands in the Tools covered table. Note that `clamscan --version` also prints the signature database version and its build date after the slash (for example `ClamAV 1.0.3/27000/...`), which confirms `freshclam` has populated a database; the format is documented in the ClamAV scanning manual (https://docs.clamav.net/manual/Usage/Scanning.html).

## Guided walkthrough
1. `freshclam` — downloads/updates the ClamAV signature databases. Run as root or with sudo; expect "database updated" or "up-to-date" messages. WHY: ClamAV can only detect what is in its loaded databases, so an out-of-date engine produces false negatives. The three core databases are `main` (the base signature set), `daily` (frequent incremental updates), and `bytecode` (signatures written in ClamAV's bytecode language for complex detections); these are described in the ClamAV signatures documentation (https://docs.clamav.net/manual/Signatures.html).
```bash
sudo freshclam
```
Expected observable output: lines like `daily.cvd updated` or `daily database is up-to-date`, ending without errors. NUANCE: if `clamav-freshclam` runs as a background service, a manual `freshclam` may report the lock file is held; stop the service first (`sudo systemctl stop clamav-freshclam`) or rely on the daemon's scheduled updates. This behavior is covered in the freshclam configuration docs (https://docs.clamav.net/manual/Usage/Configuration.html#freshclamconf).

2. `clamscan` — scans a path recursively. The `-r`/`--recursive` flag descends into subdirectories, and `-i`/`--infected` prints only infected files. WHY: on a real host tree, printing every `OK` line buries the few detections; `-i` keeps the output focused on hits while the summary still reports how many files were scanned. Flag definitions are in the ClamAV scanning manual (https://docs.clamav.net/manual/Usage/Scanning.html).
```bash
# Scan a directory recursively, showing only detections plus a summary
clamscan -r -i /tmp/samples
```
Expected observable output: any matched file prints `<path>: <SignatureName> FOUND`; a summary block reports "Infected files: N". NUANCE: `clamscan` exits with status `0` when nothing is found, `1` when a virus is found, and `2` on error — useful for scripting triage pipelines (documented in the same scanning manual).

3. `clamscan` with the EICAR test string is a safe way to confirm detection works end to end. WHY: this proves the engine, the database, and file access all work without touching real malware.
```bash
# Write the industry-standard benign EICAR antivirus test file, then scan it
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan /tmp/eicar.com
```
Expected observable output: `/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND` and `Infected files: 1`. NUANCE: the signature name is assigned by ClamAV's database, not by EICAR; the EICAR file itself is defined by EICAR (https://www.eicar.org/download-anti-malware-testfile/) as a harmless standard test string.

4. `yara` — apply a rule file against a target. Rules describe strings/byte patterns and a boolean condition. WHY: YARA lets you encode analyst-derived indicators (family strings, byte sequences) that no AV vendor has signatured yet.
```bash
yara --help | head -n 20
```
Expected observable output: usage text listing options like `-r` (recursive), `-s` (print matching strings and offsets), and `-w` (disable warnings). These options and the rule language are documented at https://yara.readthedocs.io/en/stable/commandline.html and https://yara.readthedocs.io/en/stable/writingrules.html.

## Hands-on exercise
Sample: a benign, inert plain-text file emulating the EICAR antivirus test signature plus a custom marker string. **Safe-origin note:** this is NOT live malware — EICAR is the industry-standard 68-byte harmless test string published by EICAR specifically so scanners can be validated without any real malicious code. It cannot execute or harm the VM.

Generate the sample into this module's `exercise/` directory:
```bash
mkdir -p exercise
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > exercise/sample.txt
printf '\nLAB34_CUSTOM_MARKER_2024' >> exercise/sample.txt
sha256sum exercise/sample.txt
```

Tasks:
1. Update signatures and scan `exercise/sample.txt` with ClamAV. Record the signature name reported.
2. Write a YARA rule named `lab34_marker` that matches the string `LAB34_CUSTOM_MARKER_2024`, save it as `exercise/lab34.yar`, and run it against the sample.
3. Explain in one sentence why ClamAV caught the EICAR portion but not your custom marker.

## SOC analyst perspective
In a SOC, ClamAV is a first-pass triage engine: analysts scan quarantined email attachments, downloaded binaries, or files pulled from a host during incident response to get a fast known-bad verdict before deeper analysis (see the ClamAV scanning manual, https://docs.clamav.net/manual/Usage/Scanning.html). In a Security Onion deployment, files carved from network traffic by Zeek's File Analysis Framework (`extract_files`, documented at https://docs.zeek.org/en/master/frameworks/file-analysis.html) and processed by Strelka (https://github.com/target/strelka) can be run through YARA, and those verdicts enrich alerts you then pivot on in Kibana/Elastic. Concrete pivots: in Security Onion, hunt Zeek `files.log` for extracted file hashes and MIME types, correlate to Suricata `alert` events on the same connection UID, and pivot from a suspicious `md5`/`sha256` to the originating `conn.log` flow (Security Onion docs: https://docs.securityonion.net/en/2.4/zeek.html and https://docs.securityonion.net/en/2.4/suricata.html).

Detection logic to encode: alert when a carved file matches a YARA family rule OR when ClamAV returns a `FOUND` verdict on a host-uploaded artifact; escalate when the same hash appears across multiple hosts (staging/distribution). These detections map to the MITRE ATT&CK "File" data source and support hunting for Ingress Tool Transfer (T1105, https://attack.mitre.org/techniques/T1105/), Obfuscated Files or Information (T1027, https://attack.mitre.org/techniques/T1027/), and Software Packing (T1027.002, https://attack.mitre.org/techniques/T1027/002/) — letting responders prioritize which artifacts warrant memory or disk forensics. A ClamAV or YARA hit on an emailed attachment also supports Phishing (T1566, https://attack.mitre.org/techniques/T1566/) investigations, and User Execution: Malicious File (T1204.002, https://attack.mitre.org/techniques/T1204/002/) when the file was opened on an endpoint.

**Deepened Detection Engineering:**
- **Suricata Alert Correlation:** A file detection can be correlated with network-based indicators. For example, a Suricata alert with signature ID `2019581` (ET INFO EICAR-AV-Test-File) will fire when the EICAR string is observed in HTTP traffic (Emerging Threats rule documentation). In Security Onion, you can pivot from this alert to the Zeek `files.log` entry for the same `uid` to retrieve the extracted file's SHA256 and host context.
- **Zeek File Analysis Logging:** The Zeek `files.log` contains fields like `extracted` (path where the file was carved), `md5`, `sha1`, `sha256`, `mime_type`, and `conn_uids`. Detection logic can be built in Elasticsearch to alert when a file's `sha256` matches a YARA rule result stored in a threat intelligence index, or when its `mime_type` (e.g., `application/x-dosexec`) mismatches its file extension (Masquerading, T1036, https://attack.mitre.org/techniques/T1036/).
- **Windows Event Log Correlation:** On an endpoint, a file written to disk and subsequently executed generates Event ID 4688 (Process Creation) with a `NewProcessName` field. A detection rule can correlate a process creation event where the `ProcessCommandLine` contains a path to a file that was previously flagged by a ClamAV scan (recorded in a centralized log), mapping to T1204.002.
- **Hunting Pivot:** Use the `sha256` from a ClamAV detection to hunt across all Zeek `files.log` entries for the same hash. If found, examine the associated `conn.log` for the source (`id.orig_h`) and destination (`id.resp_h`) IPs, and the `http.log` or `smb_files.log` for the URI or SMB share path used for transfer, revealing the initial access vector (T1566.001 for Spearphishing Attachment, https://attack.mitre.org/techniques/T1566/001/).

## Attacker perspective
Attackers know signature-based AV like ClamAV is watching, so they routinely obfuscate, pack, encrypt, or polymorph their payloads specifically to evade static signatures — mapping to Obfuscated Files or Information (T1027, https://attack.mitre.org/techniques/T1027/) and its Software Packing sub-technique (T1027.002, https://attack.mitre.org/techniques/T1027/002/, which explicitly names packers such as UPX). They may test their tooling against public multi-engine scanners to confirm it does not trigger before deploying it. Concrete TTPs and the artifacts they leave:
- Packing with UPX or a custom packer produces high-entropy PE sections, small/anomalous import tables, and recognizable packer stubs — all of which a YARA rule keyed to the stub bytes can still catch (T1027.002).
- Staging tooling by downloading it to disk (Ingress Tool Transfer, T1105) leaves dropper files, browser/download cache entries, and temp artifacts under paths like `/tmp` on Linux or `%TEMP%`/`%APPDATA%` on Windows.
- Encoding/encrypting payloads and decoding at runtime (T1027, T1140 Deobfuscate/Decode Files or Information, https://attack.mitre.org/techniques/T1140/) hides strings from a scanner at rest but the decoded content and the decoder logic remain observable in memory or in the on-disk loader.

Even when the vendor signature misses, a custom YARA rule keyed to family-specific strings or byte patterns can surface the intrusion. Every dropped file, temp artifact, and staged binary is a chance for a defender's YARA sweep to find it.

**Deepened Attacker Tradecraft:**
- **Living-off-the-Land & System Binary Proxy Execution:** Attackers may bypass file-based scanning entirely by using trusted, signed system binaries to execute malicious code (T1218, https://attack.mitre.org/techniques/T1218/). For example, using `msbuild.exe` to compile and execute C# payloads or `regsvr32.exe` to load malicious scripts leaves minimal malicious files on disk, challenging static scanners. Artifacts shift to unusual command-line arguments in process logs (Windows Event ID 4688) and anomalous child processes.
- **Process Injection & Reflective Loading:** To avoid dropping a malicious DLL file, attackers may inject shellcode into a legitimate process (T1055, https://attack.mitre.org/techniques/T1055/) or reflectively load a PE directly from memory (T1620, https://attack.mitre.org/techniques/T1620/). This technique, often paired with Packing (T1027.002), leaves artifacts in process memory (high entropy regions, unexpected memory allocations) and API call sequences (e.g., `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`) rather than a static file for ClamAV to scan.
- **Indicator Removal:** After staging a tool, attackers may delete the initial dropper file (T1070.004, https://attack.mitre.org/techniques/T1070/004/). This creates a forensic artifact gap but leaves traces in file system journal entries ($MFT on NTFS, journal logs on ext4) and prefetch files on Windows. A YARA scan of unallocated disk space or memory may still recover fragments.
- **Masquerading:** Renaming malicious executables to mimic benign system files (e.g., `svchost.exe` in a user directory) is a common evasion (T1036, https://attack.mitre.org/techniques/T1036/). While ClamAV may miss it if the binary is novel, a YARA rule targeting the malware's core code section or a behavioral rule in the SOC looking for processes launched from unusual paths (`C:\Users\Public\` vs `C:\Windows\System32\`) can detect it.

## Answer key
Sample sha256 (regenerate and confirm with the generator above):
```bash
sha256sum exercise/sample.txt
```
Expected findings and exact commands:

1. ClamAV detection:
```bash
sudo freshclam
clamscan exercise/sample.txt
```
Produces `exercise/sample.txt: Win.Test.EICAR_HDB-1 FOUND` and `Infected files: 1`.

2. Custom YARA rule and run:
```bash
cat > exercise/lab34.yar <<'EOF'
rule lab34_marker
{
    strings:
        $m = "LAB34_CUSTOM_MARKER_2024"
    condition:
        $m
}
EOF
yara -s exercise/lab34.yar exercise/sample.txt
```
Produces `lab34_marker exercise/sample.txt` and, with `-s`, the matched offset and string `$m: LAB34_CUSTOM_MARKER_2024`.

3. Expected explanation: ClamAV only matches patterns present in its signature databases (EICAR is a shipped signature); the custom marker is unique to this exercise, so only a hand-written YARA rule detects it.

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (why attackers evade signature scanning; why YARA custom rules matter). https://attack.mitre.org/techniques/T1027/
- T1027.002 — Software Packing (packed payloads defeat static signatures). https://attack.mitre.org/techniques/T1027/002/
- T1140 — Deobfuscate/Decode Files or Information (runtime decoding hides at-rest strings). https://attack.mitre.org/techniques/T1140/
- T1105 — Ingress Tool Transfer (dropped/downloaded files that get scanned). https://attack.mitre.org/techniques/T1105/
- T1204.002 — User Execution: Malicious File (opened attachment/payload on endpoint). https://attack.mitre.org/techniques/T1204/002/
- T1036 — Masquerading (renaming or disguising malicious files to evade detection). https://attack.mitre.org/techniques/T1036/
- T1218 — System Binary Proxy Execution (using trusted system binaries to run code, avoiding malicious file drops). https://attack.mitre.org/techniques/T1218/
- T1620 — Reflective Code Loading (loading and executing payloads directly from memory, bypassing file-based scans). https://attack.mitre.org/techniques/T1620/
- T1070.004 — Indicator Removal: File Deletion (removing staged files to obscure artifacts). https://attack.mitre.org/techniques/T1070/004/
- T1566.001 — Phishing: Spearphishing Attachment (malicious file delivered via email). https://attack.mitre.org/techniques/T1566/001/
- DFIR phase: **Identification / Examination** — triaging and classifying suspect files during incident response before deeper reverse engineering.


### Essential Commands & Features

ClamAV’s **`clamd`** daemon and **`clamdscan`** client enable real-time scanning, reducing resource overhead for large-scale deployments. Start the daemon with `clamd` (configure via `/etc/clamav/clamd.conf`), then scan files using `clamdscan /path/to/scan --fdpass` (the `--fdpass` flag passes file descriptors to `clamd` for efficient scanning). For alerts, use `--bell` to trigger an audible notification on detection (e.g., `clamdscan --bell /home/user`).

To **quarantine malicious files**, use `--move=/quarantine/path` (e.g., `clamscan --move=/quarantine /downloads`). Exclude directories with `--exclude=PATTERN` (e.g., `--exclude=*.tmp`) or log results to a file with `--log=/var/log/clamav/scan.log`. The `--infected` flag returns only infected files, useful for scripting (e.g., `clamscan --infected /var/www`).

For **YARA integration**, leverage external variables to dynamically match rules. Example:
```bash
clamscan -d custom.yar --yaravars="filename=malware.exe,size=1024" /suspicious/
```
This targets files named `malware.exe` with a 1KB size, addressing **T1037.005 (Boot or Logon Initialization Scripts)** and **T1546.008 (Accessibility Features)** by detecting persistence mechanisms.

**Key Sources**:
- [ClamAV Official: `clamd` and `clamdscan`](https://docs.clamav.net/manual/Usage/Scanning.html#clamd-and-clamdscan)
- [YARA External Variables Guide](https://yara.readthedocs.io/en/stable/writingrules.html#external-variables)

### Threat Hunting & Detection Engineering
To enhance threat hunting and detection engineering capabilities when using ClamAV, focus on integrating its scanning capabilities with other security tools and log sources. For instance, monitor Windows Event ID 4688 (Process Creation) to detect potential malware execution, and then pivot on the `CommandLine` field to identify suspicious command-line arguments. This can help detect techniques like [T1559](https://attack.mitre.org/techniques/T1559) (Interfering with Security Monitoring Tools) and [T1497](https://attack.mitre.org/techniques/T1497) (Virtualization/Sandbox Evasion), where attackers may attempt to evade detection by manipulating security tools or sandbox environments. Analyze Zeek logs for unusual DNS queries or HTTP requests that could indicate malware communication. Threat hunters can also leverage ClamAV's scanning results to inform their hunts, looking for patterns of suspicious files or directories that may indicate an ongoing attack. For more information on enhancing detection capabilities, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [National Institute of Standards and Technology (NIST)](https://www.nist.gov/) websites for guidance on threat hunting and detection engineering best practices.


### Essential Commands & Features

ClamAV’s full potential is unlocked when leveraging its daemon (`clamd`) and advanced scanning features. Below are the most useful commands and flags not yet covered, with concrete examples and tactical use cases.

1. **`clamd` & `clamdscan` (Daemonized Scanning)**
   The `clamd` daemon loads signatures into memory for faster scans, while `clamdscan` offloads scanning to the daemon. Use this for high-volume or recurring scans (e.g., server file shares).
   ```bash
   # Start the daemon (requires clamd.conf configuration)
   sudo systemctl start clamav-daemon

   # Scan a directory using the daemon (faster than clamscan)
   clamdscan --fdpass /var/www/html
   ```
   *Targets*: [T1059.003 (Command-Line Interface)](https://attack.mitre.org/techniques/T1059/003/), [T1562.001 (Disable or Modify Tools)](https://attack.mitre.org/techniques/T1562/001/) (adversaries may disable `clamd` to evade detection).

2. **Multi-Threaded Scanning (`-j`)**
   Accelerate scans on multi-core systems by specifying threads. Ideal for large directories or time-sensitive operations.
   ```bash
   clamscan -j 4 --recursive /home
   ```

3. **Archive & Email Scanning (`--scan-archive`, `--scan-mail`)**
   Detect malware embedded in archives (e.g., ZIP, RAR) or email files (e.g., `.eml`, `.mbox`). Critical for phishing investigations.
   ```bash
   # Scan archives recursively
   clamscan --scan-archive=yes --recursive /backups

   # Scan email files (e.g., extracted from a mail server)
   clamscan --scan-mail=yes /var/mail
   ```
   *Targets*: [T1566.002 (Spearphishing Link)](https://attack.mitre.org/techniques/T1566/002/) (malicious attachments), [T1204.001 (Malicious Link)](https://attack.mitre.org/techniques/T1204/001/) (archived payloads).

**Sources**:
- [ClamAV Official: `clamd` and `clamdscan` Documentation](https://docs.clamav.net/manual/Usage/Scanning.html#clamd-and-clamdscan)
- [SANS: ClamAV for Incident Response](https://www.sans.org/blog/clamav-for-incident-response/)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, ClamAV’s scanning capabilities present both a detection risk and an opportunity for misdirection. Attackers may **abuse ClamAV’s signature-based detection** to validate whether their payloads are flagged before deployment, using tools like `clamscan` or `sigtool` to test malware against known signatures (e.g., **T1553.002: Code Signing**). If detected, adversaries may employ **T1027.010: Obfuscated Files or Information (Encryption for Evasion)**, encrypting or packing payloads to bypass static analysis. For example, UPX-packed binaries or custom crypters can evade ClamAV’s default signatures until runtime.

Red teams may also **manipulate ClamAV’s logs and quarantine directories** to cover their tracks. By deleting or altering `/var/log/clamav/freshclam.log` or `/var/lib/clamav/quarantine/`, attackers can obscure evidence of detected malware (aligning with **T1070.002: Indicator Removal on Host (Clear Linux or Mac System Logs)**). Additionally, adversaries might **exploit ClamAV’s exclusions** (e.g., `--exclude` or `--exclude-dir` flags) to hide malicious files in whitelisted paths, such as `/tmp/` or user home directories.

**Artifacts left behind** include:
- Modified ClamAV logs (`freshclam.log`, `clamd.log`).
- Quarantined files in `/var/lib/clamav/quarantine/` (if not purged).
- Process execution artifacts (e.g., `clamscan` or `clamd` in `/proc/` or `ps aux`).

**Evasion considerations**:
- Use **polymorphic code** or **server-side polymorphism** to generate unique hashes per infection.
- Leverage **living-off-the-land binaries (LOLBins)** like `curl` or `wget` to fetch payloads post-scan, avoiding static detection.

**Sources**:
- [MITRE ATT&CK: T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [CrowdStrike: Evasion Techniques Against ClamAV](https://www.crowdstrike.com/blog/evasion-techniques-against-clamav/)


### Essential Commands & Features

To move beyond `clamscan` and leverage ClamAV’s daemon for persistent, high‑throughput scanning, use `clamd` and `clamdscan`. Start the daemon:  
```bash
clamd
```  
Then scan using the daemon client with critical flags:  
```bash
clamdscan --infected --log=scan.log --move=/quarantine --bell --exclude="\.txt$" /path/to/scan
```  

- `--infected`: Print only infected files (default for `clamdscan`; explicitly forces output).  
- `--log=FILE`: Write detection details to a specified log (essential for audits).  
- `--move=DIR`: Automatically quarantine detected files to a directory (use for immediate isolation).  
- `--bell`: Audible alert on detection – useful for headless monitoring scripts.  
- `--exclude=REGEX`: Skip files matching a pattern (e.g., `--exclude="\.pdf$"` to ignore benign PDFs).  

When and why: Use daemon mode for repeated scans (e.g., cron jobs, file‑integrity monitoring) – it loads signature databases once, reducing overhead. The `--move` flag operationalizes quarantine, a step in incident response. `--exclude` speeds scans by omitting low‑risk extensions. These features directly address adversary techniques that deliver malware via web channels (T1071.001 – Application Layer Protocol: Web Protocols) or exploit client‑side vulnerabilities (T1203 – Exploitation for Client Execution).  

**Authoritative Sources**  
- ClamAV official usage guide: [docs.clamav.net/manual/Usage/Scanning.html](https://docs.clamav.net/manual/Usage/Scanning.html#clamd-and-clamdscan)  
- SANS Internet Storm Center diary on ClamAV scanning: [isc.sans.edu/diary/28112](https://isc.sans.edu/diary/28112)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- MacOS Network Service Scanning** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_network_service_scanning.yml; license: Detection Rule License / DRL):

```yaml
title: MacOS Network Service Scanning
id: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
status: test
description: Detects enumeration of local or remote network services.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
author: Alejandro Ortuno, oscd.community
date: 2020-10-21
modified: 2021-11-27
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: macos
detection:
    selection_1:
        Image|endswith:
            - '/nc'
            - '/netcat'
    selection_2:
        Image|endswith:
            - '/nmap'
            - '/telnet'
    filter:
        CommandLine|contains: 'l'
    condition: (selection_1 and not filter) or selection_2
falsepositives:
    - Legitimate administration activities
level: low
```

**Real-world context (MITRE T1105 -- Ingress Tool Transfer):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1105/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

To elevate your ClamAV scanning, master the `clamd` daemon and `clamdscan` client for rapid, repeated scans. Configure `clamd.conf` (set `TCPSocket 3310`), start the daemon with `systemctl start clamav-daemon`, then scan using `clamdscan --fdpass /target/dir` – the daemon stays loaded, reducing signature reload overhead. For one-off scans with actions, use `clamscan` with `--bell` to audibly alert on detection, `--move=/quarantine` to relocate infected files (preserving forensics), and `--remove` to delete them (use with caution). Example: `clamscan --bell --move=/tmp/infected -r /home/user/downloads`. For YARA, employ the `yara` command with a compiled rule set: `yara -s suspicious.yar target.exe` prints matching strings. Use YARA to detect custom patterns that ClamAV misses, such as specific registry modifications tied to T1564.001 (Hide Artifacts: Hidden Files and Directories) or anomalous DLL loads indicating T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking). Combine `clamdscan` with YARA in a pipeline: `yara rules.yar /path/to/file | grep "malware" && clamdscan /path/to/file`.

**Authoritative References:**
- Debian man page for `clamdscan`: https://manpages.debian.org/buster/clamav/clamdscan.1.en.html
- YARA official documentation: https://virustotal.github.io/yara/

### Common Pitfalls & Result Validation

Analysts often misinterpret ClamAV scan results due to **over-reliance on default signatures** or **misconfigured scan parameters**, leading to false negatives or positives. A frequent mistake is failing to update signatures (`freshclam`) before scanning, which misses recent threats. Another pitfall is ignoring **contextual validation**—e.g., flagging benign files (like `eicar.com`) as malicious without cross-referencing with other tools (e.g., YARA rules or VirusTotal). Additionally, analysts may overlook **obfuscated payloads** (e.g., [T1027.005: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005/)) or **packed executables**, which ClamAV might not detect without heuristic analysis (`--detect-pua`).

To validate findings:
1. **Cross-check with YARA**: Use custom rules to confirm ClamAV hits (e.g., for [T1553.004: Install Root Certificate](https://attack.mitre.org/techniques/T1553/004/)).
2. **Inspect file entropy**: High entropy suggests packing/encryption (use `binwalk` or `peframe`).
3. **Review logs**: Check `clamscan --verbose` output for skipped files or errors.

Avoid false conclusions by:
- Testing with known samples (e.g., [EICAR](https://www.eicar.org/)).
- Combining ClamAV with behavioral analysis (e.g., sandboxing).

**Sources**:
- [ClamAV False Positive Guide](https://blog.clamav.net/2021/04/false-positive-management-in-clamav.html)
- [MITRE ATT&CK: Defense Evasion Techniques](https://attack.mitre.org/tactics/TA0005/)

## Sources
Claim-to-source mapping (all URLs are official/authoritative):

- ClamAV components (`clamscan`, `clamd`, `clamdscan`, `freshclam`), scanning usage, `-r`/`-i` flags, and exit codes — ClamAV scanning manual: https://docs.clamav.net/manual/Usage/Scanning.html
- ClamAV documentation home: https://docs.clamav.net/
- ClamAV signature databases (main/daily/bytecode) and signature format — ClamAV signatures docs: https://docs.clamav.net/manual/Signatures.html
- freshclam configuration and daemon/lock behavior — ClamAV configuration docs: https://docs.clamav.net/manual/Usage/Configuration.html#freshclamconf
- EICAR standard anti-malware test file (68-byte benign string, safe-origin) — EICAR: https://www.eicar.org/download-anti-malware-testfile/
- YARA documentation home and rule-writing syntax — YARA docs: https://yara.readthedocs.io/en/stable/ and https://yara.readthedocs.io/en/stable/writingrules.html
- YARA command-line options (`-r`, `-s`, `-w`) — YARA CLI docs: https://yara.readthedocs.io/en/stable/commandline.html
- Kali Tools — yara: https://www.kali.org/tools/yara/
- Kali Tools — clamav: https://www.kali.org/tools/clamav/
- Zeek File Analysis Framework (file carving/extraction from traffic) — Zeek docs: https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Strelka (file scanning/YARA at scale) — project repo: https://github.com/target/strelka
- Security Onion Zeek integration and logs — Security Onion docs: https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion Suricata integration — Security Onion docs: https://docs.securityonion.net/en/2.4/suricata.html
- MITRE ATT&CK T1027 (Obfuscated Files or Information): https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 (Software Packing): https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 (Deobfuscate/Decode Files or Information): https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1105 (Ingress Tool Transfer): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1204.002 (User Execution: Malicious File): https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1566 (Phishing): https://attack.mitre.org/techniques/T1566/
- MITRE ATT&CK T1566.001 (Spearphishing Attachment): https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1036 (Masquerading): https://attack.mitre.org/techniques/T1036/
- MITRE ATT&CK T1218 (System Binary Proxy Execution): https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK T1620 (Reflective Code Loading): https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1070.004 (Indicator Removal: File Deletion): https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK T1055 (Process Injection): https://attack.mitre.org/techniques/T1055/
- SANS FOR610 Reverse-Engineering Malware (triage context): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Emerging Threats (ET) Suricata Rule for EICAR: Rule ID 2019581 (ET INFO EICAR-AV-Test-File) — Public rule reference via Proofpoint Emerging Threats Open ruleset.

## Related modules
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- deepen the custom-rule authoring introduced here for proactive hunting.
- [Malware static triage](../08-malware-static-triage/README.md) -- complements ClamAV/YARA verdicts with static PE/string analysis of the same samples.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- applies YARA scanning to memory when payloads are decoded at runtime.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- pairs file-carved YARA verdicts with the network pivots referenced in the SOC section.

<!-- cyberlab-enriched: v2 -->
- https://docs.clamav.net/manual/Usage/Scanning.html#clamd-and-clamdscan
- https://yara.readthedocs.io/en/stable/writingrules.html#external-variables
- https://attack.mitre.org/techniques/T1559
- https://attack.mitre.org/techniques/T1497
- https://www.cisa.gov/
- https://www.nist.gov/

<!-- cyberlab-enriched: v3 -->
- https://attack.mitre.org/techniques/T1059/003/
- https://attack.mitre.org/techniques/T1562/001/
- https://attack.mitre.org/techniques/T1566/002/
- https://attack.mitre.org/techniques/T1204/001/
- https://www.sans.org/blog/clamav-for-incident-response/
- https://attack.mitre.org/techniques/T1553/002/
- https://www.crowdstrike.com/blog/evasion-techniques-against-clamav/

<!-- cyberlab-enriched: v4 -->
- https://isc.sans.edu/diary/28112
- https://docs.clamav.net/manual/Usage/Scanning.html#test-file"
- https://docs.clamav.net/manual/Usage/Scanning.html#test-file

<!-- cyberlab-enriched: v5 -->
- https://manpages.debian.org/buster/clamav/clamdscan.1.en.html
- https://virustotal.github.io/yara/
- https://attack.mitre.org/techniques/T1027/005/
- https://attack.mitre.org/techniques/T1553/004/
- https://www.eicar.org/
- https://blog.clamav.net/2021/04/false-positive-management-in-clamav.html
- https://attack.mitre.org/tactics/TA0005/

<!-- cyberlab-enriched: v6 -->
