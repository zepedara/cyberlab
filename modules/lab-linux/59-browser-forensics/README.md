# 59 * Browser & internet-history forensics -- LAB-LINUX

## Overview (plain language)
Browsers store a detailed record of user activity — visited URLs, searches, downloads, cookies, and cached files — in SQLite databases. Hindsight parses these into a single timeline, a mainstay of DFIR for phishing, insider, and download-borne-malware cases. The Chromium-based browsers (Chrome, Edge, Brave) all share the same SQLite schema, while Firefox uses a similar but distinct set of databases. Hindsight also supports Firefox parsing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Hindsight | `pip install pyhindsight` | Parse Chromium/Chrome/Edge (and Firefox) history, downloads, cookies, cache into a timeline |
| hindsight web UI | `hindsight_gui.py` (in repo) | Interactive browsing of parsed browser artifacts |
| sqlite3 | `apt install sqlite3` | Directly query the SQLite databases browsers use (History, Cookies, Login Data) |

## Learning objectives
- Locate and parse Chromium/Firefox profile artifacts with Hindsight
- Reconstruct a user's browsing, downloads, and search timeline
- Query the raw SQLite history/downloads databases directly
- Correlate browser artifacts with a phishing/download investigation

## Environment check
Run `hindsight.py -h` (ensure you are inside the Hindsight cloned repository or that the script is in your PATH; after pip installation the command may be `hindsight`). Point it at a copy of a Chrome profile (`~/.config/google-chrome/Default`) or the provided sample profile — never the live profile. Always work on a forensic copy to avoid modifying the original data.

## Guided walkthrough
1. **Run Hindsight over a profile**:  
   `hindsight.py -i ./sample_profile -o browsing -f xlsx`  
   *Why?* The `-i` flag specifies the input profile directory, `-o` sets the output name prefix, and `-f xlsx` outputs an Excel file containing multiple sheets (timeline, downloads, cookies, etc.). This command creates a single timeline merging all browser artifacts.

2. **Review the timeline**:  
   Open the generated Excel file (or CSV if you used `-f csv`). Examine visited URLs, visit counts, transition types (typed, link, auto-subframe, etc.), and timestamps. The `visit_count` column helps distinguish high-frequency legitimate sites from one-off malicious visits.

3. **Inspect downloads for suspicious files**:  
   In the downloads sheet, note the `tab_url` (source page where the download initiated), `target_path` (where the file was saved), and `danger_type` (e.g., DANGEROUS_HOST, DANGEROUS_FILE_TYPE, or SAFE). Look for executable files (.exe, .scr, .msi) or scripts (.ps1, .vbs) from untrusted domains.

4. **Query the raw DB directly**:  
   `sqlite3 History "SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 20;"`  
   *Why?* The raw SQLite database (`History`) contains the `urls` table with Chrome timestamps stored as microseconds since 1601-01-01 (epoch). The conversion formula (`last_visit_time/1000000 - 11644473600`) converts to Unix epoch (seconds). This direct query bypasses Hindsight’s abstraction and allows custom filtering.

5. **Correlate a downloaded payload’s source URL with the visit that preceded it**:  
   Find the download entry in the `downloads` table (or Hindsight’s download sheet). Note its `tab_url` and the timestamp. Then query `urls` table for visits to that `tab_url` within a few seconds before the download. This reconstructs the exact kill chain: phishing page → click → payload.

## Hands-on exercise
Parse the provided browser profile with Hindsight, find the malicious download, and report its source URL, filename, and download timestamp. Confirm the visit that led to it in the `urls` table. Use `sqlite3` to directly inspect the `downloads` table for additional metadata such as `referrer` and `danger_type`.

## SOC analyst perspective
Browser history answers *“how did it get in?”* — analysts trace a malicious download or phishing click back through the visit chain, and check cookies/logins for account-takeover indicators. From a detection engineering standpoint:

- **Log sources**: Proxy logs (e.g., Squid, Zscaler) record the outbound HTTP/S requests; combine with Zeek `http.log` (from Security Onion) to map user agent, URI, and referrer. In Windows environments, Sysmon Event ID 1 (process creation) shows the browser (e.g., `chrome.exe`) launching with the URL as a command-line argument (if not stripped). Sysmon Event ID 11 (FileCreate) logs the downloaded payload.
- **MITRE ATT&CK Techniques**: Leverage **T1204.002** (User Execution: Malicious File) for the user clicking a downloaded file; **T1105** (Ingress Tool Transfer) for the download itself; and **T1566.002** (Spearphishing Link) for the initial access. The encoded/obfuscated scripts often involved map to **T1027.002** (Obfuscated Files or Information: Software Packing) or **T1059.001** (PowerShell) if a payload is fetched, decoded, and executed.
- **Threat-hunting pivots**:
  1. **Time-based correlation**: In Elastic or Kibana, search for events with `winlog.event_id: 1` and `event_data.CommandLine` containing a long URL or base64 string, followed within seconds by `winlog.event_id: 11` with `event_data.TargetFilename` containing `.exe` or `.ps1`.
  2. **Network beaconing**: In Zeek `dns.log`, look for resolutions of domains visited only seconds before a download – especially if the domain was registered recently (WHOIS age < 30 days) or uses a TLD associated with abuse (e.g., `.tk`, `.xyz`).
  3. **Cookie exfiltration**: In Zeek `ssl.log`, identify TLS connections to known C2 domains where the client negotiates an unusual cipher suite or presents a mismatched JA3 fingerprint.
- **Security Onion specific pivots**: Use the Analyst Console (SOC) to query:
  - `suricata.alerts` with `alert.signature_id: 202XXXX` (e.g., ET MALWARE generic).
  - `zeek.http` with `http.method: POST` and `http.uri` containing `.php`, `.asp`, or encoded parameters.
  - Correlate with `zeek.ssl` `server_name` to identify beaconing to unknown IPs.

- **Windows Event ID References**:
  - **4688** (Process Creation) with `CommandLine` that includes a browser download URL.
  - **4663** (Attempt to access an object) for browser profile directories being read (e.g., `Cookies`, `Login Data`) — indicative of credential stealing.
  - **Process Access (Sysmon 10)** for browsers targeted by credential theft tools.

## Attacker perspective
Attackers deliver payloads via drive-by downloads and phishing links, and may steal browser cookies/saved credentials (Login Data). Cleared history and incognito reduce but rarely eliminate artifacts (cache, DNS, SRUM, prefetch). Specific TTPs include:

- **Phishing link with social engineering** → user clicks → payload download via browser URL redirect chain (often shortlinks or URL shorteners).
- **Drive-by download** via exploit kits (e.g., Fallout, Angler) targeting browser vulnerabilities (e.g., CVE-2021-30563) – artifacts: dropped files in %TEMP%, shellcode injection into browser process.
- **Credential harvesting**: Using `Get-BrowserData.ps1` or LaZagne to extract saved passwords from Chrome’s `Login Data` database (encrypted with Windows DPAPI, vulnerable if user is logged in & not using master password). The attacker would copy the profile directory or query the SQLite database remotely.
- **Session cookie theft**: Steal Chrome’s `Cookies` database to bypass MFA – artifacts: suspicious connections from an unusual IP (attacker) using the stolen cookie. The Zeek `http.log` will show a request with a `Cookie` header not aligned with the typical user session.
- **Evasion techniques**:
  - Incognito mode: prevents writing history/downloads to the main database, but the cache directory is still written (though cleared on close). However, memory analysis of the browser process reveals visited URLs in heap memory.
  - Clearing browsing data (via `chrome://settings/clearBrowserData`) deletes history and cookies, but leaves prefetch files (on Windows) and registry entries (e.g., `\\.DEFAULT\Software\Microsoft\Internet Explorer\TypedURLs`). Also, Volume Shadow Copy (VSS) may contain the old browser data.
  - **Timestomping** (T1070.006): attacker modifies the last access time of files to obfuscate the timeline.
- **Artifacts left behind**:
  - Prefetch: `CHROME.EXE-*.pf` records first execution time and path.
  - Amcache: stores execution evidence.
  - $MFT: timestamps give creation, modification, and access times.
  - SRUM (System Resource Usage Monitor) tracks network usage per application.

## Answer key
Hindsight's downloads sheet lists the payload with its `tab_url`/`target_path`; the `urls` table shows the preceding visit. Chrome timestamps are microseconds since 1601-01-01 (subtract 11644473600 after /1e6 for epoch). Example: `timestamp = 13344444444444444 -> 2022-03-15 14:22:55` (use `datetime()` function as shown). The `downloads` table’s `start_time` and `end_time` also use the same format.

## MITRE ATT&CK & DFIR phase
- **T1539** — Steal Web Session Cookie — browser Cookies DB is the target and the evidence
- **T1189** — Drive-by Compromise — history/downloads trace the delivering site
- **T1566.002** — Phishing: Spearphishing Link — the clicked link appears in the visit chain
- **T1204.002** — User Execution: Malicious File — user runs the downloaded payload
- **T1105** — Ingress Tool Transfer — the download itself (payload brought to victim)
- **T1562.001** — Impair Defenses: Disable or Modify Tools — attacker clears browser history or disables security features
- **T1070.004** — Indicator Removal: File Deletion — attacker deletes browser profile files
- **T1036.005** — Masquerading: Match Legitimate Name or Location — downloaded file may be named `invoice.pdf.exe` to appear benign

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Suspicious Where Execution** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_where_browser_data_recon.yml; license: Detection Rule License / DRL):

```yaml
title: Suspicious Where Execution
id: 725a9768-0f5e-4cb3-aec2-bc5719c6831a
status: test
description: |
    Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
    Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
    internal network resources such as servers, tools/dashboards, or other related infrastructure.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1217/T1217.md
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2021-12-13
modified: 2022-06-29
tags:
    - attack.discovery
    - attack.t1217
logsource:
    category: process_creation
    product: windows
detection:
    where_exe:
        - Image|endswith: '\where.exe'
        - OriginalFileName: 'where.exe'
    where_opt:
        CommandLine|contains:
            # Firefox Data
            - 'places.sqlite'
            - 'cookies.sqlite'
            - 'formhistory.sqlite'
            - 'logins.json'
            - 'key4.db'
            - 'key3.db'
            - 'sessionstore.jsonlz4'
            # Chrome Data
            - 'History'
            - 'Bookmarks'
            - 'Cookies'
            - 'Login Data'
    condition: all of where_*
falsepositives:
    - Unknown
level: low
```

**Real-world context (MITRE T1204.002 -- User Execution: Malicious File):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1204/002/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1539 (Steal Web Session Cookie)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1539/
- **Threat actors documented using it:** APT42 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
- Hindsight GitHub repository: [https://github.com/obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) (installation, usage, and code)
- Chromium Timestamp Conversion: [SANS Cyber Security Blog](https://www.sans.org/blog/understanding-google-chrome-chromium-timestamps/) (explanation of the WebKit time format)
- MITRE ATT&CK Technique T1539 (Steal Web Session Cookie): [https://attack.mitre.org/techniques/T1539/](https://attack.mitre.org/techniques/T1539/)
- MITRE ATT&CK Technique T1189 (Drive-by Compromise): [https://attack.mitre.org/techniques/T1189/](https://attack.mitre.org/techniques/T1189/)
- MITRE ATT&CK Technique T1566.002 (Spearphishing Link): [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)
- MITRE ATT&CK Technique T1204.002 (User Execution: Malicious File): [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)
- MITRE ATT&CK Technique T1105 (Ingress Tool Transfer): [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)
- MITRE ATT&CK Technique T1562.001 (Impair Defenses: Disable or Modify Tools): [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)
- MITRE ATT&CK Technique T1070.004 (Indicator Removal: File Deletion): [https://attack.mitre.org/techniques/T1070/004/](https://attack.mitre.org/techniques/T1070/004/)
- MITRE ATT&CK Technique T1036.005 (Masquerading: Match Legitimate Name or Location): [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)
- Chromium Browser Design Documents (SQLite schemas): [https://www.chromium.org/developers/design-documents/](https://www.chromium.org/developers/design-documents/)
- Security Onion Documentation: [https://docs.securityonion.net/en/latest/](https://docs.securityonion.net/en/latest/) (Zeek, Suricata, Elastic Stack integration)
- Microsoft Sysmon Event IDs: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (Event IDs 1, 3, 11)
- SANS FOR508 Advanced Forensic Analysis: [https://www.sans.org/cyber-security-courses/advanced-forensic-analysis/](https://www.sans.org/cyber-security-courses/advanced-forensic-analysis/) (course covering browser forensics)

## Related modules
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- same learning path (Scenarios)
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- same learning path (Scenarios)
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- same learning path (Scenarios)
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- same learning path (Scenarios)

<!-- cyberlab-enriched: v6 -->
