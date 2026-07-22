# 59 * Browser & internet-history forensics -- LAB-LINUX

## Overview (plain language)
Browsers store a detailed record of user activity — visited URLs, searches, downloads, cookies, and cached files — in SQLite databases. Hindsight parses these into a single timeline, a mainstay of DFIR for phishing, insider, and download-borne-malware cases.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Hindsight | pip install pyhindsight | Parse Chromium/Chrome/Edge (and Firefox) history, downloads, cookies, cache into a timeline |
| hindsight web UI | hindsight_gui.py | Interactive browsing of parsed browser artifacts |
| sqlite3 | apt install sqlite3 | Directly query the SQLite databases browsers use (History, Cookies, Login Data) |

## Learning objectives
- Locate and parse Chromium/Firefox profile artifacts with Hindsight
- Reconstruct a user's browsing, downloads, and search timeline
- Query the raw SQLite history/downloads databases directly
- Correlate browser artifacts with a phishing/download investigation

## Environment check
Run `hindsight.py -h`. Point it at a copy of a Chrome profile (`~/.config/google-chrome/Default`) or the provided sample profile — never the live profile.

## Guided walkthrough
1. Run Hindsight over a profile: `hindsight.py -i ./sample_profile -o browsing -f xlsx`.
2. Review the timeline: visited URLs, visit counts, transition types, and timestamps.
3. Inspect downloads for suspicious files (target path, source URL, danger flags).
4. Query the raw DB directly: `sqlite3 History "SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 20;"`.
5. Correlate a downloaded payload's source URL with the visit that preceded it.

## Hands-on exercise
Parse the provided browser profile with Hindsight, find the malicious download, and report its source URL, filename, and download timestamp. Confirm the visit that led to it in the `urls` table.

## SOC analyst perspective
Browser history answers 'how did it get in?' — analysts trace a malicious download or phishing click back through the visit chain, and check cookies/logins for account-takeover indicators.

## Attacker perspective
Attackers deliver payloads via drive-by downloads and phishing links, and may steal browser cookies/saved credentials (Login Data). Cleared history and incognito reduce but rarely eliminate artifacts (cache, DNS, SRUM).

## Answer key
Hindsight's downloads sheet lists the payload with its `tab_url`/`target_path`; the `urls` table shows the preceding visit. Chrome timestamps are microseconds since 1601-01-01 (subtract 11644473600 after /1e6 for epoch).

## MITRE ATT&CK & DFIR phase
- **T1539** — Steal Web Session Cookie — browser Cookies DB is the target and the evidence
- **T1189** — Drive-by Compromise — history/downloads trace the delivering site
- **T1566.002** — Phishing: Spearphishing Link — the clicked link appears in the visit chain

## Sources
- Hindsight: https://github.com/obsidianforensics/hindsight
- Chromium data formats: https://www.chromium.org/developers/design-documents/
- SANS DFIR browser forensics: https://www.sans.org/blog/

## Related modules
- - 03-timeline-analysis — fold browser events into a super-timeline
- - 48-phishing-doc-case — phishing investigation
