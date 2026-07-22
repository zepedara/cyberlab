# 58 * EVTX threat hunting with Hayabusa & Chainsaw -- LAB-LINUX

## Overview (plain language)
Windows Event Logs (.evtx) are the richest host telemetry in an intrusion. Hayabusa and Chainsaw apply Sigma detection rules across whole log directories and rank the hits, turning thousands of events into a short, prioritized lead list for the analyst.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Hayabusa | download from github.com/Yamato-Security/hayabusa | Fast Sigma-based Windows event-log (.evtx) hunting with ranked, timeline-friendly detections |
| Chainsaw | download from github.com/WithSecureLabs/chainsaw | Rapid EVTX/MFT hunting with Sigma rule matching and keyword search |
| Sigma | apt install sigma / clone SigmaHQ | Generic signature format for log detections; both tools consume Sigma rules |
| EvtxECmd | download from ericzimmerman.github.io | Normalize .evtx to CSV/JSON as a bridge into timeline tools |

## Learning objectives
- Run Hayabusa and Chainsaw against a directory of .evtx logs to surface ranked detections
- Apply Sigma rules to hunt for specific TTPs (e.g. suspicious PowerShell, service install, logon anomalies)
- Correlate event-log detections into an incident timeline
- Understand Windows Event IDs that matter (4688, 4624/4625, 7045, 4104)

## Environment check
Confirm the binaries run: `hayabusa help` and `chainsaw help`. Point them at the provided sample `.evtx` set. Both are cross-platform CLI tools that run on the SIFT Linux host.

## Guided walkthrough
1. Generate a ranked detection timeline: `hayabusa csv-timeline -d ./evtx -o timeline.csv`.
2. Triage the highest-severity hits first (critical/high) and note their Event IDs + timestamps.
3. Hunt with Chainsaw + Sigma: `chainsaw hunt ./evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml`.
4. Pivot on a lead — e.g. a 7045 service install or 4104 script block — and pull surrounding events.
5. Export normalized events with `EvtxECmd.exe -d ./evtx --csv . --csvf events.csv` for timeline correlation.

## Hands-on exercise
Run Hayabusa against the sample `./evtx` set, identify the highest-severity detection, and report its Event ID, technique, and timestamp. Confirm the same activity with a Chainsaw Sigma hunt.

## SOC analyst perspective
This is the daily bread of log-based detection: analysts run Sigma-driven sweeps over collected event logs to find lateral movement, persistence, and execution, then build a timeline from the ranked hits instead of reading raw logs.

## Attacker perspective
Attackers clear logs (`wevtutil cl`), use living-off-the-land binaries, and obfuscate PowerShell to blend in. Ranked Sigma detections and script-block logging (4104) surface these despite evasion.

## Answer key
Hayabusa ranks detections by severity using Sigma rules; the highest hit corresponds to the injected suspicious activity (e.g. T1059.001 PowerShell). Chainsaw's Sigma hunt confirms the same event via a different engine.

## MITRE ATT&CK & DFIR phase
- **T1059.001** — PowerShell — script-block logging (Event ID 4104) surfaces malicious PowerShell
- **T1543.003** — Windows Service — service install (Event ID 7045) is a common persistence signal
- **T1070.001** — Clear Windows Event Logs — gaps/clears are themselves a detection

## Sources
- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Sigma project: https://sigmahq.io/

## Related modules
- - 06-windows-artifact-libs — parse raw .evtx with libevtx
- - 49-intrusion-timeline-case — build the incident timeline
