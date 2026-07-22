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
1. Generate a ranked detection timeline: `hayabusa csv-timeline -d ./evtx -o timeline.csv`. The `-d` flag specifies the directory containing `.evtx` files, and `-o` sets the output file. This command parses all logs, matches events against its built-in Sigma rules, and outputs a timeline of detections ranked by severity (Critical, High, Medium, Low, Informational) [Hayabusa Docs].
2. Triage the highest-severity hits first (critical/high) and note their Event IDs + timestamps. For example, a Critical alert for "Suspicious PowerShell Execution" will list the Event ID (like 4104), the timestamp, and the affected host. This prioritization is central to the tool's design [Hayabusa Docs].
3. Hunt with Chainsaw + Sigma: `chainsaw hunt ./evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml`. The `-s` flag points to a directory of Sigma rules (you can clone the official SigmaHQ repository), and the `--mapping` flag specifies the YAML file that maps Sigma rule log sources to Windows Event Log channels. This allows Chainsaw to apply a broad rule set [Chainsaw Docs].
4. Pivot on a lead — e.g., a 7045 service install or 4104 script block — and pull surrounding events. Use `EvtxECmd` to dump all events from the specific log file: `EvtxECmd -f Security.evtx --csv .` to get a CSV you can filter by timestamp and Event ID. This contextualizes the detection within the sequence of events on the host [Eric Zimmerman's Tools].
5. Export normalized events with `EvtxECmd.exe -d ./evtx --csv . --csvf events.csv` for timeline correlation. This creates a single, consolidated CSV file from all `.evtx` files in the directory, which can be imported into timeline analysis tools like Timesketch or for manual review in a spreadsheet.

## Hands-on exercise
Run Hayabusa against the sample `./evtx` set, identify the highest-severity detection, and report its Event ID, technique, and timestamp. Confirm the same activity with a Chainsaw Sigma hunt.

## SOC analyst perspective
This is the daily bread of log-based detection: analysts run Sigma-driven sweeps over collected event logs to find lateral movement, persistence, and execution, then build a timeline from the ranked hits instead of reading raw logs. Detection engineering focuses on mapping specific event patterns to MITRE ATT&CK techniques. For example:
- **Detection of T1059.001 (PowerShell)**: A Sigma rule may trigger on Windows Event ID 4104 (Script Block Logging) where the `ScriptBlockText` field contains high-risk keywords like `-EncodedCommand` or `IEX` [Sigma Rule: Suspicious PowerShell Keywords].
- **Detection of T1543.003 (Windows Service)**: Event ID 7045 (A service was installed in the system) is a strong persistence indicator. Detection logic involves correlating 7045 events with process creation events (4688) where the parent process is unusual (e.g., `powershell.exe` or a user-writable directory) [MITRE ATT&CK T1543.003].
- **Detection of T1070.001 (Log Clearance)**: Event ID 1102 (The audit log was cleared) from the Security log is a direct artifact. In Security Onion, a Suricata alert can be generated for network traffic to the host coinciding with the log clear time, while Zeek's `weird.log` might note anomalous gaps in log-forwarding connections.
- **Pivoting in Security Onion**: After identifying a suspicious IP from an event log (e.g., a failed logon source in Event ID 4625), an analyst can pivot in Elastic to view all Suricata alerts (`event.module:suricata`) and Zeek connection logs (`zeek.conn.id.orig_h:<IP>`) from that IP to assess network impact.

## Attacker perspective
Attackers clear logs (`wevtutil cl`), use living-off-the-land binaries, and obfuscate PowerShell to blend in. Ranked Sigma detections and script-block logging (4104) surface these despite evasion. Concrete TTPs and artifacts include:
- **T1070.001 (Indicator Removal on Host)**: Using `wevtutil cl security` clears the Security log, generating Event ID 1102 as a tell-tale artifact. Attackers may also disable logging via `auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable`, which can be detected by changes to Registry key `HKLM\SECURITY\Policy\PolAdtEv` [MITRE ATT&CK T1070.001].
- **T1059.001 (Command and Scripting Interpreter: PowerShell)**: To evade script block logging, attackers may use reflection-based invocation, `-WindowStyle Hidden`, or execution via `regsvr32` (T1218.010). However, Event ID 4103 (PowerShell Command Activity) may still capture command lines, and Sysmon Event ID 1 (Process creation) will record the parent-child relationship [MITRE ATT&CK T1059.001].
- **T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)**: Persistence via `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` leaves a trace in the Registry hive and can generate Event ID 4688 (process creation) for the persisted binary at user logon (Event ID 4624). Sigma rules detect modifications to these autostart locations [MITRE ATT&CK T1547.001].
- **T1562.001 (Impair Defenses: Disable or Modify Tools)**: Attackers may stop security services using `net stop "Windows Defender"` or `sc config WinDefend start= disabled`. This action can be logged in System event logs (Event ID 7034, 7036) and as a process creation event for `net.exe` or `sc.exe` [MITRE ATT&CK T1562.001].

## Answer key
Hayabusa ranks detections by severity using Sigma rules; the highest hit corresponds to the injected suspicious activity (e.g., T1059.001 PowerShell). Chainsaw's Sigma hunt confirms the same event via a different engine.

## MITRE ATT&CK & DFIR phase
- **T1059.001** — PowerShell — script-block logging (Event ID 4104) surfaces malicious PowerShell [MITRE ATT&CK T1059.001]
- **T1543.003** — Windows Service — service install (Event ID 7045) is a common persistence signal [MITRE ATT&CK T1543.003]
- **T1070.001** — Clear Windows Event Logs — gaps/clears are themselves a detection [MITRE ATT&CK T1070.001]
- **T1547.001** — Registry Run Keys / Startup Folder — persistence via run keys detectable in registry and logon events [MITRE ATT&CK T1547.001]
- **T1562.001** — Impair Defenses: Disable or Modify Tools — stopping security services leaves event log traces [MITRE ATT&CK T1562.001]

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- PowerShell as a Service in Registry** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_powershell_as_service.yml; license: Detection Rule License / DRL):

```yaml
title: PowerShell as a Service in Registry
id: 4a5f5a5e-ac01-474b-9b4e-d61298c9df1d
status: test
description: Detects that a powershell code is written to the registry as a service.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020-10-06
modified: 2023-08-17
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Services\'
        TargetObject|endswith: '\ImagePath'
        Details|contains:
            - 'powershell'
            - 'pwsh'
    condition: selection
falsepositives:
    - Unknown
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_xor_hunting.yar, author: Florian Roth):

```yara
rule SUSP_XORed_Mozilla_Oct19 {
   meta:
      old_rule_name = "SUSP_XORed_Mozilla"
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth"
      reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
      date = "2019-10-28"
      modified = "2023-11-03"
      score = 60
      id = "71e5b399-c384-5330-ae52-4e0a806e7969"
   strings:
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xof1 = "Mozilla/5.0" ascii wide

      $fpa1 = "Sentinel Labs" wide
      $fpa2 = "<filter object at" ascii /* Norton Security */

      $fpb1 = { 64 65 78 0a 30 33 35 } /* dex.035 */
   condition:
      $xo1 
      and not $xof1 
      and not 1 of ($fpa*)
      and not $fpb1 at 0
}
```

**Real-world context (MITRE T1059.001 -- Command and Scripting Interpreter: PowerShell):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1059/001/ -- real in-the-wild use includes Sandworm, Akira.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `58_eventlog_hunting_benign_sample.txt` |
| sample sha256 | `6171324390a6c83f5273e7be538336ba454da3e0ebade67a48a23991392e0c35` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 58-eventlog-hunting -- for detection-rule testing only
' |
### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1059/001/
- **Threat actors documented using it:** Sandworm, Akira (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
- Hayabusa: https://github.com/Yamato-Security/hayabusa (Official documentation and rule set)
- Chainsaw: https://github.com/WithSecureLabs/chainsaw (Official documentation and mappings)
- Sigma project: https://sigmahq.io/ (Sigma specification and rule repository)
- Eric Zimmerman's Tools: https://ericzimmerman.github.io/ (EvtxECmd documentation and usage)
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/ (Technique details and procedure examples)
- MITRE ATT&CK T1543.003: https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK T1070.001: https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK T1547.001: https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1562.001: https://attack.mitre.org/techniques/T1562/001/
- Sigma Rule: Suspicious PowerShell Keywords (Example): https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_suspicious_keywords.yml

## Related modules
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- same learning path (Scenarios)
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- same learning path (Scenarios)
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- same learning path (Scenarios)
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- same learning path (Scenarios)

<!-- cyberlab-enriched: v6 -->
