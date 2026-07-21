# 15 * Behavioral / dynamic analysis -- LAB-WINDOWS

## Overview (plain language)
When you want to understand what a suspicious program actually *does*, you can watch it run instead of just reading its code. These Windows tools do exactly that. Procmon records every file, registry, and process action a program makes. Process Explorer shows a live, detailed view of running processes like a super Task Manager. Autoruns lists everything set to start automatically when Windows boots or a user logs on. Regshot takes a "before and after" snapshot of the system so you can see what a program changed. FakeNet-NG pretends to be the whole internet so malware talks to it instead of the real network, letting you see who it tries to contact — all safely inside the lab. Together they turn an unknown file into a readable story of its behavior.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Procmon | Included in FLARE-VM (Sysinternals) | Real-time capture of file system, registry, process, thread, and network activity |
| Procexp | Included in FLARE-VM (Sysinternals) | Live process explorer showing handles, DLLs, and process tree |
| Autoruns | Included in FLARE-VM (Sysinternals) | Enumerates auto-start extensibility points (ASEPs) for persistence hunting |
| Regshot | Included in FLARE-VM (Regshot) | Diffs registry/filesystem snapshots taken before and after execution |
| FakeNet-NG | Included in FLARE-VM (FakeNet-NG) | Simulated internet that intercepts and logs malware network traffic |

Notes on tool behavior (authoritative):
- Procmon monitors file system, Registry, process/thread, and (since v3) network activity in real time, combining the older Filemon and Regmon into one tool. Source: Microsoft Learn — Process Monitor.
- Process Explorer's lower pane can display open handles or loaded DLLs for the selected process, and it color-codes processes (e.g., purple = packed/compressed images per its heuristic). Source: Microsoft Learn — Process Explorer.
- Autoruns "shows what programs are configured to run during system bootup or login" across the most comprehensive set of ASEPs of any startup monitor. Source: Microsoft Learn — Autoruns.
- FakeNet-NG intercepts and redirects all or specific network traffic while simulating legitimate services, and logs the traffic. Source: Mandiant/FLARE flare-fakenet-ng GitHub.

## Learning objectives
- Configure and run Procmon with filters to isolate a target process's file and registry activity.
- Use Process Explorer and Autoruns to identify injected DLLs and persistence entries created by a sample.
- Capture a before/after Regshot diff and enumerate registry keys and files the sample created or modified.
- Redirect and log a sample's network callbacks with FakeNet-NG without any live-network egress.

## Environment check
```powershell
# Confirm each behavioral tool is present on FLARE-VM.
# Sysinternals ship as versioned EXEs; -accepteula avoids the first-run dialog.
Get-Command procmon64.exe, procexp64.exe, autoruns64.exe | Format-Table Name, Source
Test-Path 'C:\Tools\Regshot\Regshot-x64-Unicode.exe'
Test-Path 'C:\Tools\fakenet\fakenet.exe'
```
Expected output: a table listing `procmon64.exe`, `procexp64.exe`, and `autoruns64.exe` with their install paths, followed by two `True` values confirming Regshot and FakeNet-NG are installed. Paths may vary slightly by FLARE-VM version; if `Get-Command` fails, launch the tools from the FLARE-VM Start Menu to confirm presence. FLARE-VM is a script-based install collection that bundles these RE/malware-analysis tools (Sysinternals, Regshot, FakeNet-NG). Source: Mandiant flare-vm GitHub.

## Guided walkthrough
1. Launch Procmon and set a process-name filter so you only capture the sample's activity.
```powershell
# Start Procmon minimized while accepting the EULA (run as Administrator).
# WHY: Procmon captures thousands of events/sec system-wide; a Process Name filter keeps
# only the sample's events so RegSetValue/CreateFile/Process Create noise is manageable.
Start-Process procmon64.exe -ArgumentList '/AcceptEula','/Minimized'
# In the GUI: Filter > Filter... > "Process Name" is "sample.exe" then Include.
# Expected: the event list shows only RegSetValue, CreateFile, and Process Create events for sample.exe.
# NUANCE: filters only hide events from the display; use File > Backing Files or the
# capture toggle (Ctrl+E) to control what is actually recorded. Procmon's command-line
# switches (/AcceptEula, /Minimized, /Quiet, /BackingFile) are documented in Microsoft Learn.
```

2. Inspect the live process tree and loaded modules with Process Explorer.
```powershell
# Launch Process Explorer as Administrator; enable the lower pane (View > Lower Pane View > DLLs).
# WHY: the DLL lower pane reveals modules a process loaded at runtime — foreign or
# unsigned DLLs in a benign-looking host are a classic injection tell (T1055).
Start-Process procexp64.exe -ArgumentList '/accepteula'
# Expected: a color-coded tree; select the sample process to list its loaded DLLs and open handles.
# NUANCE: enable Options > Verify Image Signatures and add the "Company Name"/"Verified Signer"
# columns to spot unsigned modules quickly; purple rows indicate images Process Explorer's
# heuristic flags as packed/compressed. Source: Microsoft Learn — Process Explorer.
```

3. Baseline auto-start entries before execution using Autoruns.
```powershell
# Autoruns can export the current ASEP baseline to compare after detonation.
# WHY: capturing a pre-detonation baseline lets you diff only the NEW autostart entries
# the sample creates, instead of scrolling hundreds of legitimate ASEPs.
Start-Process autoruns64.exe -ArgumentList '/accepteula'
# In the GUI: File > Save (.arn). Later use File > Compare to diff a post-run capture.
# Expected: rows across Logon, Services, Scheduled Tasks, and Image Hijacks tabs.
# NUANCE: enable Options > Hide Microsoft Entries and turn on VirusTotal/Verify checks to
# surface untrusted, non-OS entries. Autoruns covers more ASEPs than any other startup
# monitor. Source: Microsoft Learn — Autoruns.
```

4. Take a clean baseline snapshot with Regshot before running the sample.
```powershell
# Launch Regshot, click "1st shot" > "Shot", detonate the sample, then "2nd shot" > "Shot", then "Compare".
# WHY: Regshot's before/after diff captures the net state change (keys/values/files added,
# deleted, modified) even for actions that scrolled past in Procmon's live view.
Start-Process 'C:\Tools\Regshot\Regshot-x64-Unicode.exe'
# Expected: a comparison report listing "Keys added", "Values added", and "Files added".
# NUANCE: enable "Scan dir1" and point it at C:\ (or %TEMP% for speed) so filesystem
# changes are diffed too; Regshot only sees changes that persist between the two shots,
# so transient files created and deleted mid-run may not appear. Source: Regshot project.
```

5. Start FakeNet-NG so all network calls resolve to the local simulator, then detonate.
```powershell
# Run FakeNet-NG as Administrator; it intercepts/redirects traffic and simulates services, logging connection attempts. Ctrl+C stops it.
# WHY: FakeNet-NG answers DNS and stands up listeners (HTTP/HTTPS/etc.) so the sample
# "believes" it reached its C2, revealing domains, URIs, and ports with zero real egress.
Start-Process fakenet.exe -Verb RunAs
# Expected: console banner "FakeNet-NG" and Diverter lines showing the redirected process and destination port
# (e.g. "[Diverter] ... sample.exe ... 443") as the sample calls out.
# NUANCE: FakeNet-NG writes a PCAP of captured traffic to its working directory and can be
# tuned via its config INI (listeners, ports, process/redirect rules). Source: flare-fakenet-ng GitHub.
```

## Hands-on exercise
Detonate the benign sample in this module's `exercise/` directory and produce a full behavioral report.

- **Sample:** `exercise/benign_dropper.exe`
- **Type:** Windows PE32 executable (inert training stub).
- **Safe origin:** Compiled in-lab from a benign C stub that only writes one registry Run value, drops one file to `%TEMP%`, and issues a single DNS lookup for `beacon.test.lab`. It contains **no** malicious payload, no self-replication, and performs **no** real-network egress (all traffic is captured by FakeNet-NG). Detonate only on LAB-WINDOWS with networking isolated.
- **sha256:** `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

Tasks:
1. Run Regshot 1st shot, detonate under Procmon and FakeNet-NG, then Regshot 2nd shot + Compare.
2. Identify the registry Run key value the sample writes (persistence).
3. Identify the file the sample drops and its path.
4. Identify the DNS name the sample resolves via the FakeNet-NG log.
5. Confirm the persistence entry appears in Autoruns after detonation.

## SOC analyst perspective
Behavioral analysis gives a SOC the concrete IOCs and TTPs needed to write and validate detections.

- **Registry Run-key persistence detection (T1547.001).** Procmon and Regshot reveal the exact registry value a sample creates. On endpoints, the equivalent live telemetry is **Sysmon Event ID 13 (RegistryValueSet)** for Run-key writes and **Event ID 12/14** for key create/rename. Detection logic (in prose): alert when a Sysmon EID 13 record has a `TargetObject` ending in `\Software\Microsoft\Windows\CurrentVersion\Run\` (or the machine-wide `HKLM\...\Run` / `RunOnce` equivalents) AND the writing `Image` is not a known-good installer/updater. Enrichment: correlate the `Details` field of that EID 13 (the value data — here the path to the dropped file) against the process that dropped it. Microsoft's ATT&CK page T1547.001 enumerates the Run/RunOnce key locations; the Sysmon schema/Event IDs are documented on Microsoft Learn.
- **Scheduled Task persistence detection (T1053.005).** Where a sample persists via a task instead of a Run key, the endpoint signals are **Security Event ID 4698 (a scheduled task was created)** and the corresponding **Microsoft-Windows-TaskScheduler/Operational log Event ID 106 (task registered)**. Detection logic: alert on 4698/106 where the task's Actions command line points into `%TEMP%`, `%APPDATA%`, or `%PROGRAMDATA%`, or invokes a script host (`powershell.exe`, `wscript.exe`, `mshta.exe`). Source: Microsoft Learn (4698 event) and MITRE T1053.005.
- **C2 detection (T1071.001).** FakeNet-NG surfaces the C2 domain (`beacon.test.lab`) and any URIs/ports; feed these to Security Onion. Pivots: in **Zeek** `dns.log` filter on the `query` field equal to `beacon.test.lab` and correlate the answer/`uid` to `conn.log` (fields `id.orig_h`, `id.resp_h`, `id.resp_p`, `duration`, `orig_bytes`); for TLS callbacks pivot to `ssl.log` and inspect the `server_name` (SNI) field. A **Suricata** signature can key on the `dns.query` buffer/keyword for the domain, or on the `tls.sni` keyword for the SNI — hunt the domain across Security Onion's **Alerts, Hunt, Dashboards, and PCAP** views. Security Onion ships Suricata + Zeek + the Elastic stack for exactly this pivot. Source: securityonion.net docs, docs.zeek.org, docs.suricata.io.
- **Beaconing hunt (T1071.001).** Beyond the single IOC, hunt for periodicity: in Zeek `conn.log`, group by `id.resp_h`/`id.resp_p` and look for many short, regularly spaced connections with low, consistent `orig_bytes` — the signature of automated check-ins. This is a threat-hunting pivot that catches unknown C2 the FakeNet IOC list would miss.
- **Injection detection (T1055 / T1055.001).** Process Explorer exposes injected DLLs and RWX regions; the corresponding endpoint signals are **Sysmon Event ID 8 (CreateRemoteThread)** and **Event ID 10 (ProcessAccess)** with suspicious `GrantedAccess` masks (e.g., `0x1F0FFF`/`0x1FFFFF` full access, or the `0x1438`/`0x143A` combinations seen with remote memory write). For DLL injection specifically (T1055.001), correlate a **Sysmon Event ID 7 (Image/Module Loaded)** where a module in `%TEMP%`/`%APPDATA%` loads into an unrelated host process and `Signed` is `false`. Pivot from any of these to the parent/child chain (Sysmon EID 1) to scope containment.
- **Execution / dropper telemetry (T1204.002).** The user-initiated run of `benign_dropper.exe` maps to User Execution: Malicious File; the corresponding signal is **Sysmon Event ID 1 (ProcessCreate)** with `ParentImage` being a browser, mail client, or `explorer.exe`. Threat-hunting pivot: join EID 1 to the subsequent EID 11 (FileCreate) for the `%TEMP%` drop and EID 13 for the Run-key write to reconstruct the full dropper chain from one process GUID.

Concrete IDs to detect on: **T1547.001**, **T1053.005**, **T1055**, **T1055.001**, **T1071.001**, **T1204.002**.

## Attacker perspective
Attackers rely on many of these same behaviors, and defenders exploit the artifacts they leave.

- **Registry Run-key persistence (T1547.001).** Writing `HKCU\...\CurrentVersion\Run\<name>` executes the payload at user logon. Artifacts: the Run value itself (visible in Autoruns/Regshot), a **Sysmon EID 13** record, and NTUSER.DAT hive changes (the value survives in the user hive on disk). Evasion: attackers name the value to mimic a legitimate updater (e.g., `UpdateSvc`) and point it at a signed LOLBIN so the run-key value alone looks benign. MITRE lists Run/RunOnce keys under T1547.001.
- **Scheduled Task persistence (T1053.005).** Tasks leave XML in `C:\Windows\System32\Tasks\`, registry entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` (and `\Tasks`), and **Security 4698** / **TaskScheduler/Operational 106** events — all enumerated by the Autoruns Scheduled Tasks tab. Evasion: hiding the task by deleting its `SD` (security descriptor) value under the TaskCache so it disappears from `schtasks`/Task Scheduler GUI while still firing — the TaskCache registry artifact is the forensic tell.
- **Staging (T1074 / dropped files).** Stagers commonly land in `%TEMP%` or `%APPDATA%` with predictable creation timestamps captured by Procmon `CreateFile`/`WriteFile` and by Regshot "Files added." Timestomping (T1070.006) may be used to blend in, but the MFT `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp discrepancy remains a tell, as does a `$STANDARD_INFORMATION` created time that predates the parent directory.
- **Process injection (T1055 / T1055.001).** Foreign DLLs and RWX memory regions appear in Process Explorer's DLL/handle view and via Sysmon EID 7/8/10. Evasion: allocating memory as RW then flipping to RX (avoiding a permanent RWX region), or module stomping over an already-loaded legitimate DLL to avoid a new EID 7 load event — Process Explorer's per-thread start-address view and unbacked-memory indicators still expose the anomaly.
- **User Execution (T1204.002).** The initial dropper relies on a user double-clicking the file; the attacker's evasion is social (icon/name spoofing, double extensions), while the defensive artifact is the Sysmon EID 1 parent→child lineage.
- **Anti-analysis (T1497 / T1518.001 / T1057).** Malware enumerates running processes and drivers looking for `procmon`, `procexp`, `Wireshark`, or FakeNet's redirected interface (Process Discovery, T1057) and may halt or change behavior — but the enumeration itself (process/handle queries visible in the Procmon trace, and `CreateToolhelp32Snapshot`/`Process32Next` API use) is a detectable artifact. FakeNet-specific evasion includes checking whether a hardcoded "fake" domain resolves (a sandbox that answers everything). MITRE documents Virtualization/Sandbox Evasion (T1497), Security Software Discovery (T1518.001), and Process Discovery (T1057).

## Answer key
- **Registry persistence:** Regshot Compare / Procmon `RegSetValue` shows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateSvc` = path to the dropped file.
- **Dropped file:** `%TEMP%\svc_update.dat` appears in Regshot "Files added" and Procmon `CreateFile` with `WriteFile`.
- **Network callback:** FakeNet-NG log records a DNS query for `beacon.test.lab` followed by an HTTPS/443 connection attempt.
- **Autoruns confirmation:** the `UpdateSvc` value appears under the Logon tab after re-scanning post-detonation.

Verification commands:
```powershell
# Confirm the sample hash before running.
Get-FileHash .\exercise\benign_dropper.exe -Algorithm SHA256 | Format-List
# Expected Hash: 9F2C4B1A7D63E58C0A4F1B9D2E6C8A37F5B0D1E4C9A72B8360D5E1F47A3C92B6

# After detonation, verify the persistence value directly.
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'UpdateSvc'
# Expected: an UpdateSvc property whose value points to %TEMP%\svc_update.dat
```
Sample sha256: `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

## MITRE ATT&CK & DFIR phase
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (Regshot/Autoruns/Procmon; Sysmon EID 13). https://attack.mitre.org/techniques/T1547/001/
- **T1053.005** — Scheduled Task/Job: Scheduled Task (Autoruns Scheduled Tasks tab; Security 4698, TaskScheduler/Operational 106). https://attack.mitre.org/techniques/T1053/005/
- **T1055** — Process Injection (Process Explorer DLL/handle view; Sysmon EID 8/10). https://attack.mitre.org/techniques/T1055/
- **T1055.001** — Process Injection: Dynamic-link Library Injection (foreign DLL loaded into a host process; Sysmon EID 7). https://attack.mitre.org/techniques/T1055/001/
- **T1071.001** — Application Layer Protocol: Web Protocols (FakeNet-NG capture; Zeek/Suricata pivots). https://attack.mitre.org/techniques/T1071/001/
- **T1074** — Data Staged (dropped stager in `%TEMP%`). https://attack.mitre.org/techniques/T1074/
- **T1070.006** — Indicator Removal: Timestomp (staging evasion). https://attack.mitre.org/techniques/T1070/006/
- **T1204.002** — User Execution: Malicious File (user-run dropper; Sysmon EID 1 lineage). https://attack.mitre.org/techniques/T1204/002/
- **T1057** — Process Discovery (anti-analysis process enumeration visible in Procmon). https://attack.mitre.org/techniques/T1057/
- **T1497** — Virtualization/Sandbox Evasion, and **T1518.001** — Software Discovery: Security Software Discovery (anti-analysis checks visible in Procmon). https://attack.mitre.org/techniques/T1497/ · https://attack.mitre.org/techniques/T1518/001/
- **DFIR phase:** Examination / Analysis (dynamic behavioral triage), feeding Identification and Containment.


### Essential Commands & Features

To maximize **Process Monitor (Procmon)** for behavioral dynamic analysis, master these undemonstrated but critical features:

1. **Drop Filtered Events**
   *When to use*: Reduce memory usage during long captures by discarding filtered events in real-time.
   *Example*:
   ```plaintext
   Procmon → Filter → Drop Filtered Events (check box)
   ```
   *Use case*: Monitoring persistent malware (e.g., **T1543.003: Create or Modify System Process: Windows Service**) without bloating logs.

2. **Load/Save Filters**
   *When to use*: Reuse or share preconfigured filters (e.g., for **T1036.005: Masquerading: Match Legitimate Name or Location**).
   *Example*:
   ```plaintext
   Procmon → Filter → Load Filter (select .pmf file)
   ```

3. **Stack Traces**
   *When to use*: Trace the call stack of suspicious API calls (e.g., **T1055.012: Process Injection: Process Hollowing**).
   *Example*:
   ```plaintext
   Right-click event → Stack (view module/thread context)
   ```

4. **Network Summary**
   *When to use*: Correlate process activity with network connections (e.g., **T1095: Non-Application Layer Protocol**).
   *Example*:
   ```plaintext
   Procmon → Tools → Network Summary (view process-to-port mappings)
   ```

**Sources**:
- [Sysinternals Procmon Documentation (Microsoft Docs)](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
- [SANS DFIR: Advanced Procmon Techniques](https://www.sans.org/blog/advanced-process-monitor-filters/)

### Threat Hunting & Detection Engineering
To enhance threat hunting and detection engineering capabilities, focus on identifying patterns of behavior that align with specific MITRE ATT&CK techniques. For instance, **T1588: Obtain Capabilities** and **T1595: Active Scanning** can be detected by analyzing network logs for unusual scan activity or by monitoring system calls for suspicious capability acquisitions. In Windows environments, monitor Event ID 4688 for command-line arguments that may indicate capability acquisition attempts. Additionally, inspect Zeek logs for unusual scan patterns, such as multiple connections to different ports within a short timeframe. Threat hunters can pivot on these findings by investigating related processes, network connections, or user accounts. By integrating these detection logic elements into a comprehensive threat hunting strategy, security teams can improve their ability to detect and respond to advanced threats. For more information on threat hunting and detection engineering, visit the Cyber and Infrastructure Security Agency (CISA) website at [https://www.cisa.gov/](https://www.cisa.gov/) or the National Institute of Standards and Technology (NIST) Computer Security Resource Center at [https://csrc.nist.gov/](https://csrc.nist.gov/).


### Essential Commands & Features

To deepen behavioral dynamic analysis with **Process Monitor (Procmon)**, leverage these undemonstrated but critical features for efficient threat hunting and forensic investigation:

1. **Drop Filtered Events**
   *When to use*: Reduce memory usage during long captures by discarding filtered events in real-time (e.g., excluding noise like `svchost.exe`).
   *Example*:
   ```plaintext
   Filter → Drop Filtered Events (Ctrl+X)
   ```
   *Use case*: Detect **T1027.002 Obfuscated Files or Information: Software Packing** by focusing on anomalous process starts without storage overhead.

2. **Load/Save Filters**
   *When to use*: Reuse or share complex filters (e.g., for **T1562.001 Impair Defenses: Disable or Modify Tools**).
   *Example*:
   ```plaintext
   Filter → Load Filter (Ctrl+L) → Select "DisableDefender.pmf"
   ```
   *Pre-built filters*: Download from [Sysinternals forums](https://forum.sysinternals.com/procmon-filters_topic10353.html).

3. **Stack Traces**
   *When to use*: Trace the call stack of suspicious events (e.g., DLL injection via **T1055.002 Process Injection: Portable Executable Injection**).
   *Example*:
   ```plaintext
   Right-click event → Stack (Ctrl+K)
   ```
   *Tip*: Enable symbol servers (Options → Configure Symbols) for accurate function names.

4. **Bookmarks**
   *When to use*: Flag critical events (e.g., registry modifications tied to **T1112 Modify Registry**) for later review.
   *Example*:
   ```plaintext
   Right-click event → Bookmark (Ctrl+B) → Add note: "Persistence via Run key"
   ```
   *Export*: Save bookmarks via File → Save → "Include bookmarks only".

**Authoritative Sources**:
- [Procmon Advanced Features (Windows Sysinternals)](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon#advanced-features)
- [SANS DFIR Procmon Cheat Sheet](https://www.sans.org/blog/process-monitor-cheat-sheet/)

### Adversary Emulation & Red-Team Perspective

From a red-team perspective, **behavioral dynamic analysis evasion** is a critical tactic to bypass automated sandboxing and endpoint detection. Attackers abuse this by crafting malware that detects analysis environments (e.g., virtual machines, debuggers, or sandbox-specific artifacts) before executing malicious payloads. A common technique is **T1497.001: System Checks**, where malware queries system properties (e.g., CPU cores, memory, or registry keys like `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`) to identify sandboxed or low-resource environments. If analysis conditions are detected, the malware may delay execution, exit silently, or trigger decoy behaviors (e.g., benign file operations) to mislead defenders.

Another evasion method is **T1622: Debugger Evasion**, where adversaries use anti-debugging tricks (e.g., checking for `IsDebuggerPresent()` or timing discrepancies) to thwart dynamic analysis. Artifacts left behind include:
- **Process hollowing** (e.g., `svchost.exe` spawned with anomalous memory regions).
- **Delayed execution** (e.g., scheduled tasks via `schtasks.exe` or registry `Run` keys).
- **Suspicious API calls** (e.g., `NtQueryInformationProcess` for debugger checks).

To evade detection, attackers may:
- **Obfuscate strings** (e.g., XOR-encoded API calls).
- **Use sleep loops** to outlast sandbox timeouts.
- **Leverage legitimate processes** (e.g., `mshta.exe` or `rundll32.exe`) for execution.

**Sources:**
- [FireEye: Anti-Sandbox Techniques](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)
- [CrowdStrike: Adversary Tradecraft](https://www.crowdstrike.com/blog/adversary-tradecraft-how-attackers-are-evading-detection/)

## Sources
Tool behavior, flags, and expected output:
- Microsoft Learn — Process Monitor (real-time file/Registry/process/network monitoring; command-line switches incl. /AcceptEula, /Minimized, /Quiet, /BackingFile): https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- Microsoft Learn — Process Explorer (DLL/handle lower pane, image-signature verification, packed-image color coding): https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- Microsoft Learn — Autoruns (broadest ASEP coverage; Compare, Hide Microsoft Entries, VirusTotal): https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Microsoft Learn — Sysmon (Event IDs 1/7/8/10/11/12/13/14 used in detection logic): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Learn — Security Event 4698 (a scheduled task was created): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
- Mandiant/FLARE — FakeNet-NG (traffic interception/redirection, service simulation, PCAP + logging, config): https://github.com/mandiant/flare-fakenet-ng
- Mandiant — FLARE-VM (tool bundle/installer): https://github.com/mandiant/flare-vm
- Regshot project (registry/filesystem before-after diff, Scan dir): https://sourceforge.net/projects/regshot/

Detection, hunting, and platform pivots:
- Security Onion documentation (Suricata + Zeek + Elastic; Alerts/Hunt/Dashboards/PCAP): https://docs.securityonion.net/
- Zeek documentation (dns.log `query`, conn.log `id.resp_h`/`id.resp_p`/`orig_bytes`, ssl.log `server_name`): https://docs.zeek.org/
- Suricata documentation (rule keywords incl. `dns.query`, `tls.sni`): https://docs.suricata.io/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

MITRE ATT&CK technique pages:
- T1547.001: https://attack.mitre.org/techniques/T1547/001/
- T1053.005: https://attack.mitre.org/techniques/T1053/005/
- T1055: https://attack.mitre.org/techniques/T1055/
- T1055.001: https://attack.mitre.org/techniques/T1055/001/
- T1071.001: https://attack.mitre.org/techniques/T1071/001/
- T1074: https://attack.mitre.org/techniques/T1074/
- T1070.006: https://attack.mitre.org/techniques/T1070/006/
- T1204.002: https://attack.mitre.org/techniques/T1204/002/
- T1057: https://attack.mitre.org/techniques/T1057/
- T1497: https://attack.mitre.org/techniques/T1497/
- T1518.001: https://attack.mitre.org/techniques/T1518/001/

## Related modules
- [Scenario: document detonation with network sim](../55-doc-detonation-case/README.md) -- shares fakenet-ng for network-callback capture during detonation.
- [Static reverse engineering](../12-static-re/README.md) -- same learning path (Windows RE); static triage before dynamic runs.
- [Dynamic debugging](../13-dynamic-debugging/README.md) -- same learning path (Windows RE); step through the behaviors observed here.
- [.NET reverse engineering](../14-dotnet-re/README.md) -- same learning path (Windows RE); managed-code counterpart to this module.

<!-- cyberlab-enriched: v2 -->
- https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
- https://www.sans.org/blog/advanced-process-monitor-filters/
- https://www.cisa.gov/](https://www.cisa.gov/
- https://csrc.nist.gov/](https://csrc.nist.gov/

<!-- cyberlab-enriched: v3 -->
- https://forum.sysinternals.com/procmon-filters_topic10353.html
- https://docs.microsoft.com/en-us/sysinternals/downloads/procmon#advanced-features
- https://www.sans.org/blog/process-monitor-cheat-sheet/
- https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html
- https://www.crowdstrike.com/blog/adversary-tradecraft-how-attackers-are-evading-detection/

<!-- cyberlab-enriched: v4 -->
