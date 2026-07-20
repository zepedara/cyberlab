# 15 * Behavioral / dynamic analysis -- LAB-WINDOWS

## Overview (plain language)
When you want to understand what a suspicious program actually *does*, you can watch it run instead of just reading its code. These Windows tools do exactly that. Procmon records every file, registry, and process action a program makes. Process Explorer shows a live, detailed view of running processes like a super Task Manager. Autoruns lists everything set to start automatically when Windows boots or a user logs on. Regshot takes a "before and after" snapshot of the system so you can see what a program changed. FakeNet-NG pretends to be the whole internet so malware talks to it instead of the real network, letting you see who it tries to contact — all safely inside the lab. Together they turn an unknown file into a readable story of its behavior.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Procmon | Included in FLARE-VM (Sysinternals) | Real-time capture of file system, registry, process, and thread activity |
| Procexp | Included in FLARE-VM (Sysinternals) | Live process explorer showing handles, DLLs, and process tree |
| Autoruns | Included in FLARE-VM (Sysinternals) | Enumerates auto-start extensibility points (ASEPs) for persistence hunting |
| Regshot | Included in FLARE-VM (Regshot) | Diffs registry/filesystem snapshots taken before and after execution |
| FakeNet-NG | Included in FLARE-VM (FakeNet-NG) | Simulated internet that intercepts and logs malware network traffic |

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
Expected output: a table listing `procmon64.exe`, `procexp64.exe`, and `autoruns64.exe` with their install paths, followed by two `True` values confirming Regshot and FakeNet-NG are installed. Paths may vary slightly by FLARE-VM version; if `Get-Command` fails, launch the tools from the FLARE-VM Start Menu to confirm presence.

## Guided walkthrough
1. Launch Procmon and set a process-name filter so you only capture the sample's activity.
```powershell
# Start Procmon minimized while accepting the EULA (run as Administrator).
Start-Process procmon64.exe -ArgumentList '/AcceptEula','/Minimized'
# In the GUI: Filter > Filter... > "Process Name" is "sample.exe" then Include.
# Expected: the event list shows only RegSetValue, CreateFile, and Process Create events for sample.exe.
```

2. Inspect the live process tree and loaded modules with Process Explorer.
```powershell
# Launch Process Explorer as Administrator; enable the lower pane (View > Lower Pane View > DLLs).
Start-Process procexp64.exe -ArgumentList '/accepteula'
# Expected: a color-coded tree; select the sample process to list its loaded DLLs and open handles.
```

3. Baseline auto-start entries before execution using Autoruns.
```powershell
# Autoruns can export the current ASEP baseline to compare after detonation.
Start-Process autoruns64.exe -ArgumentList '/accepteula'
# In the GUI: File > Save (.arn). Later use File > Compare to diff a post-run capture.
# Expected: rows across Logon, Services, Scheduled Tasks, and Image Hijacks tabs.
```

4. Take a clean baseline snapshot with Regshot before running the sample.
```powershell
# Launch Regshot, click "1st shot" > "Shot", detonate the sample, then "2nd shot" > "Shot", then "Compare".
Start-Process 'C:\Tools\Regshot\Regshot-x64-Unicode.exe'
# Expected: a comparison report listing "Keys added", "Values added", and "Files added".
```

5. Start FakeNet-NG so all network calls resolve to the local simulator, then detonate.
```powershell
# Run FakeNet-NG as Administrator; it hijacks DNS/HTTP and logs connection attempts. Ctrl+C stops it.
Start-Process fakenet.exe -Verb RunAs
# Expected: console banner "FakeNet-NG" and lines like "[Diverter] ... sample.exe ... 443" as the sample calls out.
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
Behavioral analysis gives a SOC the concrete IOCs and TTPs needed to write and validate detections. Procmon and Regshot reveal the exact registry Run key or scheduled task a sample creates, which maps to ATT&CK T1547.001 (Registry Run Keys) and T1053.005 (Scheduled Task) — an analyst turns those into Sigma rules feeding Security Onion. FakeNet-NG surfaces C2 domains and URIs (T1071.001) that become Suricata/Zeek signatures and threat-intel indicators searched in Security Onion's Hunt and PCAP views. Process Explorer exposes injected DLLs and hollowed processes (T1055) so responders can pivot from a Sysmon alert to the parent/child chain during containment and scoping.

## Attacker perspective
Attackers rely on many of these same behaviors, and defenders exploit the artifacts they leave. Persistence via Run keys (T1547.001) and services writes durable registry values that Autoruns and Regshot expose; dropped stagers land in `%TEMP%` or `%APPDATA%` with predictable timestamps captured by Procmon. Process injection (T1055) leaves foreign DLLs and RWX memory regions visible in Process Explorer. Sophisticated malware also probes for these very analysis tools, checking for `procmon`, `procexp`, or FakeNet's hijacked interface (T1518.001 / T1497 sandbox evasion) and altering behavior — but that anti-analysis check itself is a detectable artifact in the Procmon trace.

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
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys (Regshot/Autoruns/Procmon).
- **T1053.005** — Scheduled Task/Job (Autoruns Scheduled Tasks tab).
- **T1055** — Process Injection (Process Explorer DLL/handle view).
- **T1071.001** — Application Layer Protocol: Web (FakeNet-NG capture).
- **T1497 / T1518.001** — Virtualization/Sandbox Evasion & Security Software Discovery (anti-analysis checks visible in Procmon).
- **DFIR phase:** Examination / Analysis (dynamic behavioral triage), feeding Identification and Containment.

## Sources
- Microsoft Sysinternals — Process Monitor: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- Microsoft Sysinternals — Process Explorer: https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- Microsoft Sysinternals — Autoruns: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Mandiant/FLARE — FakeNet-NG: https://github.com/mandiant/flare-fakenet-ng
- Mandiant — FLARE-VM: https://github.com/mandiant/flare-vm
- Regshot project: https://sourceforge.net/projects/regshot/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK — T1547.001: https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK — T1055: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK — T1071/001: https://attack.mitre.org/techniques/T1071/001/