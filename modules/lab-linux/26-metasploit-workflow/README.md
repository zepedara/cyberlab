# 26 * Metasploit Framework workflow (training range) -- LAB-LINUX

## Overview (plain language)
Metasploit is a large toolbox that security testers use to safely simulate how a real attacker breaks into a computer. It bundles thousands of ready-made "exploits" (ways to abuse a flaw), "payloads" (the code that runs after a break-in), and helper scanners. Nmap is a network mapper: it looks at a target machine and reports which doors (ports) are open and what programs answer behind them. Used together in a training range, you first use Nmap to see what a target is running, then use Metasploit to test a matching, deliberately vulnerable service. This module keeps everything inside an isolated lab so nothing real gets attacked, and it teaches you what the attack looks like from both the attacker's console and the defender's logs.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| metasploit-framework | apt install metasploit-framework | Exploitation framework: scan, exploit, and post-exploitation modules for red-team simulation |
| nmap | apt install nmap | Network/port scanner and service/version discovery to enumerate a target before exploitation |

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

## Guided walkthrough
1. `nmap` — scan a single lab target for open ports and service versions. Use a lab-range address; here `203.0.113.10` stands in for your isolated training target.
```bash
TARGET=203.0.113.10
nmap -sV -Pn -p 1-1000 -oN scan.txt "$TARGET"
```
Expected observable output: a table of `PORT STATE SERVICE VERSION` lines (e.g. `80/tcp open http Apache httpd`), plus a saved `scan.txt` you can grep later.

2. `nmap` — export XML so Metasploit can import the results into its database.
```bash
TARGET=203.0.113.10
nmap -sV -Pn -oX scan.xml "$TARGET"
```
Expected: a well-formed `scan.xml` file; no console table by default because output was redirected to XML.

3. `msfconsole` — start the framework and import the Nmap results (non-interactive with `-x`).
```bash
msfconsole -q -x "db_import scan.xml; hosts; services; exit"
```
Expected: Metasploit reports `Importing 'Nmap XML' data`, then prints `Hosts` and `Services` tables reflecting the scan you imported.

4. `msfconsole` — search for and inspect an auxiliary scanner module (read-only, safe to view).
```bash
msfconsole -q -x "search type:auxiliary name:http_version; info auxiliary/scanner/http/http_version; exit"
```
Expected: a search results table listing modules, followed by the `info` description, options, and references for `auxiliary/scanner/http/http_version`.

5. `msfconsole` — run an auxiliary HTTP scanner against the lab target only.
```bash
msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS 203.0.113.10; set RPORT 80; run; exit"
```
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

## SOC analyst perspective
A defender rarely sees Metasploit directly; they see its footprint. In Security Onion, an Nmap `-sV` sweep and Metasploit auxiliary scanners generate bursts of connection attempts and short-lived TCP sessions across many ports from one source IP, which Zeek `conn.log` records as high fan-out with many `S0`/`REJ` states, and which Suricata often flags with scan/recon signatures. Analysts pivot on the source IP in the Security Onion Hunt/Kibana views, correlate with server access logs, and map the activity to MITRE ATT&CK **T1046 Network Service Discovery** and **T1595 Active Scanning**. Successful exploitation with a Meterpreter payload then produces unusual outbound C2 sessions and process anomalies on the host, tying into detection and the identification/containment phases of incident response.

## Attacker perspective
An attacker uses Nmap to fingerprint a target's exposed services, then selects a matching Metasploit module to gain access or extract information. The framework speeds up exploitation by handling payload delivery, staging, and post-exploitation, and can obfuscate or encode payloads to slip past simple filters. But this activity is noisy: scans leave rejected-connection floods in firewall and Zeek logs, version probes appear as odd User-Agent or malformed requests in web server logs, and the msfdb backend on the attacker box records imported hosts, services, loot, and command history in `~/.msf4/`. Default Meterpreter callbacks and staged payloads also produce recognizable network patterns and on-disk artifacts that DFIR examiners can hunt for.

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
- **T1595 Active Scanning** — Nmap sweeps and Metasploit auxiliary scanners (DFIR phase: identification / examination).
- **T1046 Network Service Discovery** — service/version enumeration to select exploits (DFIR phase: identification).
- **T1190 Exploit Public-Facing Application** — Metasploit exploit modules against exposed services (DFIR phase: identification / containment).
- **T1059 Command and Scripting Interpreter** — post-exploitation command execution via payloads (DFIR phase: examination / eradication).

## Sources
- Rapid7 Metasploit Framework documentation — https://docs.metasploit.com/
- Kali Linux Tools: metasploit-framework — https://www.kali.org/tools/metasploit-framework/
- Kali Linux Tools: nmap — https://www.kali.org/tools/nmap/
- Nmap Reference Guide — https://nmap.org/book/man.html
- MITRE ATT&CK T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1595 Active Scanning — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/
- SANS: Nmap Cheat Sheet — https://www.sans.org/posters/nmap-cheat-sheet/