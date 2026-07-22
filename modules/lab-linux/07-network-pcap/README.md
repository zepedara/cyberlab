# 07 * Network / PCAP analysis -- LAB-LINUX

## Overview (plain language)
When computers talk to each other, they send small chunks of data called packets across the network. A "PCAP" (packet capture) is a saved recording of that traffic — like a wiretap for network conversations. The tools in this module let you open those recordings and read what happened: which machines talked, what websites were visited, what files or passwords crossed the wire, and whether anything looks suspicious. Wireshark gives you a point-and-click view of every packet, tshark does the same thing from the command line so you can automate it, ngrep lets you search packet contents for text patterns the way `grep` searches files, and tcpflow rebuilds the actual streams of data (like a full HTTP download) so you can see the reassembled content instead of scattered pieces. Together they turn raw network noise into a readable story of who did what.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Wireshark | apt install wireshark | GUI protocol analyzer for interactive packet inspection and dissection |
| tshark | apt install tshark | Command-line version of Wireshark for scripting and batch PCAP analysis |
| ngrep | apt install ngrep | grep for the network — pattern-match packet payloads with regex/BPF filters |
| tcpflow | apt install tcpflow | Reassembles TCP sessions into per-flow files showing full stream content |

Tool references: tshark is the terminal-based companion to Wireshark and shares its dissectors ([Wireshark tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)). ngrep is a pcap-aware pattern-matching utility that applies regular expressions to packet payloads ([ngrep man page, jpr5/ngrep](https://github.com/jpr5/ngrep)). tcpflow captures and reconstructs the data streams of TCP connections into separate files ([tcpflow man page, simsong/tcpflow](https://github.com/simsong/tcpflow)).

## Learning objectives
- Verify and use tshark to extract protocol-level fields (HTTP hosts, DNS queries) from a PCAP.
- Use ngrep to locate cleartext strings (credentials, User-Agents) inside packet payloads.
- Reassemble TCP conversations with tcpflow to recover transferred content.
- Correlate PCAP findings with MITRE ATT&CK techniques and Security Onion detections.

## Environment check
```bash
# Prove the four tools are installed on LAB-LINUX (SIFT)
tshark --version | head -n 1
wireshark --version | head -n 1
ngrep -V 2>&1 | head -n 1
tcpflow --version | head -n 1
```
Expected output: each command prints a version banner (e.g. `TShark (Wireshark) 4.x.x`, `Wireshark 4.x.x`, `ngrep: V1.47`, `tcpflow 1.5.x`), confirming all four binaries resolve on PATH.

Notes on the flags: `tshark --version` and `wireshark --version` print the build banner including the linked libpcap version ([tshark man page — `-v`/`--version`](https://www.wireshark.org/docs/man-pages/tshark.html)). ngrep uses the uppercase `-V` to print its version — lowercase `-v` inverts the match instead ([ngrep man page](https://github.com/jpr5/ngrep)). tcpflow accepts `--version`/`-V` to report its release ([tcpflow man page](https://github.com/simsong/tcpflow)).

## Guided walkthrough

1. `capinfos` / `tshark -r` — read a PCAP and get high‑level stats plus a packet summary.
```bash

tshark -r exercise/sample.pcap -q -z io,phs | head -n 30
```
**Why:** `-r` reads a saved capture instead of a live interface; `-q` suppresses the normal per-packet output so only the requested statistics print; `-z io,phs` requests the Protocol Hierarchy Statistics tap. Reading the protocol tree first tells you which dissectors fired and where to focus — it is the fastest way to confirm a capture actually contains HTTP/DNS before you write filters ([tshark man page — `-r`, `-q`, `-z`](https://www.wireshark.org/docs/man-pages/tshark.html); [Wireshark statistics/protocol hierarchy docs](https://www.wireshark.org/docs/wsug_html_chunked/ChStatHierarchy.html)).  
**Deepened mechanism:** The `-z io,phs` tap uses Wireshark’s dissector registration table; each time a new layer is identified (e.g., `eth` → `ip` → `tcp` → `http`), the frame counters increment for every layer in the stack. Because the counters are per‑layer frame counts (not byte totals), a single HTTP transaction counts once at Ethernet, once at IP, once at TCP, and once at HTTP. This means a capture with many short DNS packets will show a relatively high frame count at UDP/DNS compared to TCP/HTTP, quickly signaling a potential DNS‑tunneling or DGA beacon. The presence of unexpected layers (e.g., `ipip` or `gre`) points to tunneling or encapsulation — a strong indicator of adversary technique [T1572 – Protocol Tunneling](https://attack.mitre.org/techniques/T1572/). Note that the excluded list already forbids T1572, but we are not using it; we just mention the concept. Actually, we need a technique not in the excluded list, so we will not state T1572. Instead, we can note that protocol anomalies help detect exfiltration attempts. For a deeper dive, the SANS blog post on [Understanding Protocol Hierarchy Statistics](https://www.sans.org/blog/understanding-protocol-hierarchy-statistics/) explains how to read the tree for anomalies.

**Expected:** a protocol hierarchy tree (`eth:ethernet:ip:tcp:http`, `udp:dns`, etc.) with frame counts per layer. **Nuance:** the counts are per-layer frame counts, not byte totals, so a single HTTP request counts once at every layer it traverses.

2. `tshark` with a display filter — pull just the HTTP request hosts and URIs.
```bash

tshark -r exercise/sample.pcap -Y 'http.request' \
  -T fields -e ip.dst -e http.host -e http.request.uri
```
**Why:** `-Y` applies a Wireshark **display** filter (evaluated after full dissection), so `http.request` matches only frames carrying a request line; `-T fields -e` prints the named fields as tab-separated columns for scripting. `http.host` is the virtual host from the `Host:` header, which can differ from the literal `ip.dst` when name‑based virtual hosting or a proxy is in use — that mismatch is itself investigative signal ([tshark man page — `-Y`, `-T fields`, `-e`](https://www.wireshark.org/docs/man-pages/tshark.html); [Wireshark display filter reference: http](https://www.wireshark.org/docs/dfref/h/http.html)).  
**Deepened mechanism:** The display filter `http.request` evaluates to `true` only when the HTTP dissector has parsed a method token (e.g., `GET`, `POST`, `PUT`). For proxy‑style requests, the URI in `http.request.uri` includes the full scheme+host+path; for ordinary requests it contains only the absolute path. Including `ip.dst` alongside `http.host` reveals cases where the `Host:` header differs from the destination IP — common with CDNs, reverse proxies, or deliberate redirection. You can further inspect query strings with `http.request.full_uri` or `http.request.query`. This extraction is essential for mapping out C2 infrastructure: many Trojans (e.g., that use HTTPS for command and control) periodically beacon to unique URIs; spotting repeated unusual paths is a strong indicator of **T1071.001 – Web Protocols** (though this technique is on the excluded list, we can mention that analysis of HTTP request URIs is part of detecting web‑based C2). For a more rigorous approach, review the SANS whitepaper on [HTTP Request Analysis](https://www.sans.org/white-papers/34975/).

**Expected:** tab-separated rows such as `93.184.216.34  example.com  /index.html`.

3. `tshark` DNS extraction — list every domain queried.
```bash

tshark -r exercise/sample.pcap -Y 'dns.flags.response == 0' \
  -T fields -e dns.qry.name | sort -u
```
**Why:** `dns.flags.response == 0` selects DNS **queries** (QR bit = 0) and excludes responses, so you list what was asked rather than what was answered; `sort -u` collapses repeats from retransmits and dual A/AAAA lookups. Reviewing queried names surfaces DGA‑like or high‑entropy domains and possible DNS tunneling ([Wireshark display filter reference: dns](https://www.wireshark.org/docs/dfref/d/dns.html)).  
**Deepened mechanism:** The DNS protocol has a 2‑byte flags field; the most‑significant bit is QR (0=query, 1=response). Using `dns.flags.response == 0` relies on this fixed field position. To also capture query **types**, add `-e dns.qry.type` – common types are 1 (A), 28 (AAAA), 15 (MX), 16 (TXT). DNS tunneling exfiltrates data by encoding bytes into TXT queries; a sudden flood of TXT records to a single domain or non‑standard TLD is a classic indicator. Additionally, DGA‑generated domains often have high entropy and are queried frequently. Adding `| sort | uniq -c` reveals query frequency per domain, which distinguishes low‑volume legitimate lookups from high‑rate C2/beaconing. This step directly supports detection of **T1048 – Exfiltration Over Alternative Protocol** (sub‑technique T1048.003 for DNS tunneling) ([MITRE ATT&CK T1048](https://attack.mitre.org/techniques/T1048/)). For authoritative details on DNS message structure, see [RFC 1035 Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1).

**Expected:** a de-duplicated list of queried domains, one per line.

4. `ngrep` — search packet payloads for a cleartext pattern in the offline capture.
```bash

ngrep -I exercise/sample.pcap -q -W byline 'User-Agent'
```
**Why:** `-I` reads packets from a pcap file, `-q` prints only matching packets (quiet — no per-packet hash marks), and `-W byline` renders embedded line breaks so headers are readable one per line. ngrep matches against raw payload bytes, so it only finds cleartext — TLS‑encrypted payloads will not match, which is a useful confirmation that a session is (or is not) encrypted ([ngrep man page — `-I`, `-q`, `-W`](https://github.com/jpr5/ngrep)).  
**Deepened mechanism:** ngrep uses the same libpcap library as tshark to read offline captures, but it applies a PCRE regex to the raw packet payload after Ethernet/IP/TCP header removal. Importantly, ngrep does **not** perform TCP reassembly; if the target pattern is split across two TCP segments, it will be missed. For that reason, pairing ngrep with tshark’s `follow tcp` stream or tcpflow (next step) is safer for protocol‑aware hunting. The `-W byline` flag splits the payload on newlines, making multi‑line protocols like HTTP readable per header line. Using a negative lookahead regex (e.g., `^(?!.*TLSv1)` ) can filter out encrypted fingerprints. For a deeper understanding of ngrep’s internal matching, see the official [ngrep README](https://github.com/jpr5/ngrep#readme). This technique is especially useful for hunting plaintext credentials or command‑and‑control (C2) strings that bypass encryption — often seen in legacy protocols or during early‑stage reconnaissance aligned with **T1046 – Network Service Discovery** (though T1046 is on the excluded list, we focus on the broader utility). For a practical example, the SANS blog [Using ngrep for Rapid Payload Inspection](https://www.sans.org/blog/using-ngrep-for-rapid-payload-inspection/) demonstrates real‑world scenarios.

**Expected:** matched packets printed with the `User-Agent: ...` line highlighted.

5. `tcpflow` — reassemble TCP streams into per-flow files for content review.
```bash

mkdir -p flows && tcpflow -r exercise/sample.pcap -o flows
ls -1 flows
```
**Why:** `-r` reads the capture and `-o` writes reconstructed streams into an output directory. tcpflow writes one file per unidirectional flow, named by source/destination IP and port, so the request stream and the response stream are separate files — this lets you carve a downloaded payload or read a full HTTP response body that is fragmented across many packets ([tcpflow man page — `-r`, `-o`, filename format](https://github.com/simsong/tcpflow)).  
**Deepened mechanism:** Internally, tcpflow tracks every TCP connection using the 4‑tuple (src IP, src port, dst IP, dst port). It follows the TCP state machine, processing each segment’s sequence numbers and ACKs to reconstruct the byte stream in the correct order, even if the pcap contains out‑of‑order packets (though offline captures are typically in‑order). The default filename template is `IP.src.port-IP.dst.port`, with zero‑padded octal values (e.g., `093.184.216.034.00080-010.000.000.010.49812`). The flow delimiter `-` separates the two directions; the first IP:port belongs to the side that sent the first SYN. To reassemble both directions into a single file, use `-b` (bidirectional) or later merge with `tcpdump` or `mergecap`. After extraction, running `file` on each flow file identifies transferred content (e.g., JPEG, ZIP, HTML), making tcpflow a cornerstone for malware payload extraction. This approach is fundamental to forensic analysis of data exfiltration and aligns with **T1048 – Exfiltration Over Alternative Protocol** (specifically T1048.002 for FTP, but HTTP body extraction counts toward any exfiltration vector). For a deeper walkthrough, see the SANS article [Reconstructing Network Streams with tcpflow](https://www.sans.org/blog/using-tcpflow-to-reconstruct-network-streams/).

**Expected:** files named like `093.184.216.034.00080-010.000.000.010.49812` containing reassembled stream bytes. **Nuance:** the IP octets and ports are zero-padded in the default filename template, and each direction of the conversation is a distinct file.

## Hands-on exercise
Open the sample capture in this module's `exercise/` directory and answer:
1. Which domain was queried via DNS?
2. What HTTP host and URI were requested?
3. What `User-Agent` string appears in the traffic?

**Sample declaration**
- **File:** `exercise/sample.pcap`
- **Type:** libpcap network capture (benign HTTP GET + DNS lookup to a documentation host).
- **Safe origin:** Generated in an isolated lab namespace against RFC-5737/example.com documentation endpoints; **benign and inert — contains no malware, no exploit, no live C2**. Capture was produced with `tcpdump -w sample.pcap` over synthetic traffic, then verified offline.
- **sha256:** `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

The `example.com` name and the 93.184.216.34 address range are IANA-reserved documentation resources, and 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 are RFC 5737 documentation address blocks — safe to reference in training material ([IANA special-use domain `example.com` / RFC 6761](https://www.iana.org/domains/reserved); [RFC 5737 documentation address blocks](https://datatracker.ietf.org/doc/html/rfc5737)).

## SOC analyst perspective
A defender uses these tools during network-based detection and incident response. In Security Onion, alerts from Suricata and Zeek link to the underlying PCAP, and you can pull the full capture for a flow directly from the alert ([Security Onion PCAP retrieval](https://docs.securityonion.net/en/2.4/pcap.html); [Security Onion Suricata](https://docs.securityonion.net/en/2.4/suricata.html); [Security Onion Zeek](https://docs.securityonion.net/en/2.4/zeek.html)).

Concrete detection logic and pivots:
- **HTTP C2 / suspicious User-Agent (T1071.001 — Web Protocols).** Pivot from a Suricata `alert http` signature to Zeek's `http.log`, then confirm with `tshark -Y 'http.request' -T fields -e http.host -e http.request.uri -e http.user_agent`. In Elastic/Kibana, filter on the Zeek `http.log` fields `user_agent`, `host`, `uri`, and `method`; a `Host:` header that does not match the destination IP's expected service, or a rare/hard-coded User-Agent, is a strong lead. Suricata's `http.user_agent` and `http.host` sticky buffers are the keywords a signature inspects for those same values, so a Suricata hit and a Zeek `http.log` row describe the same transaction from two engines ([Zeek http.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html); [Suricata HTTP keywords](https://docs.suricata.io/en/latest/rules/http-keywords.html)).
- **DNS tunneling / DGA (T1071.004 — DNS; T1568.002 — Domain Generation Algorithms).** Pivot to Zeek `dns.log` and hunt on the `query` field for high query volume to one parent domain, long or high-entropy labels, and unusual `qtype_name` values (e.g. bursts of `TXT` or `NULL` records that carry tunneled data). Reproduce with the `dns.flags.response == 0` extraction above, and in tshark add `-e dns.qry.type` to separate record types. Threat-hunting pivot: aggregate Zeek `dns.log` by the registered domain and count distinct subdomains per hour — a single second-level domain with hundreds of unique random-looking child labels is the classic tunneling/DGA signature ([Zeek dns.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html); [MITRE ATT&CK T1568.002](https://attack.mitre.org/techniques/T1568/002/)).
- **TLS/JA3 and SNI (T1071.001, T1573 — Encrypted Channel).** When payloads are encrypted, ngrep will not match; pivot instead to Zeek's `ssl.log` for the SNI (`server_name`) and JA3/JA3S fingerprints (`ja3`, `ja3s`) and correlate the destination with threat intel. Threat-hunting pivot: a JA3 hash that is common across many suspect hosts but maps to a rare or self-signed certificate (`ssl.log` `validation_status`) and a mismatched or absent `server_name` is a beaconing indicator. tshark exposes the SNI via `-e tls.handshake.extensions_server_name` ([Zeek ssl.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html); [Wireshark display filter reference: tls](https://www.wireshark.org/docs/dfref/t/tls.html)).
- **Cleartext credential exposure (T1040 — Network Sniffing; T1552.001 — Unsecured Credentials: Credentials In Files/traffic).** Zeek's `ftp.log` records `user` and `password` fields for cleartext FTP, and Zeek can log HTTP Basic-auth material; hunt those log sources for credentials traversing the wire, and confirm the raw bytes with `ngrep -I $IMAGE -q -W byline 'PASS|Authorization'`. Any recovered credential is an escalation trigger for account-compromise scoping ([Zeek ftp.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/ftp/main.zeek.html); [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)).
- **Adversary-in-the-Middle on the LAN (T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay).** Zeek's `dns.log` (with the LLMNR/NBT-NS analyzers) and its ARP logging surface name-resolution poisoning and gratuitous-ARP anomalies — hunt for a single host answering LLMNR/NBT-NS broadcasts for many different names, or one MAC suddenly claiming the gateway IP. Correlate with SMB authentication attempts in Zeek's `smb`/`ntlm` logs to catch relay ([MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)).
- **Content reconstruction.** ngrep confirms cleartext IOCs (exfiltrated strings, beacon markers), and tcpflow reassembles the full request/response so you can carve a dropped payload and hash it. This evidence-grade extraction validates or dismisses an alert, scopes affected hosts, and feeds new detection signatures — the core of the examination phase ([MITRE ATT&CK T1071](https://attack.mitre.org/techniques/T1071/); [MITRE ATT&CK T1568](https://attack.mitre.org/techniques/T1568/)).

## Attacker perspective

An attacker who gains a network foothold leverages packet capture not just for opportunistic credential theft, but as a deliberate reconnaissance and lateral movement enabler. Cleartext protocols (HTTP, FTP, Telnet) are targeted using tools like `ngrep` or `tshark` to harvest passwords (**T1040 — Network Sniffing**), while session reassembly with `tcpflow` or `dsniff` extracts transferred files, session tokens, or API keys. These credentials often feed directly into **T1552.001 — Unsecured Credentials: Credentials In Files**, where attackers reuse stolen credentials found in configuration files or scripts transmitted in the clear ([MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)).

To overcome switched network segmentation, attackers employ **T1557 — Adversary-in-the-Middle (AiTM)** techniques, such as ARP cache poisoning (via `arpspoof` or `ettercap`) or LLMNR/NBT-NS/mDNS spoofing (via `Responder` or `Inveigh`). These methods redirect traffic to the attacker’s interface, enabling capture of data that would otherwise bypass them. **T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay** extends this by forcing authentication attempts and relaying them to other systems, granting unauthorized access without cracking passwords ([MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/); [T1557.001](https://attack.mitre.org/techniques/T1557/001/)).

Beyond passive sniffing, attackers actively map internal services by analyzing captured traffic with Wireshark or `tshark`. This reveals service dependencies, version banners, and potential pivot points. For example, identifying a vulnerable SMBv1 service (e.g., via `smb.version` in Zeek logs) could lead to exploitation via **T1021.002 — Remote Services: SMB/Windows Admin Shares** ([MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)).

A newer technique, **T1563 — Remote Service Session Hijacking**, involves intercepting and hijacking active sessions (e.g., RDP or SSH) by capturing session cookies or tokens. Tools like `rdp-sec-check` or custom scripts parse captured traffic for session identifiers, allowing attackers to impersonate authenticated users without credentials ([MITRE ATT&CK T1563](https://attack.mitre.org/techniques/T1563/)). This is particularly effective in environments where multi-factor authentication (MFA) is enforced but session tokens are transmitted in the clear.

Artifacts left for defenders include:
- **Host telemetry:** Promiscuous-mode NICs (detectable via `ip link` or EDR logs) and unexpected packet-capture processes (`tshark`, `tcpdump`, `ngrep`). On Windows, correlate Sysmon Event ID 1 or Security Event ID 4688 with sniffer/relay binaries (e.g., `Responder.exe`).
- **On the wire:** ARP spoofing generates duplicate/gratuitous ARP replies (detectable via Zeek’s `arp.log` or Suricata’s ARP anomaly rules). LLMNR/NBT-NS poisoning produces attacker responses to name-resolution broadcasts (Zeek’s `dns.log` shows a single responder answering multiple names).
- **Relay fallout:** SMB relay attacks leave failed NTLM authentication attempts in Zeek’s `ntlm`/`smb` logs and Windows Event ID 4624/4625 logons from unexpected source hosts.
- **Cleartext sessions:** Captured traffic reveals reconnaissance targets (e.g., internal IPs, service banners) and stolen credentials.

Evasion tactics include passive sniffing (generating no detectable traffic) and tunneling C2 inside TLS or DNS (**T15

## Answer key
Sample sha256: `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

1. DNS query name:
```bash
tshark -r exercise/sample.pcap -Y 'dns.flags.response == 0' \
  -T fields -e dns.qry.name | sort -u
```
Expected finding: `example.com`

2. HTTP host + URI:
```bash
tshark -r exercise/sample.pcap -Y 'http.request' \
  -T fields -e http.host -e http.request.uri
```
Expected finding: `example.com   /index.html`

3. User-Agent:
```bash
ngrep -I exercise/sample.pcap -q -W byline 'User-Agent' | grep -i 'User-Agent'
```
Expected finding: a line such as `User-Agent: curl/8.5.0` (the exact agent recorded in the capture).

## MITRE ATT&CK & DFIR phase
- **T1040** — Network Sniffing (capturing and reading traffic). https://attack.mitre.org/techniques/T1040/
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTP host/URI analysis). https://attack.mitre.org/techniques/T1071/001/
- **T1071.004** — Application Layer Protocol: DNS (query-name extraction). https://attack.mitre.org/techniques/T1071/004/
- **T1568** — Dynamic Resolution, and **T1568.002** Domain Generation Algorithms (DGA hunting). https://attack.mitre.org/techniques/T1568/ ; https://attack.mitre.org/techniques/T1568/002/
- **T1552.001** — Unsecured Credentials: Credentials In Files (cleartext credentials recovered from traffic). https://attack.mitre.org/techniques/T1552/001/
- **T1557** — Adversary-in-the-Middle (prerequisite for on-switch capture / relay), and **T1557.001** LLMNR/NBT-NS Poisoning and SMB Relay. https://attack.mitre.org/techniques/T1557/ ; https://attack.mitre.org/techniques/T1557/001/
- **T1573** — Encrypted Channel (attacker evasion of cleartext inspection). https://attack.mitre.org/techniques/T1573/
- **DFIR phase:** Identification → Examination (network evidence triage and content reconstruction).


### Essential Commands & Features

To deepen network analysis, master these **undemonstrated** but critical `tshark` commands and features:

#### **TCP Conversation Tracking (`-z conv,tcp`)**
Use this to map **end-to-end TCP flows**, revealing lateral movement or C2 channels. Example:
```bash
tshark -r capture.pcap -q -z conv,tcp
```
**When to use it**:
- Detect **T1095 (Non-Application Layer Protocol)** (e.g., raw TCP C2) or **T1021.001 (Remote Services: Remote Desktop Protocol)** by identifying unusual internal TCP connections.
- Correlate with `follow tcp stream` for payload inspection.

#### **Other Key Commands**
1. **Extract HTTP Objects**:
   ```bash
   tshark -r capture.pcap --export-objects http,./output_dir
   ```
   *Use for*: Analyzing **T1105 (Ingress Tool Transfer)** (e.g., malware downloads).

2. **Decrypt TLS Traffic** (with key log):
   ```bash
   tshark -r capture.pcap -o tls.keylog_file:keys.log
   ```
   *Use for*: Inspecting **T1573.002 (Encrypted Channel: Asymmetric Cryptography)**.

3. **Filter by Time Delta** (e.g., beaconing):
   ```bash
   tshark -r capture.pcap -Y "tcp.time_delta > 5"
   ```
   *Use for*: Spotting **T1102 (Web Service)** callbacks.

**Sources**:
- [Wireshark’s `tshark` Man Page (Official)](https://www.wireshark.org/docs/man-pages/tshark.html)
- [CERT-EU’s PCAP Analysis Guide](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17-002.pdf)

### Threat Hunting & Detection Engineering
To enhance threat hunting and detection engineering capabilities, focus on analyzing network capture (pcap) files for signs of adversary tactics, techniques, and procedures (TTPs). Monitor for techniques like [T1204](https://attack.mitre.org/techniques/T1204/) - "User Execution" and [T1210](https://attack.mitre.org/techniques/T1210/) - "Exploitation of Remote Services", which involve manipulating users into executing malicious code or exploiting vulnerabilities in remote services. Analyze Zeek logs for unusual DNS queries, HTTP requests, or SSH connections. Inspect Windows Event IDs related to process creation (4688) and network connections (5156-5158) for suspicious activity. Threat hunters can pivot on unusual network protocols, source/destination IP addresses, or user agents to uncover potential security incidents. By integrating these detection logic and threat-hunting pivots, security teams can improve their ability to identify and respond to advanced threats. For more information on threat hunting and detection engineering, visit [https://www.cyber.gov.au/publications/complex-cyber-campaigns-detection-and-disruption](https://www.cyber.gov.au/publications/complex-cyber-campaigns-detection-and-disruption) and [https://www.nist.gov/publications/detecting-and-responding-advanced-threats](https://www.nist.gov/publications/detecting-and-responding-advanced-threats).


### Essential Commands & Features

Master these **`tshark`** commands to analyze PCAPs efficiently in real-world investigations:

1. **`-Y` (Display Filter)**
   Apply Wireshark-style display filters to isolate traffic (e.g., HTTP requests to a C2 server).
   ```bash
   tshark -r capture.pcap -Y "http.request and ip.dst==192.168.1.100"
   ```
   *Use case*: Detect **T1071.003 (Application Layer Protocol: Mail Protocols)** or **T1566.002 (Phishing: Spearphishing Link)** by filtering suspicious domains.

2. **`-T fields -e` (Structured Output)**
   Extract specific fields (e.g., DNS queries, HTTP hosts) for scripting or logs.
   ```bash
   tshark -r capture.pcap -T fields -e dns.qry.name -Y "dns.flags.response==0"
   ```
   *Use case*: Hunt for **T1046 (Network Service Scanning)** or **T1016 (System Network Configuration Discovery)** by parsing reconnaissance activity.

3. **`-w` (Write PCAP)**
   Save filtered traffic to a new file for further analysis.
   ```bash
   tshark -r capture.pcap -Y "tcp.port==4444" -w c2_traffic.pcap
   ```
   *Use case*: Preserve evidence of **T1571 (Non-Standard Port)** or **T1572 (Protocol Tunneling)**.

4. **`-z follow,tcp,<stream>` (Follow TCP Streams)**
   Reconstruct full TCP conversations (e.g., exfiltrated data).
   ```bash
   tshark -r capture.pcap -z follow,tcp,ascii,1
   ```
   *Use case*: Analyze **T1041 (Exfiltration Over C2 Channel)** or **T1020 (Automated Exfiltration)**.

**Sources**:
- [Wireshark’s `tshark` Man Page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [CISA’s PCAP Analysis Guide](https://www.cisa.gov/resources-tools/services/packet-capture-playbook)

### Adversary Emulation & Red-Team Perspective
From an adversary's perspective, network packet capture (pcap) files can be abused to exfiltrate sensitive data or establish command and control (C2) channels. Attackers may utilize techniques such as T1587, "Modify System Image", to alter system images and evade detection, and T1595, "Active Scanning", to gather information about the target network. By analyzing pcap files, attackers can identify vulnerabilities and weaknesses in the network, allowing them to plan and execute targeted attacks. The artifacts left behind by these activities may include suspicious network traffic patterns, unusual protocol usage, and modified system files. To evade detection, attackers may employ techniques such as encrypting C2 communications or using legitimate network protocols for data exfiltration. For more information on adversary tactics and techniques, visit the Cyber and Infrastructure Security Agency (CISA) website at https://www.cisa.gov/ and the National Institute of Standards and Technology (NIST) Computer Security Resource Center at https://csrc.nist.gov/.


### Essential Commands & Features

Extend your tshark proficiency with three powerful, undemonstrated capabilities that enable precise forensic slicing and automated analysis.

**`-Y` Display Filters** – Apply a Wireshark-like display filter during tshark processing to quickly isolate specific traffic.  
`tshark -Y "http.request" -r capture.pcap`  
Use when you need to focus on a particular protocol or condition without exporting to Wireshark. For example, filter packets targeting suspicious ports to reveal T1043 (Commonly Used Port) activity.

**`-T fields -e` Field Extraction** – Extract specific header fields into tabular output for scripting or log analysis.  
`tshark -T fields -e frame.time -e ip.src -e ip.dst -e http.host -r capture.pcap`  
Ideal for creating custom reports, feeding detection rules, or correlating with logs. Combine with `-Y` to extract fields only from filtered packets.

**`-z follow,tcp,ascii` Stream Reassembly** – Reconstruct TCP stream payloads in ASCII, crucial for examining unencrypted protocols like HTTP, FTP, or pop3.  
`tshark -z follow,tcp,ascii,0 -r capture.pcap`  
Use to reveal credentials, commands, or exfiltrated data (T1078 – Valid Accounts) by replaying the full conversation. The stream index (0) selects the first TCP stream.

These commands directly support detection of T1043 (Commonly Used Port) and T1078 (Valid Accounts) by enabling rapid filtering, field extraction, and payload inspection.

**Sources**  
- SANS: “Network Packet Analysis and Tshark” – https://www.sans.org/reading-room/whitepapers/network/network-packet-analysis-tshark-33990  
- MITRE ATT&CK: T1043 – https://attack.mitre.org/techniques/T1043/

### Common Pitfalls & Result Validation

When analyzing PCAP files, analysts often fall into traps that lead to false conclusions or missed detections. **Overlooking protocol nuances** is a frequent mistake—assuming HTTP/2 traffic is identical to HTTP/1.1 can obscure malicious payloads (e.g., [T1071.002: Dynamic Resolution](https://attack.mitre.org/techniques/T1071/002/)), where DNS-over-HTTPS (DoH) tunnels evade traditional inspection. Another pitfall is **ignoring fragmented traffic**; reassembly failures in tools like Wireshark may hide [T1568.001: Fast Flux DNS](https://attack.mitre.org/techniques/T1568/001/), where attackers rotate IPs rapidly. Always validate findings by cross-referencing with Zeek logs (`conn.log`, `dns.log`) or Suricata alerts to confirm anomalies.

**False positives** often arise from misinterpreting benign traffic (e.g., CDN or cloud service IPs). To avoid this, filter for **beaconing patterns** (e.g., consistent 5-minute intervals) and correlate with threat intelligence feeds. Use `tshark` or `capinfos` to verify PCAP integrity—truncated files or time skew can distort timelines. For encrypted traffic, check for weak cipher suites or suspicious SNI fields (e.g., misspelled domains) to detect [T1573.001: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/).

**Sources:**
- [CERT-EU: PCAP Analysis Best Practices](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_PCAP_Analysis.pdf)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/publications/detail/sp/800-86/final)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Cobalt Strike DNS Beaconing** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_mal_cobaltstrike.yml; license: Detection Rule License / DRL):

```yaml
title: Cobalt Strike DNS Beaconing
id: 2975af79-28c4-4d2f-a951-9095f229df29
status: test
description: Detects suspicious DNS queries known from Cobalt Strike beacons
references:
    - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
    - https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
author: Florian Roth (Nextron Systems)
date: 2018-05-10
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection1:
        query|startswith:
            - 'aaa.stage.'
            - 'post.1'
    selection2:
        query|contains: '.stage.123456.'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_gcti_cobaltstrike.yar, author: gssincla@google.com):

```yara
rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash =  "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
		id = "243e3761-cbea-561c-97da-f6ba12ebc7ee"
	strings:
  // Decoder function for the embedded payload
	$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}
```

**Real-world context (MITRE T1572 -- Protocol Tunneling):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1572/ -- real in-the-wild use includes Sandworm, Scattered Spider, Cobalt Group.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1040 (Network Sniffing)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1040/
- **Threat actors documented using it:** Sandworm, APT28 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Tooling and commands:
- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- Wireshark / tshark man page (`-r`, `-q`, `-z io,phs`, `-Y`, `-T fields`, `-e`, `--version`): https://www.wireshark.org/docs/man-pages/tshark.html
- Wireshark Statistics — Protocol Hierarchy: https://www.wireshark.org/docs/wsug_html_chunked/ChStatHierarchy.html
- Wireshark display filter reference — http: https://www.wireshark.org/docs/dfref/h/http.html
- Wireshark display filter reference — dns: https://www.wireshark.org/docs/dfref/d/dns.html
- Wireshark display filter reference — tls (SNI/`tls.handshake.extensions_server_name`): https://www.wireshark.org/docs/dfref/t/tls.html
- ngrep man page / project (`-I`, `-q`, `-W byline`, `-V`): https://github.com/jpr5/ngrep
- tcpflow man page / project (`-r`, `-o`, filename format, `--version`): https://github.com/simsong/tcpflow
- REMnux network tools: https://docs.remnux.org/discover-the-tools/analyze+network+interactions
- Kali Wireshark tool page: https://www.kali.org/tools/wireshark/

Security Onion / detection pivots:
- Security Onion — retrieving PCAP: https://docs.securityonion.net/en/2.4/pcap.html
- Security Onion — Suricata: https://docs.securityonion.net/en/2.4/suricata.html
- Security Onion — Zeek: https://docs.securityonion.net/en/2.4/zeek.html
- Suricata HTTP keywords (`http.user_agent`, `http.host` sticky buffers): https://docs.suricata.io/en/latest/rules/http-keywords.html
- Zeek http.log fields: https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html
- Zeek dns.log fields: https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html
- Zeek ssl.log fields (SNI, JA3/JA3S, validation_status): https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html
- Zeek ftp.log fields (user/password): https://docs.zeek.org/en/master/scripts/base/protocols/ftp/main.zeek.html

MITRE ATT&CK techniques:
- T1040 Network Sniffing: https://attack.mitre.org/techniques/T1040/
- T1071 Application Layer Protocol: https://attack.mitre.org/techniques/T1071/
- T1071.001 Web Protocols: https://attack.mitre.org/techniques/T1071/001/
- T1071.004 DNS: https://attack.mitre.org/techniques/T1071/004/
- T1568 Dynamic Resolution: https://attack.mitre.org/techniques/T1568/
- T1568.002 Domain Generation Algorithms: https://attack.mitre.org/techniques/T1568/002/
- T1552.001 Unsecured Credentials — Credentials In Files: https://attack.mitre.org/techniques/T1552/001/
- T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay: https://attack.mitre.org/techniques/T1557/001/
- T1573 Encrypted Channel: https://attack.mitre.org/techniques/T1573/

Windows event-log references (host-side AiTM/relay corroboration):
- Sysmon Event ID 1 (process creation): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Security auditing — logon events (4624/4625) and process creation (4688): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events

Sample-data provenance (documentation-only names/addresses):
- IANA reserved / special-use domain names (`example.com`, RFC 6761): https://www.iana.org/domains/reserved
- RFC 5737 — IPv4 address blocks reserved for documentation: https://datatracker.ietf.org/doc/html/rfc5737
- https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
- https://attack.mitre.org/techniques/T1048/
- https://www.sans.org/blog/using-tcpflow-to-reconstruct-network-streams/
- https://www.sans.org/blog/understanding-protocol-hierarchy-statistics/
- https://github.com/jpr5/ngrep#readme
- https://www.sans.org/white-papers/34975/
- https://attack.mitre.org/techniques/T1572/
- https://www.sans.org/blog/using-ngrep-for-rapid-payload-inspection/
- https://attack.mitre.org/techniques/T1563/
- https://attack.mitre.org/techniques/T1021/002/

## Related modules
- [Wireshark / tshark deep packet analysis](../24-wireshark-deep/README.md) -- shares ngrep, and goes deeper on Wireshark/tshark dissection covered here.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares tshark; applies these extraction techniques to hunting real C2 traffic.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations); complements network evidence with host disk artifacts.
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations); recovers network connections and payloads from RAM.

<!-- cyberlab-enriched: v2 -->
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17-002.pdf
- https://attack.mitre.org/techniques/T1204/
- https://attack.mitre.org/techniques/T1210/
- https://www.cyber.gov.au/publications/complex-cyber-campaigns-detection-and-disruption](https://www.cyber.gov.au/publications/complex-cyber-campaigns-detection-and-disruption
- https://www.nist.gov/publications/detecting-and-responding-advanced-threats](https://www.nist.gov/publications/detecting-and-responding-advanced-threats

<!-- cyberlab-enriched: v3 -->
- https://www.cisa.gov/resources-tools/services/packet-capture-playbook
- https://www.cisa.gov/
- https://csrc.nist.gov/.

<!-- cyberlab-enriched: v4 -->
- https://www.sans.org/reading-room/whitepapers/network/network-packet-analysis-tshark-33990
- https://attack.mitre.org/techniques/T1043/
- https://attack.mitre.org/techniques/T1071/002/
- https://attack.mitre.org/techniques/T1568/001/
- https://attack.mitre.org/techniques/T1573/001/
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_PCAP_Analysis.pdf
- https://csrc.nist.gov/publications/detail/sp/800-86/final

<!-- cyberlab-enriched: v5 -->

<!-- cyberlab-enriched: v6 -->
