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

## Guided walkthrough
1. `capinfos` / `tshark -r` — read a PCAP and get high-level stats plus a packet summary.
```bash
# Summary of the capture: packet count, time range, protocols seen
tshark -r exercise/sample.pcap -q -z io,phs | head -n 30
```
Expected: a protocol hierarchy tree (`eth:ethernet:ip:tcp:http`, `udp:dns`, etc.) with frame counts per layer.

2. `tshark` with a display filter — pull just the HTTP request hosts and URIs.
```bash
# Extract HTTP virtual host + requested URI for every request
tshark -r exercise/sample.pcap -Y 'http.request' \
  -T fields -e ip.dst -e http.host -e http.request.uri
```
Expected: tab-separated rows such as `93.184.216.34  example.com  /index.html`.

3. `tshark` DNS extraction — list every domain queried.
```bash
# All DNS query names in the capture
tshark -r exercise/sample.pcap -Y 'dns.flags.response == 0' \
  -T fields -e dns.qry.name | sort -u
```
Expected: a de-duplicated list of queried domains, one per line.

4. `ngrep` — search packet payloads for a cleartext pattern in the offline capture.
```bash
# Hunt for HTTP User-Agent strings inside the payloads
ngrep -I exercise/sample.pcap -q -W byline 'User-Agent'
```
Expected: matched packets printed with the `User-Agent: ...` line highlighted.

5. `tcpflow` — reassemble TCP streams into per-flow files for content review.
```bash
# Reassemble flows into the current directory, then list what was recovered
mkdir -p flows && tcpflow -r exercise/sample.pcap -o flows
ls -1 flows
```
Expected: files named like `093.184.216.034.00080-010.000.000.010.49812` containing reassembled stream bytes.

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

## SOC analyst perspective
A defender uses these tools during network-based detection and incident response. In Security Onion, alerts from Suricata/Zeek pivot you to the exact PCAP; you then run tshark to confirm what an IDS rule flagged — extracting the malicious host, URI, JA3/TLS SNI, or DNS name that triggered it (mapping to T1071 Application Layer Protocol and T1568 Dynamic Resolution). ngrep quickly confirms cleartext IOCs like exfiltrated data or beaconing patterns, while tcpflow reassembles the full request/response so you can recover a dropped payload or verify C2 content. This evidence-grade extraction validates or dismisses an alert, scopes affected hosts, and feeds new detection signatures — the core of the examination phase.

## Attacker perspective
An attacker who gains a network foothold uses the same capture capability for reconnaissance and credential theft — sniffing cleartext protocols (HTTP, FTP, Telnet) with ngrep or tshark to harvest passwords (T1040 Network Sniffing), or reassembling sessions with tcpflow to steal transferred files and tokens. Offensively, running Wireshark/tshark against a mirrored or MITM'd link maps internal services and protocols before pivoting. The artifacts they leave for defenders: promiscuous-mode NIC state, unexpected packet-capture processes in host telemetry, ARP-spoofing entries when combined with a MITM tool, and — on the wire — the very cleartext sessions that reveal both their reconnaissance targets and the credentials they grabbed.

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
- **T1040** — Network Sniffing (capturing and reading traffic).
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTP host/URI analysis).
- **T1568** — Dynamic Resolution / **T1071.004** — DNS (query-name extraction).
- **DFIR phase:** Identification → Examination (network evidence triage and content reconstruction).

## Sources
- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation/
- Wireshark / tshark documentation: https://www.wireshark.org/docs/man-pages/tshark.html
- ngrep project: https://github.com/jpr5/ngrep
- tcpflow documentation: https://github.com/simsong/tcpflow/wiki
- REMnux network tools: https://docs.remnux.org/discover-the-tools/analyze+network+interactions
- Kali Wireshark tool page: https://www.kali.org/tools/wireshark/
- MITRE ATT&CK T1040 Network Sniffing: https://attack.mitre.org/techniques/T1040/
- MITRE ATT&CK T1071 Application Layer Protocol: https://attack.mitre.org/techniques/T1071/