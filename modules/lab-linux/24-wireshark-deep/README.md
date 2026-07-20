# 24 * Wireshark / tshark deep packet analysis -- LAB-LINUX

## Overview (plain language)
Every time a computer talks to another computer, it sends small chunks of data called packets across the network. Wireshark, tshark, and ngrep are tools that let you capture and read those packets so you can see exactly what was sent and received. Think of it like recording every phone call on an office line and then reading a transcript. Wireshark is the graphical version with clickable menus and colors; tshark is the same engine but driven from the command line so you can script and filter it; ngrep is a simpler tool that searches packet contents for text patterns, much like the `grep` command you use on files. Analysts use these to answer questions like "what website did this machine contact?", "what data left the building?", and "is this traffic normal or an attack?" — all without touching the suspicious computer itself.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Wireshark | apt install wireshark | GUI packet capture and protocol analysis / deep dissection of pcap files |
| tshark | apt install tshark | Command-line packet analysis, filtering, and field extraction from pcaps |
| ngrep | apt install ngrep | grep-style pattern matching against live traffic or pcap payloads |

## Learning objectives
- Verify the packet-analysis toolset is installed and can open a pcap on LAB-LINUX.
- Use tshark display filters to isolate DNS, HTTP, and TLS conversations in a capture.
- Extract specific protocol fields (hostnames, URIs, JA3-relevant fields) with `-T fields`.
- Use ngrep to locate cleartext strings (credentials, beacons) inside a pcap payload.
- Correlate a suspicious flow to a MITRE ATT&CK technique and document it for IR.

## Environment check
```bash
# Prove all three tools are present and print their versions
wireshark --version | head -n 1
tshark --version | head -n 1
ngrep -V 2>&1 | head -n 1
```
Expected output: three version banners, e.g. `Wireshark 4.2.x`, `TShark (Wireshark) 4.2.x`, and an `ngrep: V1.47` line. If any command reports "command not found", install with `sudo apt install wireshark tshark ngrep`.

## Guided walkthrough
1. `capinfos` — confirm the capture is readable and summarize it (packet count, duration, file hashes).
```bash
capinfos exercise/sample.pcap
```
Expected: a summary table showing number of packets, capture duration, data size, and SHA256 of the file.

2. `tshark` — list every packet with a one-line summary to get oriented.
```bash
tshark -r exercise/sample.pcap -c 20
```
Expected: the first 20 packets, one per line, with time, source/destination IP, protocol, and info column.

3. `tshark` — isolate DNS queries to reveal contacted domains (a common IOC source).
```bash
tshark -r exercise/sample.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```
Expected: one domain name per line for every DNS query in the capture.

4. `tshark` — pull HTTP request hosts and URIs to reconstruct web activity.
```bash
tshark -r exercise/sample.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```
Expected: tab-separated host + path pairs for each HTTP request.

5. `tshark` — extract TLS Server Name Indication values from encrypted sessions.
```bash
tshark -r exercise/sample.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name
```
Expected: the destination hostnames requested inside TLS ClientHello messages.

6. `ngrep` — search packet payloads for a cleartext keyword (e.g. a user-agent or credential marker).
```bash
ngrep -I exercise/sample.pcap -q -W byline "User-Agent"
```
Expected: matching packets printed with their payloads, showing each HTTP `User-Agent` header.

## Hands-on exercise
Open `exercise/sample.pcap` in this module's `exercise/` directory and answer:
1. How many DNS queries are in the capture, and what domain is queried most?
2. What is the full URI of the single HTTP GET request?
3. What plaintext User-Agent string appears in the HTTP traffic?

**Sample declaration**
- Type: libpcap capture file (`.pcap`) containing benign simulated DNS + HTTP traffic.
- Safe origin: generated in an isolated lab using `curl` against an INetSim/FakeNet-NG responder — **no live malware, no real C2, no PII, no external egress**. The capture contains only synthetic requests.
- sha256: `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

## SOC analyst perspective
In an incident, a defender rarely trusts the compromised host — they trust the wire. tshark and ngrep let an analyst carve command-and-control beacons, data-exfiltration flows, and lateral-movement traffic out of a Security Onion pcap without altering endpoint evidence. Security Onion already runs Zeek and Suricata to produce alerts and connection logs; when an alert fires (say Suricata flags a suspicious domain), the analyst pivots into the full packet capture via Security Onion's PCAP retrieval and uses tshark filters (`dns.qry.name`, `http.host`, `tls.handshake.extensions_server_name`) to confirm the indicator and pull hard IOCs. This directly supports detection of Application Layer Protocol (T1071) C2, DNS-based signaling (T1071.004), and Exfiltration Over C2 Channel (T1041). ngrep quickly proves whether credentials or tool output traversed the network in cleartext.

## Attacker perspective
An attacker uses the same packet-level visibility, but as a defender-awareness problem: they know that unencrypted C2, cleartext credentials, and noisy scanning all leave a permanent record in any capture appliance. Offensive operators therefore encrypt beacons (TLS), blend into common ports, and use domain fronting or DNS tunneling to evade grep-style detection — yet each still leaves artifacts. TLS ClientHello SNI values, JA3-relevant handshake fields, unusual DNS TXT-record volume, periodic beacon timing, and consistent User-Agent strings all persist in pcap even when payloads are encrypted. An attacker running tshark/ngrep on a network they've tapped (e.g., after ARP poisoning) can harvest cleartext creds — Network Sniffing (T1040) — but that tap plus the resulting arp anomalies are themselves detectable artifacts for the blue team.

## Answer key
Sample sha256: `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

1. Count DNS queries and find the most frequent domain:
```bash
tshark -r exercise/sample.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn
```
Expected: a count table; the top line is the most-queried domain.

2. Full HTTP GET URI:
```bash
tshark -r exercise/sample.pcap -Y "http.request.method == \"GET\"" -T fields -e http.host -e http.request.uri
```
Expected: the host and path of the single GET request.

3. Plaintext User-Agent:
```bash
ngrep -I exercise/sample.pcap -q -W byline "User-Agent" | grep -i "User-Agent"
```
Expected: the `User-Agent:` header line from the HTTP request.

## MITRE ATT&CK & DFIR phase
- T1071 — Application Layer Protocol (HTTP/DNS/TLS C2 detection in pcap).
- T1071.004 — Application Layer Protocol: DNS.
- T1040 — Network Sniffing (offensive capture / defender detection of taps).
- T1041 — Exfiltration Over C2 Channel.
- DFIR phase: **Examination / Analysis** (deep inspection of previously collected network evidence), feeding **Identification** of IOCs.

## Sources
- Wireshark User's Guide & tshark manual — https://www.wireshark.org/docs/wsug_html_chunked/ and https://www.wireshark.org/docs/man-pages/tshark.html
- Kali Tools — Wireshark — https://www.kali.org/tools/wireshark/
- Kali Tools — ngrep — https://www.kali.org/tools/ngrep/
- REMnux docs (network analysis tools incl. tshark/ngrep) — https://docs.remnux.org/discover-the-tools/examine+network+interactions
- SANS FOR572: Advanced Network Forensics — https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response/
- Security Onion Documentation — PCAP retrieval & Zeek/Suricata — https://docs.securityonion.net/
- MITRE ATT&CK — T1071 https://attack.mitre.org/techniques/T1071/ , T1040 https://attack.mitre.org/techniques/T1040/ , T1041 https://attack.mitre.org/techniques/T1041/