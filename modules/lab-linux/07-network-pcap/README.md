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
1. `capinfos` / `tshark -r` — read a PCAP and get high-level stats plus a packet summary.
```bash
# Summary of the capture: packet count, time range, protocols seen
tshark -r exercise/sample.pcap -q -z io,phs | head -n 30
```
Why: `-r` reads a saved capture instead of a live interface; `-q` suppresses the normal per-packet output so only the requested statistics print; `-z io,phs` requests the Protocol Hierarchy Statistics tap. Reading the protocol tree first tells you which dissectors fired and where to focus — it is the fastest way to confirm a capture actually contains HTTP/DNS before you write filters ([tshark man page — `-r`, `-q`, `-z`](https://www.wireshark.org/docs/man-pages/tshark.html); [Wireshark statistics/protocol hierarchy docs](https://www.wireshark.org/docs/wsug_html_chunked/ChStatHierarchy.html)).
Expected: a protocol hierarchy tree (`eth:ethernet:ip:tcp:http`, `udp:dns`, etc.) with frame counts per layer. Nuance: the counts are per-layer frame counts, not byte totals, so a single HTTP request counts once at every layer it traverses.

2. `tshark` with a display filter — pull just the HTTP request hosts and URIs.
```bash
# Extract HTTP virtual host + requested URI for every request
tshark -r exercise/sample.pcap -Y 'http.request' \
  -T fields -e ip.dst -e http.host -e http.request.uri
```
Why: `-Y` applies a Wireshark **display** filter (evaluated after full dissection), so `http.request` matches only frames carrying a request line; `-T fields -e` prints the named fields as tab-separated columns for scripting. `http.host` is the virtual host from the `Host:` header, which can differ from the literal `ip.dst` when name-based virtual hosting or a proxy is in use — that mismatch is itself investigative signal ([tshark man page — `-Y`, `-T fields`, `-e`](https://www.wireshark.org/docs/man-pages/tshark.html); [Wireshark display filter reference: http](https://www.wireshark.org/docs/dfref/h/http.html)).
Expected: tab-separated rows such as `93.184.216.34  example.com  /index.html`.

3. `tshark` DNS extraction — list every domain queried.
```bash
# All DNS query names in the capture
tshark -r exercise/sample.pcap -Y 'dns.flags.response == 0' \
  -T fields -e dns.qry.name | sort -u
```
Why: `dns.flags.response == 0` selects DNS **queries** (QR bit = 0) and excludes responses, so you list what was asked rather than what was answered; `sort -u` collapses repeats from retransmits and dual A/AAAA lookups. Reviewing queried names surfaces DGA-like or high-entropy domains and possible DNS tunneling ([Wireshark display filter reference: dns](https://www.wireshark.org/docs/dfref/d/dns.html)).
Expected: a de-duplicated list of queried domains, one per line.

4. `ngrep` — search packet payloads for a cleartext pattern in the offline capture.
```bash
# Hunt for HTTP User-Agent strings inside the payloads
ngrep -I exercise/sample.pcap -q -W byline 'User-Agent'
```
Why: `-I` reads packets from a pcap file, `-q` prints only matching packets (quiet — no per-packet hash marks), and `-W byline` renders embedded line breaks so headers are readable one per line. ngrep matches against raw payload bytes, so it only finds cleartext — TLS-encrypted payloads will not match, which is a useful confirmation that a session is (or is not) encrypted ([ngrep man page — `-I`, `-q`, `-W`](https://github.com/jpr5/ngrep)).
Expected: matched packets printed with the `User-Agent: ...` line highlighted.

5. `tcpflow` — reassemble TCP streams into per-flow files for content review.
```bash
# Reassemble flows into the current directory, then list what was recovered
mkdir -p flows && tcpflow -r exercise/sample.pcap -o flows
ls -1 flows
```
Why: `-r` reads the capture and `-o` writes reconstructed streams into an output directory. tcpflow writes one file per unidirectional flow, named by source/destination IP and port, so the request stream and the response stream are separate files — this lets you carve a downloaded payload or read a full HTTP response body that is fragmented across many packets ([tcpflow man page — `-r`, `-o`, filename format](https://github.com/simsong/tcpflow)).
Expected: files named like `093.184.216.034.00080-010.000.000.010.49812` containing reassembled stream bytes. Nuance: the IP octets and ports are zero-padded in the default filename template, and each direction of the conversation is a distinct file.

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
- **HTTP C2 / suspicious User-Agent (T1071.001 — Web Protocols).** Pivot from a Suricata `alert http` signature to Zeek's `http.log`, then confirm with `tshark -Y 'http.request' -T fields -e http.host -e http.request.uri -e http.user_agent`. In Elastic/Kibana, filter on the `http.user_agent` and `http.virtual_host` fields Zeek populates. A `Host:` header that does not match the destination IP's expected service, or a rare/hard-coded User-Agent, is a strong lead ([Zeek http.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html)).
- **DNS tunneling / DGA (T1071.004 — DNS; T1568.002 — Domain Generation Algorithms).** Pivot to Zeek `dns.log` and hunt for high query volume, long labels, or high-entropy names, then reproduce with the `dns.flags.response == 0` extraction above ([Zeek dns.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html)).
- **TLS/JA3 and SNI (T1071.001, T1573 — Encrypted Channel).** When payloads are encrypted, ngrep will not match; pivot instead to Zeek's `ssl.log` for the SNI (`server_name`) and JA3/JA3S fingerprints and correlate the destination with threat intel. tshark exposes the SNI via `-e tls.handshake.extensions_server_name` ([Zeek ssl.log fields](https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html); [Wireshark display filter reference: tls](https://www.wireshark.org/docs/dfref/t/tls.html)).
- **Content reconstruction.** ngrep confirms cleartext IOCs (exfiltrated strings, beacon markers), and tcpflow reassembles the full request/response so you can carve a dropped payload and hash it. This evidence-grade extraction validates or dismisses an alert, scopes affected hosts, and feeds new detection signatures — the core of the examination phase ([MITRE ATT&CK T1071](https://attack.mitre.org/techniques/T1071/); [MITRE ATT&CK T1568](https://attack.mitre.org/techniques/T1568/)).

## Attacker perspective
An attacker who gains a network foothold uses the same capture capability for reconnaissance and credential theft — sniffing cleartext protocols (HTTP, FTP, Telnet) with ngrep or tshark to harvest passwords (**T1040 — Network Sniffing**), or reassembling sessions with tcpflow to steal transferred files and tokens ([MITRE ATT&CK T1040](https://attack.mitre.org/techniques/T1040/)). To position for capture on a switched network they commonly pair sniffing with **T1557 — Adversary-in-the-Middle** (e.g., ARP cache poisoning or LLMNR/NBT-NS/mDNS spoofing) so traffic that would not normally reach them is redirected ([MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/); [T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)). Offensively, running Wireshark/tshark against a mirrored or AiTM'd link maps internal services and protocols before pivoting.

Artifacts left for defenders:
- **Host telemetry:** the NIC entering promiscuous mode, and unexpected packet-capture processes (`tshark`, `tcpdump`, `ngrep`) — visible in process/EDR logs.
- **On the wire:** ARP-spoofing races produce duplicate/gratuitous ARP replies mapping the gateway IP to the attacker MAC (detectable in Zeek and via Suricata ARP-anomaly logic), and LLMNR/NBT-NS poisoning produces attacker responses to name-resolution broadcasts.
- **The cleartext sessions themselves** reveal both the reconnaissance targets and any credentials grabbed.

Evasion: passive sniffing generates no packets of its own and is essentially invisible on the wire, so defenders rely on host-side detection (promiscuous-mode/process monitoring) and on catching the AiTM prerequisite rather than the capture itself. Attackers further reduce cleartext exposure risk to themselves by tunneling their own C2 inside TLS or DNS (**T1573 — Encrypted Channel**, **T1071.004 — DNS**) so that a defender's ngrep sweep finds nothing ([MITRE ATT&CK T1573](https://attack.mitre.org/techniques/T1573/)).

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
- **T1568** — Dynamic Resolution (and **T1568.002** Domain Generation Algorithms for DGA hunting). https://attack.mitre.org/techniques/T1568/
- **T1557** — Adversary-in-the-Middle (prerequisite for on-switch capture / relay). https://attack.mitre.org/techniques/T1557/
- **T1573** — Encrypted Channel (attacker evasion of cleartext inspection). https://attack.mitre.org/techniques/T1573/
- **DFIR phase:** Identification → Examination (network evidence triage and content reconstruction).

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
- Zeek http.log fields: https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html
- Zeek dns.log fields: https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html
- Zeek ssl.log fields (SNI, JA3/JA3S): https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html

MITRE ATT&CK techniques:
- T1040 Network Sniffing: https://attack.mitre.org/techniques/T1040/
- T1071 Application Layer Protocol: https://attack.mitre.org/techniques/T1071/
- T1071.001 Web Protocols: https://attack.mitre.org/techniques/T1071/001/
- T1071.004 DNS: https://attack.mitre.org/techniques/T1071/004/
- T1568 Dynamic Resolution: https://attack.mitre.org/techniques/T1568/
- T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay: https://attack.mitre.org/techniques/T1557/001/
- T1573 Encrypted Channel: https://attack.mitre.org/techniques/T1573/

Sample-data provenance (documentation-only names/addresses):
- IANA reserved / special-use domain names (`example.com`, RFC 6761): https://www.iana.org/domains/reserved
- RFC 5737 — IPv4 address blocks reserved for documentation: https://datatracker.ietf.org/doc/html/rfc5737

## Related modules
- [Wireshark / tshark deep packet analysis](../24-wireshark-deep/README.md) -- shares ngrep, and goes deeper on Wireshark/tshark dissection covered here.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares tshark; applies these extraction techniques to hunting real C2 traffic.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations); complements network evidence with host disk artifacts.
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations); recovers network connections and payloads from RAM.

<!-- cyberlab-enriched: v1 -->
