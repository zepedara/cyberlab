# 24 * Wireshark / tshark deep packet analysis -- LAB-LINUX

## Overview (plain language)
Every time a computer talks to another computer, it sends small chunks of data called packets across the network. Wireshark, tshark, and ngrep are tools that let you capture and read those packets so you can see exactly what was sent and received. Think of it like recording every phone call on an office line and then reading a transcript. Wireshark is the graphical version with clickable menus and colors; tshark is the same engine but driven from the command line so you can script and filter it; ngrep is a simpler tool that searches packet contents for text patterns, much like the `grep` command you use on files. Analysts use these to answer questions like "what website did this machine contact?", "what data left the building?", and "is this traffic normal or an attack?" — all without touching the suspicious computer itself.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Wireshark | apt install wireshark | GUI packet capture and protocol analysis / deep dissection of pcap files |
| tshark | apt install tshark | Command-line packet analysis, filtering, and field extraction from pcaps |
| ngrep | apt install ngrep | grep-style pattern matching against live traffic or pcap payloads |

Notes on the claims above:
- Wireshark and tshark share the same dissection engine; tshark is described by the Wireshark project as "a network protocol analyzer... the command line version of Wireshark." (Wireshark tshark man page — https://www.wireshark.org/docs/man-pages/tshark.html)
- ngrep is documented as a tool that applies grep-style expressions to network packet payloads. (ngrep project — https://github.com/jpr5/ngrep and kali.org/tools/ngrep — https://www.kali.org/tools/ngrep/)

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

Notes:
- `-v`/`--version` is documented for both wireshark and tshark. (tshark man page — https://www.wireshark.org/docs/man-pages/tshark.html ; wireshark man page — https://www.wireshark.org/docs/man-pages/wireshark.html)
- `ngrep -V` prints version/compile information per the ngrep man page. (Debian ngrep man page — https://manpages.debian.org/bookworm/ngrep/ngrep.8.en.html) The exact version string (e.g. `V1.47`) depends on the packaged release; treat it as an example, not a guaranteed value.

## Guided walkthrough
1. `capinfos` — confirm the capture is readable and summarize it (packet count, duration, file hashes). This is the first triage step: it validates the file is a well-formed capture and records an integrity hash *before* you begin analysis, so any later handling can be shown not to have altered the evidence.
```bash
capinfos exercise/sample.pcap
```
Expected: a summary table showing number of packets, capture duration, data size, and file hashes. By default modern `capinfos` prints SHA256 (and historically SHA1/RIPEMD160/MD5 depending on build); use `capinfos -H` to force hash output if your build suppresses it. Confirm the SHA256 matches the value in the Answer key before trusting the analysis. (capinfos man page — https://www.wireshark.org/docs/man-pages/capinfos.html)

2. `tshark` — list every packet with a one-line summary to get oriented. Running with no display filter first prevents you from prematurely filtering out the very traffic that matters; the one-line-per-packet view is the fastest way to spot the protocol mix.
```bash
tshark -r exercise/sample.pcap -c 20
```
Expected: the first 20 packets (`-c 20` caps the count), one per line, with frame number, time, source/destination IP, protocol, and the Info column — the same summary you'd see in Wireshark's packet list. `-r` reads a saved capture rather than a live interface. (tshark man page — https://www.wireshark.org/docs/man-pages/tshark.html)

3. `tshark` — isolate DNS queries to reveal contacted domains (a common IOC source). `-Y` applies a *display filter* (Wireshark's post-dissection filter syntax), distinct from `-f` capture/BPF filters. `dns.flags.response == 0` matches query packets only (response bit clear), so you list what the host *asked for*, not what it received.
```bash
tshark -r exercise/sample.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```
Expected: one domain name per line for every DNS query in the capture. `-T fields -e <field>` emits just the chosen dissector field rather than the full summary. The field names come from the Wireshark display filter reference. (tshark man page — https://www.wireshark.org/docs/man-pages/tshark.html ; DNS display filter reference — https://www.wireshark.org/docs/dfref/d/dns.html)

4. `tshark` — pull HTTP request hosts and URIs to reconstruct web activity. `http.request` is true only on request packets, so this reconstructs the client-side browsing/beaconing without response noise.
```bash
tshark -r exercise/sample.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```
Expected: tab-separated host + path pairs for each HTTP request (multiple `-e` fields are output tab-separated by default). Note that HTTP requests carried over TLS (HTTPS) are *not* visible here without decryption keys — only cleartext HTTP appears. (HTTP display filter reference — https://www.wireshark.org/docs/dfref/h/http.html)

5. `tshark` — extract TLS Server Name Indication (SNI) values from encrypted sessions. Even when payloads are encrypted, the SNI in the ClientHello is sent in cleartext (unless Encrypted Client Hello is in use), so it is one of the highest-value IOCs available from TLS traffic you cannot decrypt.
```bash
tshark -r exercise/sample.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name
```
Expected: the destination hostnames requested inside TLS ClientHello messages. This is the field name in the current TLS dissector (older captures/tutorials may reference `ssl.handshake.extensions_server_name`). (TLS display filter reference — https://www.wireshark.org/docs/dfref/t/tls.html)

6. `ngrep` — search packet payloads for a cleartext keyword (e.g. a user-agent or credential marker). This complements tshark by matching *arbitrary byte patterns* in payloads regardless of whether Wireshark has a dissector field for them.
```bash
ngrep -I exercise/sample.pcap -q -W byline "User-Agent"
```
Expected: matching packets printed with their payloads, showing each HTTP `User-Agent` header. `-I` reads a pcap file, `-q` is quiet (only print packets that match, suppressing the per-packet `#` hash marks), and `-W byline` renders embedded line breaks so headers print readably. (ngrep man page — https://manpages.debian.org/bookworm/ngrep/ngrep.8.en.html)

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
In an incident, a defender rarely trusts the compromised host — they trust the wire. tshark and ngrep let an analyst carve command-and-control beacons, data-exfiltration flows, and lateral-movement traffic out of a Security Onion pcap without altering endpoint evidence. Security Onion runs Zeek and Suricata to produce network metadata and alerts, and stores full packet capture via Stenographer for retrieval (Security Onion docs — https://docs.securityonion.net/en/2.4/pcap.html ; Zeek — https://docs.securityonion.net/en/2.4/zeek.html ; Suricata — https://docs.securityonion.net/en/2.4/suricata.html).

Concrete detection logic and pivots:
- **DNS-based C2 / tunneling (T1071.004):** Pivot from Zeek `dns.log` (or the `dns.query` field in Elastic/Kibana) to spot high query volume to one domain, long/high-entropy labels, or heavy TXT-record use. Confirm in full pcap with `tshark -r $IMAGE -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn`. Suricata's ET rulesets carry signatures for known DNS-tunnel tooling.
- **HTTP C2 / suspicious beaconing (T1071.001):** Pivot from Zeek `http.log` (`host`, `uri`, `user_agent`) — a rare or hardcoded User-Agent, fixed URI, and regular inter-request timing are classic Cobalt-Strike-style tells. Confirm with the `http.request` field extraction from the walkthrough.
- **TLS C2 (T1071.001 / T1573 Encrypted Channel):** Pivot from Zeek `ssl.log` / `x509.log` using SNI and the JA3/JA3S fingerprint fields Zeek emits, then correlate to the ClientHello in pcap via `tls.handshake.extensions_server_name`. A JA3 hash matching known offensive tooling with a suspicious SNI is a strong lead.
- **Exfiltration over C2 (T1041):** Look for large outbound byte counts on the C2 flow in Zeek `conn.log` (`orig_bytes` vs `resp_bytes`) or Suricata flow records, then reconstruct the transfer in pcap.
- **Cleartext credentials on the wire:** `ngrep` proves whether credentials, tokens, or tool output traversed unencrypted — a direct check that supports Network Sniffing (T1040) impact assessment.
- **Ingress Tool Transfer (T1105):** Detect the download of tools or payloads by analyzing HTTP `GET` requests for known malicious URIs or file extensions (e.g., `.exe`, `.ps1`, `.dll`). In Zeek `http.log`, filter on `method=="GET"` and examine the `uri` field for suspicious patterns. In the pcap, use `tshark -Y "http.request.method == GET && http.request.uri contains .exe"` to find executable downloads. Correlate with Suricata alerts for known malicious file hashes or domains.
- **Command and Scripting Interpreter (T1059) via HTTP POST:** Identify potential command execution by searching for POST requests with encoded or obfuscated parameters. In Zeek `http.log`, look for `method=="POST"` to unusual domains with high `request_body_len`. In the pcap, use `tshark -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri` and examine payloads with `ngrep -I $IMAGE -q -W byline "cmd\|powershell\|/bin/sh"`.
- **Threat Hunting Pivot:** From a Suricata alert for a known C2 domain, retrieve the full pcap session via Security Onion's `soc` or `capme` tools. Use `tshark -r $IMAGE -Y "ip.addr == $SUSPECT_IP" -z conv,ip` to list all conversations involving that IP, then extract the JA3 fingerprint with `tshark -r $IMAGE -Y "tls.handshake.type == 1 && ip.addr == $SUSPECT_IP" -T fields -e tls.handshake.ja3_hash`. Hunt for other internal hosts with the same JA3 hash across historical Zeek `ssl.log` data.

Document each confirmed indicator (domain, IP, URI, SNI, JA3, User-Agent) as an IOC for blocking and threat-hunt retro-search. Technique IDs: T1071 (https://attack.mitre.org/techniques/T1071/), T1071.001 (https://attack.mitre.org/techniques/T1071/001/), T1071.004 (https://attack.mitre.org/techniques/T1071/004/), T1573 (https://attack.mitre.org/techniques/T1573/), T1041 (https://attack.mitre.org/techniques/T1041/), T1105 (https://attack.mitre.org/techniques/T1105/), T1059 (https://attack.mitre.org/techniques/T1059/).

## Attacker perspective
An attacker uses the same packet-level visibility, but as a defender-awareness problem: they know that unencrypted C2, cleartext credentials, and noisy scanning all leave a permanent record in any capture appliance. Offensive operators therefore encrypt beacons (TLS — Encrypted Channel, T1573.002 Asymmetric Cryptography), blend into common ports (443/80/53), and use protocol tunneling (T1572) or DNS tunneling to evade grep-style detection — yet each still leaves artifacts.

Concrete TTPs, artifacts, and evasion:
- **HTTP/HTTPS C2 (T1071.001):** Operators customize Malleable C2 profiles to mimic legitimate traffic and randomize `User-Agent`/URI. Artifacts that persist: SNI in the ClientHello (cleartext unless ECH), the TLS JA3/JA3S handshake fingerprint (unchanged by profile tweaks), certificate details in Zeek `x509.log`, and beacon *timing* regularity even under jitter.
- **DNS tunneling (T1071.004):** Encoding data into subdomains and TXT records leaves abnormally long labels, high query entropy, and elevated query volume in Zeek `dns.log` — all detectable without decrypting anything.
- **Network sniffing after a tap (T1040):** An adversary running tshark/ngrep on a network they've tapped can harvest cleartext creds, but achieving the tap via ARP cache poisoning (T1557.002) generates its own artifacts — duplicate/changing MAC-to-IP mappings and gratuitous ARP visible in the capture and in Zeek/Suricata ARP anomaly detection.
- **Evasion vs. residual signal:** Domain fronting (formerly cataloged under T1090.004) and encrypted payloads defeat payload inspection but do not hide flow metadata, SNI, JA3, or timing — which is why full-pcap + Zeek metadata retention beats payload-only searching.
- **Ingress Tool Transfer (T1105):** Attackers often stage tools via HTTP/S downloads from external servers. To evade signature-based detection, they may use compromised legitimate sites (watering holes), split payloads across multiple requests, or use non-standard ports. Artifacts include HTTP `GET` requests with unusual `User-Agent` strings (e.g., default Python-urllib) and mismatched content-type vs. file extension in Zeek `http.log`.
- **Command and Scripting Interpreter (T1059) via Web Shells:** Web shells (T1505.003) often communicate via HTTP POST with base64 or URL-encoded command parameters. While encryption (TLS) hides the payload, the pattern of frequent POST requests to a specific URI with small, regular response sizes can be detected in Zeek `http.log` via the `post_body_len` and `resp_body_len` fields. Attackers may rotate URIs or use `GET` with parameters to blend in.
- **Data Exfiltration via DNS (T1048.003):** Beyond tunneling, attackers exfiltrate data via DNS TXT or NULL record queries. This leaves a trail of high-volume, sequential queries to the same authoritative server, with request names containing encoded data (high entropy). Detection via Zeek `dns.log` focuses on `qtype_name=="TXT"` and `query` length anomalies.

Technique references: T1071.001 (https://attack.mitre.org/techniques/T1071/001/), T1071.004 (https://attack.mitre.org/techniques/T1071/004/), T1040 (https://attack.mitre.org/techniques/T1040/), T1557.002 (https://attack.mitre.org/techniques/T1557/002/), T1572 (https://attack.mitre.org/techniques/T1572/), T1573.002 (https://attack.mitre.org/techniques/T1573/002/), T1105 (https://attack.mitre.org/techniques/T1105/), T1059 (https://attack.mitre.org/techniques/T1059/), T1505.003 (https://attack.mitre.org/techniques/T1505/003/), T1048.003 (https://attack.mitre.org/techniques/T1048/003/).

## Answer key
Sample sha256: `c039d5d4db1a5d96dd80c4a321a2bdf6013428a9cf0782f780883e0b44851c77`

1. Count DNS queries and find the most frequent domain:
```bash
tshark -r exercise/sample.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn
```
Expected: a count table; the top line is the most-queried domain. The total number of DNS queries is the sum of the counts (or `... | wc -l` on the field output).

2. Full HTTP GET URI:
```bash
tshark -r exercise/sample.pcap -Y "http.request.method == \"GET\"" -T fields -e http.host -e http.request.uri
```
Expected: the host and path of the single GET request (host and URI are tab-separated; concatenate to form the full URL).

3. Plaintext User-Agent:
```bash
ngrep -I exercise/sample.pcap -q -W byline "User-Agent" | grep -i "User-Agent"
```
Expected: the `User-Agent:` header line from the HTTP request. Equivalent tshark cross-check: `tshark -r exercise/sample.pcap -Y "http.request" -T fields -e http.user_agent`.

## MITRE ATT&CK & DFIR phase
- T1071 — Application Layer Protocol (HTTP/DNS/TLS C2 detection in pcap). https://attack.mitre.org/techniques/T1071/
- T1071.001 — Application Layer Protocol: Web Protocols (HTTP/HTTPS C2). https://attack.mitre.org/techniques/T1071/001/
- T1071.004 — Application Layer Protocol: DNS. https://attack.mitre.org/techniques/T1071/004/
- T1573 / T1573.002 — Encrypted Channel / Asymmetric Cryptography (TLS C2). https://attack.mitre.org/techniques/T1573/
- T1572 — Protocol Tunneling. https://attack.mitre.org/techniques/T1572/
- T1040 — Network Sniffing (offensive capture / defender detection of taps). https://attack.mitre.org/techniques/T1040/
- T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning (tap technique). https://attack.mitre.org/techniques/T1557/002/
- T1041 — Exfiltration Over C2 Channel. https://attack.mitre.org/techniques/T1041/
- T1105 — Ingress Tool Transfer. https://attack.mitre.org/techniques/T1105/
- T1059 — Command and Scripting Interpreter. https://attack.mitre.org/techniques/T1059/
- T1505.003 — Server Software Component: Web Shell. https://attack.mitre.org/techniques/T1505/003/
- T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol. https://attack.mitre.org/techniques/T1048/003/
- DFIR phase: **Examination / Analysis** (deep inspection of previously collected network evidence), feeding **Identification** of IOCs.


### Essential Commands & Features

Mastering `tshark`’s command-line capabilities accelerates analysis and enables automation. Below are the most impactful commands and features not yet covered, with concrete examples and tactical use cases.

- **`-Y` (Read Filter)**: Apply display filters directly to reduce noise. Use when hunting for **T1021.002 (Remote Services: SMB/Windows Admin Shares)** or **T1560.001 (Archive Collected Data: Archive via Utility)**.
  ```bash
  tshark -r capture.pcap -Y "smb2.cmd == 1 && smb2.filename contains 'password'"
  ```

- **`-w` (Write PCAP)**: Save filtered traffic for later analysis or sharing. Critical for preserving evidence of **T1020 (Automated Exfiltration)**.
  ```bash
  tshark -i eth0 -f "tcp port 445" -w smb_traffic.pcap
  ```

- **`-r` (Read File)**: Process existing PCAPs without live capture. Essential for post-incident analysis.
  ```bash
  tshark -r suspicious.pcap -q -z io,phs
  ```

- **`-z` (Statistics)**: Generate summaries (e.g., protocol hierarchy, endpoints). Quickly identify anomalies like **T1571 (Non-Standard Port)**.
  ```bash
  tshark -r traffic.pcap -z endpoints,ip
  ```

- **Follow Streams**: Reconstruct TCP/UDP sessions in ASCII or hex. Vital for analyzing **T1001.003 (Data Obfuscation: Protocol Impersonation)**.
  ```bash
  tshark -r exfil.pcap -q -z follow,tcp,ascii,1
  ```

**Sources**:
- [Wireshark Man Page (tshark)](https://www.wireshark.org/docs/man-pages/tshark.html)
- [CISA Tshark Cheat Sheet](https://www.cisa.gov/sites/default/files/publications/tshark_cheat_sheet.pdf)

### Threat Hunting & Detection Engineering
To effectively hunt and detect threats, security analysts must leverage various log sources and tools. For instance, analyzing Windows Event ID 4688 (Process Creation) can help identify suspicious process executions, which may indicate the use of [T1204](https://attack.mitre.org/techniques/T1204) - User Execution or [T1218](https://attack.mitre.org/techniques/T1218) - Signed Binary Proxy Execution. By examining the `CommandLine` field in these event logs, analysts can detect potential malicious activity, such as unusual script executions or unexpected system calls. Additionally, threat hunters can pivot on suspicious network activity, like unusual DNS queries or HTTP requests, to uncover hidden threats. By integrating these detection techniques with tools like Wireshark, security teams can enhance their threat hunting capabilities and improve overall detection engineering. For more information on threat hunting and detection engineering, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) or the [National Institute of Standards and Technology (NIST)](https://www.nist.gov/) websites.

## Sources
Claim → source mapping (all URLs are official/authoritative):

- tshark flags (`-r`, `-Y`, `-c`, `-T fields`, `-e`), engine/description, `-v` — Wireshark tshark man page: https://www.wireshark.org/docs/man-pages/tshark.html
- Wireshark GUI / `--version` — Wireshark man page: https://www.wireshark.org/docs/man-pages/wireshark.html
- Wireshark general usage & display-filter concepts — Wireshark User's Guide: https://www.wireshark.org/docs/wsug_html_chunked/
- `capinfos` behavior, hash output (`-H`) — capinfos man page: https://www.wireshark.org/docs/man-pages/capinfos.html
- Display filter field names: DNS (`dns.qry.name`, `dns.flags.response`) — https://www.wireshark.org/docs/dfref/d/dns.html ; HTTP (`http.request`, `http.host`, `http.request.uri`, `http.user_agent`, `http.request.method`) — https://www.wireshark.org/docs/dfref/h/http.html ; TLS (`tls.handshake.extensions_server_name`) — https://www.wireshark.org/docs/dfref/t/tls.html
- ngrep flags (`-I`, `-q`, `-W byline`, `-V`) and grep-style payload matching — ngrep man page: https://manpages.debian.org/bookworm/ngrep/ngrep.8.en.html ; project repo: https://github.com/jpr5/ngrep
- Kali Tools — Wireshark: https://www.kali.org/tools/wireshark/ ; Kali Tools — ngrep: https://www.kali.org/tools/ngrep/
- REMnux docs (network analysis tools incl. tshark/ngrep) — https://docs.remnux.org/discover-the-tools/examine+network+interactions
- SANS FOR572: Advanced Network Forensics — https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response/
- Security Onion Documentation — PCAP retrieval: https://docs.securityonion.net/en/2.4/pcap.html ; Zeek: https://docs.securityonion.net/en/2.4/zeek.html ; Suricata: https://docs.securityonion.net/en/2.4/suricata.html
- MITRE ATT&CK techniques — T1071 https://attack.mitre.org/techniques/T1071/ ; T1071.001 https://attack.mitre.org/techniques/T1071/001/ ; T1071.004 https://attack.mitre.org/techniques/T1071/004/ ; T1573 https://attack.mitre.org/techniques/T1573/ ; T1573.002 https://attack.mitre.org/techniques/T1573/002/ ; T1572 https://attack.mitre.org/techniques/T1572/ ; T1040 https://attack.mitre.org/techniques/T1040/ ; T1557.002 https://attack.mitre.org/techniques/T1557/002/ ; T1041 https://attack.mitre.org/techniques/T1041/ ; T1105 https://attack.mitre.org/techniques/T1105/ ; T1059 https://attack.mitre.org/techniques/T1059/ ; T1505.003 https://attack.mitre.org/techniques/T1505/003/ ; T1048.003 https://attack.mitre.org/techniques/T1048/003/
- Zeek Log Documentation — conn.log, http.log, dns.log, ssl.log, x509.log fields: https://docs.zeek.org/en/master/script-reference/log-files.html
- Suricata Rule Writing — Flow and HTTP keywords: https://docs.suricata.io/en/suricata-7.0.0/rules/intro.html

## Related modules
- [Network / PCAP analysis](../07-network-pcap/README.md) -- shares ngrep for payload pattern matching against captures.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares tshark for hunting C2 flows in pcap.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives) for host-side memory evidence.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives) for signature-based detection.

<!-- cyberlab-enriched: v2 -->
- https://www.cisa.gov/sites/default/files/publications/tshark_cheat_sheet.pdf
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1218
- https://www.cisa.gov/
- https://www.nist.gov/

<!-- cyberlab-enriched: v3 -->
