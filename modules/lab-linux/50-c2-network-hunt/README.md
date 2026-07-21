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

Deliverables: the C2 IP, the beacon URI, and a YARA rule that matches the exported object.

## SOC analyst perspective
A defender ingests full-packet capture and Zeek/Suricata logs in Security Onion, then pivots to the raw PCAP for confirmation. Using tshark you rapidly triage a capture at scale — protocol hierarchy (`-z io,phs`) and conversation statistics (`-z conv,ip`) surface a low-and-slow beacon that periodic `http.request` filtering confirms.

Concrete detection logic and pivots:
- **Zeek `http.log`** (Security Onion): hunt the fixed callback path and non-browser agent, e.g. `http.uri: "/gate.php"` combined with a short `http.user_agent` like `Beacon/1.0`. Zeek's `http.log` fields (`host`, `uri`, `user_agent`, `method`, `status_code`) are documented at https://docs.zeek.org/en/master/logs/http.html.
- **Zeek `conn.log`**: pivot on `id.resp_h` (the responder/C2 IP) and look for many short-lived connections with consistent inter-arrival timing and small `orig_bytes`/`resp_bytes` — the beaconing signature. See https://docs.zeek.org/en/master/logs/conn.html.
- **Suricata**: alert on suspicious HTTP with `http.uri`/`http.user_agent` keywords; Suricata's HTTP keyword set is documented at https://docs.suricata.io/en/latest/rules/http-keywords.html. Suricata alerts and flow records land in Elastic within Security Onion (https://docs.securityonion.net/).
- **Elastic/Kibana**: pivot from a matching alert to `network.protocol: http` and aggregate by `destination.ip` and `http.request.body.content`/`user_agent.original` to scope how many hosts share the indicator.
- **YARA on carved objects**: after `--export-objects`, run YARA against the payloads to attribute the activity to a known family marker.

Map findings to ATT&CK **T1071 (Application Layer Protocol)** and **T1071.001 (Web Protocols)** for detection engineering, alert tuning, and incident scoping during an active intrusion. Encrypted beacons should also be scoped against **T1573 (Encrypted Channel)** and off-port beacons against **T1571 (Non-Standard Port)**.

## Attacker perspective
An adversary establishes C2 by having implanted malware beacon to a controller over ordinary-looking protocols (HTTP/HTTPS, DNS) to blend with normal traffic. Concrete TTPs and the artifacts they leave:
- **T1071.001 (Web Protocols):** implant sends periodic GET/POST to a fixed callback path (e.g. `/gate.php`). Artifacts: repeated same-URI requests, distinctive/short User-Agent strings, and payload markers recoverable from PCAP and matchable with YARA.
- **T1568 / T1568.002 (Dynamic Resolution / Domain Generation Algorithms):** algorithmically generated hostnames. Artifacts: bursts of NXDOMAIN responses and high-entropy domain names in Zeek `dns.log`. See https://attack.mitre.org/techniques/T1568/002/.
- **T1573 (Encrypted Channel):** TLS-wrapped beacons defeat plaintext inspection. Artifacts: consistent TLS client fingerprints (e.g. JA3) and self-signed or reused certificates in Zeek `ssl.log`/`x509.log`. See https://attack.mitre.org/techniques/T1573/.
- **T1571 (Non-Standard Port):** HTTP on an uncommon port. Artifact: protocol/port mismatch visible in `-z io,phs` and Zeek `conn.log` service inference. See https://attack.mitre.org/techniques/T1571/.
- **T1090.004 (Domain Fronting) / T1102 (Web Service):** hiding behind legitimate CDNs or SaaS. Artifact: SNI/Host header mismatch. See https://attack.mitre.org/techniques/T1090/004/ and https://attack.mitre.org/techniques/T1102/.

Evasion: attackers tune sleep timers and add jitter to defeat naive periodicity detection, rotate URIs/User-Agents, and encrypt payloads. Even so, durable signatures — fixed URIs, User-Agent artifacts, TLS/JA3 fingerprints, and payload markers — persist in captured traffic and give hunters something to pivot on across hosts.

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
- **DFIR phases:** Identification (spot beacon in traffic), Examination/Analysis (filter, export objects, YARA-confirm), Reporting (map to ATT&CK). These phases follow the SANS DFIR / FOR508 investigative workflow (https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).


### Threat Hunting & Detection Engineering

Hunt for **Exfiltration Over Alternative Protocol (T1048)** by pivoting on rare, high-volume outbound connections to non-standard ports. Use Zeek’s `conn.log` to filter for `duration > 10s` and `orig_bytes > 10MB` where `service` is not `http`, `https`, `dns`, or `smtp`. Cross-reference with Windows Event ID **5156** (Windows Filtering Platform connection) to identify processes (e.g., `powershell.exe`, `certutil.exe`) initiating these flows. For **Data Encoding (T1132.001)**, inspect `dce_rpc.log` or `smb_files.log` for base64-encoded payloads in file transfers (e.g., `*.txt` or `*.dat` with entropy > 4.5).

Leverage Suricata’s `fileinfo` keyword to detect **Non-Application Layer Protocol (T1095)** by alerting on raw TCP/UDP traffic to ports like `4444` or `8080` where `app_proto` is `failed` or `none`. Correlate with Zeek’s `notice.log` for `SSL::Invalid_Server_Cert` events, indicating covert channels. Hunt for **Process Injection (T1055.001)** by querying Windows Event ID **4688** for `CreateRemoteThread` calls from unusual parents (e.g., `wscript.exe` spawning `svchost.exe`).

**Sources:**
- [CISA: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://www.cisa.gov/resources-tools/services/detecting-post-compromise-threat-activity-microsoft-cloud-environments)
- [FireEye: Detecting and Responding to Advanced Threats with Network Traffic Analysis](https://www.fireeye.com/current-threats.html)

### Adversary Emulation & Red-Team Perspective
Adversaries may leverage the network hunting environment to their advantage by employing techniques such as [T1204](https://attack.mitre.org/techniques/T1204) - User Execution, where they trick users into executing malicious commands or scripts, and [T1218](https://attack.mitre.org/techniques/T1218) - Signed Binary Proxy Execution, which allows them to execute malicious code by proxying it through signed binaries. To achieve this, attackers may create malicious artifacts such as suspicious scripts, executable files, or modified system binaries. Network defenders should be aware of these tactics and monitor for signs of adversary emulation, such as unusual network activity or changes to system files. To evade detection, attackers may use code obfuscation or anti-debugging techniques, making it essential for defenders to employ robust detection and analysis tools. For more information on adversary emulation and red-team tactics, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [NSA Cybersecurity](https://www.nsa.gov/What-We-Do/Cybersecurity/) websites.

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
- Zeek `http.log` fields — https://docs.zeek.org/en/master/logs/http.html
- Zeek `conn.log` fields — https://docs.zeek.org/en/master/logs/conn.html
- Suricata HTTP keywords for rules — https://docs.suricata.io/en/latest/rules/http-keywords.html
- Security Onion (Zeek/Suricata/Elastic/PCAP analysis) — https://docs.securityonion.net/
- SANS FOR508 — DFIR investigative workflow and phases — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

## Related modules
- [Network / PCAP analysis](../07-network-pcap/README.md) -- shares tshark for PCAP triage and filtering.
- [Wireshark / tshark deep packet analysis](../24-wireshark-deep/README.md) -- shares tshark for deeper packet dissection and stream following.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares yara for pattern-matching carved artifacts.
- [Malware static triage](../08-malware-static-triage/README.md) -- shares yara for authoring and running detection rules.

<!-- cyberlab-enriched: v1 -->
- https://www.cisa.gov/resources-tools/services/detecting-post-compromise-threat-activity-microsoft-cloud-environments
- https://www.fireeye.com/current-threats.html
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1218
- https://www.cisa.gov/
- https://www.nsa.gov/What-We-Do/Cybersecurity/

<!-- cyberlab-enriched: v2 -->
