# 50 * Scenario: C2 network traffic hunt -- LAB-LINUX

## Overview (plain language)
Command-and-control (C2) traffic is the "phone home" chatter malware uses to talk to an attacker's server after a machine is infected. In this scenario you learn to hunt that chatter inside a captured network file (a PCAP). Wireshark is a graphical tool that lets you look at every packet on the wire, one by one, like reading a transcript of a conversation. tshark is its command-line twin, ideal for scripting and quickly summarizing large captures. YARA is a pattern-matching engine: you write simple rules that describe suspicious bytes or strings, then scan files (including data carved from a PCAP) to flag matches. Together they let a beginner spot beacons, weird domains, and known-bad payloads without guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Wireshark | apt install wireshark | GUI packet analyzer for inspecting PCAP conversations and following streams |
| tshark | apt install tshark | Command-line packet analyzer for filtering, statistics, and scripted PCAP triage |
| YARA | apt install yara | Pattern-matching engine to flag known-bad strings/bytes in files carved from traffic |

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

## Guided walkthrough
1. Build the benign practice capture and payload (see Hands-on exercise for details), then confirm the PCAP loads.
```bash
cd exercise/
# Protocol hierarchy: shows which protocols dominate the capture
tshark -r c2_hunt.pcap -q -z io,phs
```
What it does: prints a protocol tree with byte/packet counts. Expected observable output: an HTTP branch under TCP, useful for spotting the C2 channel.

2. List conversations to find a host that talks repeatedly to one destination (beacon behavior).
```bash
tshark -r exercise/c2_hunt.pcap -q -z conv,ip
```
Expected output: a table of IP pairs; the infected host 203.0.113.10 shows many small, regular exchanges with the C2 IP 198.51.100.20.

3. Filter to the suspicious HTTP requests and read the URIs and User-Agent.
```bash
tshark -r exercise/c2_hunt.pcap -Y 'http.request' \
  -T fields -e ip.dst -e http.host -e http.request.uri -e http.user_agent
```
Expected output: repeated GET requests to `/gate.php` with an unusual User-Agent, a classic beacon fingerprint.

4. Export the HTTP objects so YARA can scan the payload bytes.
```bash
mkdir -p exercise/objects
tshark -r exercise/c2_hunt.pcap --export-objects http,exercise/objects
ls -1 exercise/objects
```
Expected output: one or more extracted files (e.g. `gate.php`) written to `exercise/objects/`.

5. In Wireshark GUI (optional), open the PCAP and use "Follow > HTTP Stream" on the beacon packet to visually confirm the request/response.
```bash
wireshark exercise/c2_hunt.pcap &
```
Expected observable output: Wireshark opens; right-clicking the beacon packet and choosing Follow HTTP Stream shows the plaintext `X-C2-Beacon` marker.

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
- **Verify sample integrity** (after generation, compute and record the digest):
```bash
sha256sum exercise/c2_hunt.pcap
```

Deliverables: the C2 IP, the beacon URI, and a YARA rule that matches the exported object.

## SOC analyst perspective
A defender ingests full-packet capture and Zeek/Suricata logs in Security Onion, then pivots to the raw PCAP for confirmation. Using tshark you rapidly triage a capture at scale — protocol hierarchy and conversation statistics surface a low-and-slow beacon that periodic `http.request` filtering confirms. In Security Onion you would hunt the same `/gate.php` URI and anomalous User-Agent in Zeek `http.log`, then export objects and run YARA (or Suricata rules) against carved payloads to attribute the activity. This ties directly to ATT&CK T1071 (Application Layer Protocol) and T1071.001 (Web Protocols) for detection engineering, alert tuning, and incident scoping during an active intrusion.

## Attacker perspective
An adversary establishes C2 by having implanted malware beacon to a controller over ordinary-looking protocols (HTTP/HTTPS, DNS) to blend with normal traffic (T1071, T1571 non-standard ports, T1573 encryption). They tune jitter and sleep timers to defeat naive periodicity detection and reuse legitimate CDNs or domain fronting to hide the true destination. Artifacts left behind for defenders include repeated small requests to a fixed URI, hard-coded or algorithmically generated hostnames, distinctive User-Agent strings, TLS JA3 fingerprints, and payload markers — all recoverable from PCAP and matchable with YARA, giving hunters durable signatures to pivot on across hosts.

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
Expected output: the YARA scan prints `c2_beacon_demo <path>` for the extracted object containing the marker.

Record the sample digest produced by the generator:
```bash
sha256sum exercise/c2_hunt.pcap
```
(Digest is deterministic for a fixed `text2pcap` template; the validator holds the reference value.)

## MITRE ATT&CK & DFIR phase
- **T1071 — Application Layer Protocol**, **T1071.001 — Web Protocols**: HTTP beacon to C2.
- **T1571 — Non-Standard Port** (if beacon uses uncommon ports).
- **T1041 — Exfiltration Over C2 Channel** (if data leaves via the same channel).
- **DFIR phases:** Identification (spot beacon in traffic), Examination/Analysis (filter, export objects, YARA-confirm), Reporting (map to ATT&CK).

## Sources
- Wireshark User's Guide — https://www.wireshark.org/docs/wsug_html_chunked/
- tshark manual page — https://www.wireshark.org/docs/man-pages/tshark.html
- text2pcap manual page — https://www.wireshark.org/docs/man-pages/text2pcap.html
- YARA documentation — https://yara.readthedocs.io/en/stable/
- Kali tools: yara — https://www.kali.org/tools/yara/
- MITRE ATT&CK T1071 (Application Layer Protocol) — https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001/
- SANS: Hunting for Command and Control — https://www.sans.org/white-papers/
- Security Onion Documentation (Zeek/PCAP analysis) — https://docs.securityonion.net/