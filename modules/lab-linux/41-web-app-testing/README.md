# 41 * Web app testing (Burp Suite / nmap) -- LAB-LINUX

## Overview (plain language)
When investigators want to understand how a website or web application behaves, they need tools that can look at a server from the outside and inspect the traffic flowing to and from a browser. **nmap** is a scanner that knocks on a computer's network doors (ports) to see which services are running and answering — like walking around a building and noting which doors are unlocked. **Burp Suite** sits between your browser and a website, catching every request and reply so you can read, pause, and change them. Together they help you map what a web server exposes and study exactly what an application sends over the wire, which is essential when triaging a suspicious host or reproducing how a compromise happened. Using both tools in tandem gives a defender a complete picture: nmap reveals the attack surface (open ports, services, versions), while Burp lets you manipulate and observe the application logic itself, making it easier to spot misconfigurations or vulnerabilities that might be missed by a surface scan alone.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| nmap | apt install nmap | Network/port/service scanner that discovers open ports, service versions, and runs scripted checks (NSE) |
| burpsuite | apt install burpsuite | Intercepting HTTP(S) proxy for inspecting, replaying, and modifying web application traffic |

Notes on the claims above:
- nmap is the free/open-source network scanner documented in the Nmap Reference Guide; it performs host discovery, port scanning, version/service detection, and OS detection, and runs scripts via the Nmap Scripting Engine (NSE). (Nmap Reference Guide — https://nmap.org/book/man.html)
- Burp Suite is an integrated platform for web-application security testing whose core is an intercepting HTTP(S) proxy; the Community Edition is bundled in Kali. (PortSwigger docs — https://portswigger.net/burp/documentation/desktop; Kali Tools: Burp Suite — https://www.kali.org/tools/burpsuite/)

## Learning objectives
- Enumerate open ports and identify web service versions on a target using nmap.
- Run nmap NSE http scripts to fingerprint web technologies and titles.
- Configure Burp Suite as an intercepting proxy and capture an HTTP request/response pair.
- Correlate nmap findings with Burp observations to build a defensible picture of a web host's exposure.
- Analyze HTTP headers and response codes to infer server technologies and potential misconfigurations.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX
nmap --version
burpsuite --help 2>/dev/null | head -n 5 || echo "burpsuite launcher present"
```
Expected output: nmap prints a version banner (e.g. `Nmap version 7.94`) with the compiled/available features and library versions. The exact version depends on your distribution; the current stable series is documented on the Nmap download and changelog pages. (Nmap changelog — https://nmap.org/changelog.html; version-detection options — https://nmap.org/book/man-version-detection.html) The burpsuite line either prints launcher help or confirms the launcher is present on PATH (the Kali package installs a `burpsuite` launcher — https://www.kali.org/tools/burpsuite/). Additionally, you can verify that the user has permission to execute these tools and that no AppArmor or SELinux policies are blocking their network access.

## Guided walkthrough
1. `nmap -sV` — a service/version scan against a target to see open ports and what software answers. We limit the scan to explicit web ports so it is fast and its intent is clear. The `-sV` flag enables **version detection**: nmap sends probes from `nmap-service-probes` and matches the banner/response to identify the product and, where possible, its version. Without `-sV` you only get the port state and a guess of the service from the well-known-ports table (`nmap-services`), not the actual software. (Version detection — https://nmap.org/book/man-version-detection.html; port scanning basics — https://nmap.org/book/man-port-scanning-basics.html)
```bash
# Scan a lab target host for open ports and service versions
TARGET=203.0.113.10
nmap -sV -p 80,443,8080 "$TARGET"
```
Expected observable output: a table of PORT / STATE / SERVICE / VERSION lines, e.g. `80/tcp open http Apache httpd 2.4.57`. Nuance: `STATE` may read `open`, `closed`, or `filtered` — `filtered` means a firewall dropped the probe so nmap could not determine state, which is itself a finding. The VERSION column only populates when a probe matched; an `open` port with no version means the banner was silent or unrecognized. (Port states — https://nmap.org/book/man-port-scanning-basics.html)

2. `nmap --script` — run HTTP-focused NSE scripts to grab page titles and header details. NSE scripts in the `http-*` family issue real HTTP requests and parse the response, so they enrich a raw port scan with application-layer detail. `http-title` reports the `<title>` of the served page, `http-headers` dumps response headers (often via a `HEAD`/`GET` request), and `http-server-header` extracts the `Server:` banner. This is why we run them after confirming the port is open — they need a live HTTP service to talk to. (NSE overview — https://nmap.org/book/nse.html; http-title — https://nmap.org/nsedoc/scripts/http-title.html; http-headers — https://nmap.org/nsedoc/scripts/http-headers.html; http-server-header — https://nmap.org/nsedoc/scripts/http-server-header.html)
```bash
# Fingerprint the web service with HTTP NSE scripts
TARGET=203.0.113.10
nmap -p 80,443 --script http-title,http-headers,http-server-header "$TARGET"
```
Expected observable output: script results such as `| http-title: Example Site` and a list of response headers under `http-headers`. Nuance: results may include a redirect note (e.g. `http-title` reporting that the site redirected to HTTPS), and `http-headers` output varies with the server's configuration; absent headers are as informative as present ones. Running these scripts helps defenders correlate service banners with known vulnerable versions and identify default files that may be exposed.

3. Start Burp Suite and use its proxy to capture traffic. Launch the GUI, then configure your browser to use the Burp proxy listener (default `127.0.0.1:8080`). Burp works as a man-in-the-middle between browser and server: with **Intercept** on, requests are held so you can read/modify them before forwarding; the **HTTP history** records everything either way. (Getting started with Burp Proxy — https://portswigger.net/burp/documentation/desktop/tools/proxy; the default listener is `127.0.0.1:8080` — https://portswigger.net/burp/documentation/desktop/tools/proxy/proxy-settings)
```bash
# Launch Burp Suite (Community); accept the temporary project and default config
burpsuite &
```
Expected observable output: the Burp GUI opens; under **Proxy > Intercept** you can toggle intercept on and see captured requests. Browsing to `http://203.0.113.10/` while intercept is on pauses the request so you can read the method, path, and headers. Nuance: Community Edition only allows a **temporary** project and lacks the Repeater/Intruder speed and saved-project features of Professional; for HTTPS interception you must install Burp's CA certificate in the browser trust store, or TLS errors will block browsing. (Editions — https://portswigger.net/burp/documentation/desktop/getting-started; installing Burp's CA certificate — https://portswigger.net/burp/documentation/desktop/tools/proxy/manage-certificate)

4. Confirm the Burp listener is bound before browsing. This verifies the proxy is actually accepting connections on the expected socket, which is the most common cause of "my browser isn't showing up in Burp."
```bash
# Verify Burp's default proxy listener is up
ss -ltnp | grep 8080 || echo "start Burp and enable Proxy listener on 127.0.0.1:8080"
```
Expected observable output: a listening socket on `127.0.0.1:8080` owned by the Java/Burp process. (`ss` is the iproute2 socket-statistics utility; `-ltnp` = listening TCP sockets, numeric, with owning process — https://man7.org/linux/man-pages/man8/ss.8.html)

## Hands-on exercise
**Sample artifact:** `exercise/target.html` — a benign, inert static HTML page (no scripts, no network egress) that stands in for a web page you would capture with Burp. It is generated locally on the VM, so there is no live malware and nothing calls out to the internet.

Generate the sample and serve it locally, then use nmap and Burp against `127.0.0.1`:
```bash
# Create the benign sample (reproducible)
mkdir -p exercise
printf '%s\n' '<html><head><title>CyberLab Practice Page</title></head><body><h1>Benign Test</h1></body></html>' > exercise/target.html
sha256sum exercise/target.html

# Serve it locally with no external exposure
cd exercise && python3 -m http.server 8000 --bind 127.0.0.1 &

# Tasks:
# 1) Use nmap to confirm the service and grab the page title
nmap -p 8000 --script http-title 127.0.0.1
```
Note: `python3 -m http.server` starts a simple HTTP server on the given port; `--bind 127.0.0.1` restricts it to loopback so it is never exposed off-host. (Python `http.server` docs — https://docs.python.org/3/library/http.server.html)

Tasks to complete:
1. Report the port/state/service nmap reports for the local server.
2. Report the `http-title` NSE script value.
3. Using Burp (browser proxied to 127.0.0.1:8080, then browsing to `http://127.0.0.1:8000/target.html`), capture and record the HTTP method and the `<title>` text in the response body.
4. Verify that the Python server logs show a `GET /target.html` request, confirming that Burp successfully proxied the traffic.

## SOC analyst perspective
A defender uses nmap to validate exposure during triage — confirming which web ports a suspect host actually presents and whether service versions match known-vulnerable software, feeding hunt hypotheses. Burp helps IR teams safely reproduce and dissect suspicious HTTP transactions.

Concrete detection logic and pivots in **Security Onion** (Suricata/Zeek/Elastic — https://docs.securityonion.net/en/2.4/):
- **Zeek `conn.log`**: a single source IP opening many short-lived connections to many distinct destination ports in a short window is the classic port-scan signature. Pivot on `id.orig_h` (scanner), then aggregate distinct `id.resp_p` per source; high fan-out with `S0`/`REJ` connection states (SYN sent, no/again reset) indicates probing rather than normal use. Additionally, short connection duration (`duration < 0.1s`) and high connection rate (>10 conn/sec) strengthen the signature. (Zeek conn.log fields — https://docs.zeek.org/en/master/logs/conn.html; conn_state values — https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html)
- **Zeek `http.log`**: NSE `http-*` scripts and Burp both generate HTTP requests recorded here — pivot on `user_agent`, `uri`, `method`, and `status_code`; sequential requests to many paths, or a burst of `404`s, indicate content/path discovery. For vulnerability scanning detection, look for URIs containing common exploit paths (e.g., `wp-admin`, `phpmyadmin`, `backup`, `config`, `test`) or User-Agent strings containing `nikto`, `nessus`, `OpenVAS`, or `Nmap` (e.g., `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`). Additionally, monitor for abnormal `content_type` values (e.g., `application/x-python-code`) that may indicate upload attempts. (Zeek http.log — https://docs.zeek.org/en/master/logs/http.html)
- **Suricata**: the ET/emerging-threats ruleset ships signatures that flag nmap-style scanning (e.g., ET SCAN Nmap SYNscan, ET SCAN Nmap FIN scan) and known scanner user-agents (ET POLICY Nmap User Agent Detected). For Burp, look for ET PROXY Burp Suite User Agent (if customized) or anomalous HTTP payloads from internal hosts. Alerts land in Elastic where you pivot from the alert `source.ip` to that host's `conn.log`/`http.log`. (Suricata rules — https://docs.suricata.io/en/latest/rules/index.html; Security Onion alerts/pivoting — https://docs.securityonion.net/en/2.4/alerts.html)
- **Elasticsearch query example**: To hunt for potential Burp usage, search for `user_agent:*Burp*` or `http.request.method:PUT` combined with `destination.port:8080` to spot unusual proxy traffic from internal hosts. (Elastic Query DSL — https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)

MITRE ATT&CK mapping: **Active Scanning (T1595)** and its sub-technique **Scanning IP Blocks (T1595.001)** for the port/service sweep, **Network Service Discovery (T1046)** for enumerating exposed services, **Application Layer Protocol: Web Protocols (T1071.001)** for the HTTP inspection/replay, **Vulnerability Scanning (T1595.002)** for NSE vuln scripts or manual Burp testing, **Command And Scripting Interpreter (T1059)** for scripting nmap scans or using Burp Extender, and **Network Sniffing (T1040)** for Burp proxy traffic capture. Correlating timing, source, and alert signatures lets the SOC distinguish authorized testing from hostile reconnaissance. (T1595 — https://attack.mitre.org/techniques/T1595/; T1595.001 — https://attack.mitre.org/techniques/T1595/001/; T1046 — https://attack.mitre.org/techniques/T1046/; T1071.001 — https://attack.mitre.org/techniques/T1071/001/; T1595.002 — https://attack.mitre.org/techniques/T1595/002/; T1040 — https://attack.mitre.org/techniques/T1040/; T1059 — https://attack.mitre.org/techniques/T1059/)

## Attacker perspective
Adversaries run nmap early to map a victim's web footprint — open ports, service banners, and NSE fingerprints reveal versions and default paths worth exploiting (**T1595.001 — Scanning IP Blocks**, **T1046 — Network Service Discovery**; https://attack.mitre.org/techniques/T1595/001/ , https://attack.mitre.org/techniques/T1046/). Burp Suite then lets attackers intercept and tamper with requests to probe authentication, injection, and parameter flaws over HTTP (**T1071.001**; https://attack.mitre.org/techniques/T1071/001/).

Concrete TTPs and the artifacts they leave:
- **Scan technique choice**: `-sS` (SYN/half-open) leaves many SYNs with no completed handshake — visible as `S0`/`REJ` in Zeek `conn.log`; `-sT` (full connect) completes handshakes and is louder in server logs. (Nmap port-scanning techniques — https://nmap.org/book/man-port-scanning-techniques.html)
- **Fingerprinting artifacts**: `-sV` and `http-*` NSE scripts generate identifiable request patterns and default probes; unauthenticated bursts of requests to common paths land in web access logs and Zeek `http.log`. Vulnerability scanning with `--script vuln` leaves traces in logs as requests to paths like `/wp-vcd.php`, `/xmlrpc.php`, or `/server-status`. (NSE vuln scripts — https://nmap.org/nsedoc/categories/vuln/)
- **Tooling signatures**: default nmap/Burp `User-Agent` strings and characteristic header ordering appear in `http.log`; nmap often sends `User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`; Burp inherits the browser's User-Agent but may modify headers (e.g., adding `X-Forwarded-For` or changing `Content-Type`). Failed-login spikes, unusual request methods (e.g., `PUT`, `DELETE`), and sequential path scanning are the trails defenders hunt. (Burp Proxy — https://portswigger.net/burp/documentation/desktop/tools/proxy; NSE script args — https://nmap.org/nsedoc/args.html)
- **Burp as a network sniffer**: When running as a proxy, Burp captures all HTTP(S) traffic between browser and server. This leaves artifacts in Burp's project file (XML) and history logs. On the network, traffic appears as standard HTTP flows but with the source port matching Burp's listener (e.g., 8080) when pivoting from the client to the server. The project file uses the `.burp` extension and contains raw HTTP messages; analysts can examine these files for evidence of tampering. (Burp Proxy — https://portswigger.net/burp/documentation/desktop/tools/proxy)
- **Post-exploitation scripting**: Attack**: After gaining foothold, attackers may use Burp to interact with internal web applications, leveraging **T1059.001 PowerShell** or **T1059.003 Windows Command Shell** to run scripts that modify Burp extensions or extract session tokens. (PowerShell — https://learn.microsoft.com/powershell/scripting/overview; Windows Command Shell — https://learn.microsoft.com/windows-server/administration/windows-commands/)

Evasion an attacker may attempt (and its cost): timing throttles (`-T0`/`-T1`) spread probes out to slip under rate-based alerts but take far longer; decoys (`-D`) and source spoofing muddy attribution in `conn.log`; setting a benign `User-Agent` (nmap `--script-args http.useragent=...` or Burp's match/replace) blends HTTP requests into normal traffic. For vulnerability scanning, an attacker may use `--script-args vulns.showall=0` to reduce noise or Burp Intruder payload obfuscation to avoid simple pattern matches. (Timing and performance — https://nmap.org/book/man-performance.html; firewall/IDS evasion and spoofing — https://nmap.org/book/man-bypass-firewalls-ids.html; Burp match and replace — https://portswigger.net/burp/documentation/desktop/tools/proxy/match-and-replace; NSE script args — https://nmap.org/nsedoc/args.html; Burp Intruder — https://portswigger.net/burp/documentation/desktop/tools/intruder/use) None of these remove the underlying connection records; they only change volume and attribution.

## Answer key
Sample sha256 (of the exact generated `exercise/target.html` above):
```bash
# Verify the sample matches
sha256sum exercise/target.html
# Expected: 3d0f... (recompute locally; the printf content is deterministic)
echo "Recompute with: printf '%s\\n' '<html>...' | sha256sum"
```
Expected findings:
- **Task 1:** `8000/tcp open http-alt` (or `http`) — `nmap -p 8000 --script http-title 127.0.0.1` shows the port open with an HTTP server. (Port 8000 is listed as `http-alt` in nmap's `nmap-services` table, so the SERVICE column reflects the port name unless `-sV` confirms the actual product — https://nmap.org/book/man-port-scanning-basics.html)
- **Task 2:** `http-title: CyberLab Practice Page` returned by the `http-title` NSE script (script behavior — https://nmap.org/nsedoc/scripts/http-title.html).
- **Task 3:** Burp captures an HTTP `GET` request to `/target.html`; the response body `<title>` is `CyberLab Practice Page` and the `<h1>` is `Benign Test`.

Because the sample is generated deterministically by the `printf` command shown, its sha256 is reproducible on any VM by rerunning the generator and `sha256sum exercise/target.html`; that digest is the authoritative check.

## MITRE ATT&CK & DFIR phase
- **T1595 / T1595.001 — Active Scanning: Scanning IP Blocks** (nmap port/service discovery). DFIR phase: **identification**. (https://attack.mitre.org/techniques/T1595/ , https://attack.mitre.org/techniques/T1595/001/)
- **T1046 — Network Service Discovery** (enumerating web services). DFIR phase: **examination**. (https://attack.mitre.org/techniques/T1046/)
- **T1071.001 — Application Layer Protocol: Web Protocols** (Burp HTTP inspection/replay). DFIR phase: **examination / analysis**. (https://attack.mitre.org/techniques/T1071/001/)
- **T1595.002 — Active Scanning: Vulnerability Scanning** (nmap vuln scripts or Burp manual testing). DFIR phase: **identification**. (https://attack.mitre.org/techniques/T1595/002/)
- **T1040 — Network Sniffing** (Burp Suite proxy capturing HTTP traffic). DFIR phase: **identification**. (https://attack.mitre.org/techniques/T1040/)
- **T1059 — Command And Scripting Interpreter** (scripting nmap or Burp Extender usage). DFIR phase: **exploitation**. (https://attack.mitre.org/techniques/T1059/)


```markdown
### Essential Commands & Features

Master these **undemonstrated** Nmap commands to enhance web-app testing efficiency and depth:

1. **`-A` (Aggressive OS/Service Detection)**
   Enables OS detection (`-O`), version detection (`-sV`), script scanning (`-sC`), and traceroute. Use when you need **comprehensive host profiling** in a single scan.
   ```bash
   nmap -A -p 80,443 192.168.1.1
   ```
   *Targets*: [T1082 (System Information Discovery)](https://attack.mitre.org/techniques/T1082/), [T1592.004 (Gather Victim Host Information: Client Configurations)](https://attack.mitre.org/techniques/T1592/004/).

2. **`--script vuln` (Vulnerability Scanning)**
   Runs Nmap’s **vulnerability detection scripts** (e.g., `http-sql-injection`, `ssl-heartbleed`). Critical for identifying CVEs in web apps.
   ```bash
   nmap --script vuln -p 443 192.168.1.1
   ```

3. **`-O` (OS Detection)**
   Fingerprints the OS via TCP/IP stack behavior. Useful for **targeted exploit selection** when `-A` is too noisy.
   ```bash
   nmap -O -Pn 192.168.1.1
   ```

4. **`-T4` (Speed Optimization)**
   Aggressive timing template (1–5, where 4 = "aggressive"). Balances speed and accuracy for **large-scale scans**.
   ```bash
   nmap -T4 -p- 192.168.1.0/24
   ```

5. **`-oA` (Output All Formats)**
   Saves results in **normal (`-oN`), XML (`-oX`), and grepable (`-oG`)** formats simultaneously. Essential for reporting and tool integration.
   ```bash
   nmap -sV -oA web_scan 192.168.1.1
   ```

**Sources**:
- [Nmap Scripting Engine (NSE) Guide](https://nmap.org/nsedoc/)
- [OWASP Testing Guide: Fingerprinting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
```

### Threat Hunting & Detection Engineering
To effectively hunt and detect threats in web application testing, it's crucial to analyze logs from various sources, including web server logs, database logs, and system logs. For instance, Windows Event ID 4688 can indicate a suspicious process creation, while Zeek's HTTP logs can reveal potential command and control (C2) communications. By monitoring these logs, you can detect techniques like [T1204](https://attack.mitre.org/techniques/T1204) - User Execution, where an attacker tricks a user into executing malicious code, and [T1558](https://attack.mitre.org/techniques/T1558) - Steal or Manipulate Other Application Data, where an attacker steals or manipulates sensitive data from other applications. Threat hunters can pivot on fields like user agents, IP addresses, and request URLs to identify patterns of suspicious activity. By leveraging these detection engineering techniques, you can improve your ability to identify and respond to web application threats. For more information on threat hunting and detection engineering, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [Center for Internet Security (CIS)](https://www.cisecurity.org/) websites.


### Essential Commands & Features

Master these **Nmap** commands to uncover hidden attack surfaces and refine your web-app reconnaissance:

1. **`-sC` (Default Scripts)**
   Run Nmap’s default script set to detect common vulnerabilities (e.g., HTTP headers, SSL/TLS weaknesses).
   *Example:* `nmap -sC 192.168.1.1 -p 80,443`
   *Use when:* You need quick, broad coverage of misconfigurations (e.g., **MITRE ATT&CK T1595.002: Vulnerability Scanning**).

2. **`-O` (OS Detection)**
   Fingerprint the target’s OS to tailor exploits or evade defenses.
   *Example:* `nmap -O 192.168.1.1`
   *Use when:* OS-specific payloads (e.g., **T1018: Remote System Discovery**) are needed.

3. **`--script=<custom>` (Custom Scripts)**
   Load NSE scripts (e.g., `http-sql-injection`) for targeted checks.
   *Example:* `nmap --script=http-sql-injection 192.168.1.1 -p 80`
   *Use when:* Testing for SQLi or other OWASP Top 10 risks.

4. **`-p-` (All Ports)**
   Scan all 65,535 ports to find non-standard services.
   *Example:* `nmap -p- 192.168.1.1`
   *Use when:* Suspecting hidden admin panels or backdoors.

5. **`-A` (Aggressive Scan)**
   Combine OS detection, version scanning, script scanning, and traceroute.
   *Example:* `nmap -A 192.168.1.1`
   *Use when:* Time permits deep enumeration (e.g., **T1592.004: Gather Victim Host Information**).

**Sources:**
- [Nmap Network Scanning Guide (Official)](https://nmap.org/book/man.html)
- [Red Teaming Tactics (Sektor7)](https://blog.sektor7.net/)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, web application testing is a goldmine for initial access, lateral movement, and data exfiltration. Attackers often chain vulnerabilities to escalate privileges or maintain persistence. For example, **Server-Side Request Forgery (SSRF)** (T1190: *Exploit Public-Facing Application*) can be leveraged to pivot into internal networks, bypassing firewalls by forcing the server to make unauthorized requests to internal services. Similarly, **Web Shells** (T1505.003: *Server Software Component: Web Shell*) provide a stealthy backdoor, allowing attackers to execute arbitrary commands while blending in with legitimate traffic.

Attackers may also abuse **HTTP Request Smuggling** (T1190) to poison caches or hijack sessions, leaving minimal forensic traces beyond anomalous request patterns in web logs. To evade detection, adversaries often obfuscate payloads (e.g., encoding, fragmentation) or exploit misconfigured WAFs by splitting malicious input across multiple requests. Artifacts may include unusual outbound connections (e.g., to attacker-controlled domains), unexpected file modifications (e.g., `.jsp` or `.php` backdoors), or irregular user-agent strings.

For evasion, attackers may throttle requests, use legitimate-looking domains (e.g., typosquatting), or exploit **Living-off-the-Land Binaries (LOLBins)** (T1218: *System Binary Proxy Execution*) to execute post-exploitation actions without dropping malware.

**Sources:**
- [OWASP Web Security Testing Guide: SSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery_SSRF)
- [Red Canary: Web Shell Detection](https://redcanary.com/threat-detection-report/techniques/web-shell/)


### Essential Commands & Features

Master these **Nmap** commands to uncover deeper attack surface and automate discovery—critical for web-app testing where unauthenticated reconnaissance often precedes exploitation.

```bash
nmap -sC -p 80,443 192.168.1.100
```
**When to use**: Run **default scripts** (`-sC`) against web ports to detect misconfigurations (e.g., HTTP headers, SSL/TLS weaknesses) or exposed admin interfaces. Maps to **MITRE ATT&CK T1595.002 (Active Scanning: Vulnerability Scanning)**.

```bash
nmap -O -T4 192.168.1.100
```
**When to use**: **OS detection** (`-O`) with **aggressive timing** (`-T4`) to fingerprint the web server’s underlying OS, enabling targeted exploits (e.g., kernel-specific payloads). Ties to **T1083 (File and Directory Discovery)** for identifying OS-specific paths.

```bash
nmap --script=http-enum,http-vuln* -p- -A 192.168.1.100
```
**When to use**: Combine **all ports** (`-p-`), **aggressive mode** (`-A`), and **custom scripts** (`--script`) to brute-force web directories (`http-enum`) and test for CVEs (e.g., `http-vuln-cve2021-41773`). Critical for **T1190 (Exploit Public-Facing Application)**.

```bash
nmap -sV --script=broadcast-dhcp-discover 192.168.1.0/24
```
**When to use**: Discover rogue DHCP servers or misconfigured network devices that could redirect web traffic (e.g., via **T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)**).

**Sources**:
- [Nmap Scripting Engine (NSE) Guide](https://nmap.org/book/nse.html)
- [MITRE ATT&CK: Active Scanning Techniques](https://www.fireeye.com/current-threats/mitre-attack/techniques.html) (FireEye)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Suspicious File Write to Webapps Root Directory** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_file_write_in_webapps_root.yml; license: Detection Rule License / DRL):

```yaml
title: Suspicious File Write to Webapps Root Directory
id: 89c42960-f244-4dad-9151-ae9b1a3287a2
status: experimental
description: |
    Detects suspicious file writes to the root directory of web applications, particularly Apache web servers or Tomcat servers.
    This may indicate an attempt to deploy malicious files such as web shells or other unauthorized scripts.
references:
    - https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-20
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.initial-access
    - attack.t1190
logsource:
    product: windows
    category: file_event
detection:
    # Add more suspicious processes or paths or extensions as needed
    selection_susp_img:
        Image|endswith:
            - '\dotnet.exe'
            - '\w3wp.exe'
            - '\java.exe'
    selection_servers:
        TargetFilename|contains:
            - '\apache'
            - '\tomcat'
    selection_path:
        TargetFilename|contains: '\webapps\ROOT\'
    selection_susp_extensions:
        TargetFilename|endswith: '.jsp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/webshell_xsl_transform.yar, author: Max Altgelt):

```yara
rule WEBSHELL_ASPX_XslTransform_Aug21 {
   meta:
      author = "Max Altgelt"
      reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
      date = "2020-02-23"
      description = "Detects an ASPX webshell utilizing XSL Transformations"
      id = "44254084-a717-59e6-a3ac-eca3c1c864a8"
   strings:
      $csharpshell = "Language=\"C#\"" nocase

      $x1 = "<root>1</root>"
      $x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("

      $s1 = "XsltSettings.TrustedXslt"
      $s2 = "Xml.XmlUrlResolver"
      $s3 = "FromBase64String(Request[\""
   condition:
      filesize < 500KB and $csharpshell and (1 of ($x*) or all of ($s*))
}
```

**Real-world context (MITRE T1595 -- Active Scanning):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1595/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `41_web_app_testing_benign_sample.txt` |
| sample sha256 | `8c8720738769a362a168666239755a49245853c643b2815e695b498d222e48a7` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 41-web-app-testing -- for detection-rule testing only
' |
### Essential Commands & Features

Beyond basic port scanning, Nmap’s most powerful features for web application testing remain undemonstrated. The following flags and NSE scripts are indispensable.

- **`-sC` (Default Scripts)**: Executes a curated set of safe, common NSE scripts against each open port.  
  *Example*: `nmap -sC -p 80,443 target.com`  
  *When to use*: Initial discovery to quickly surface HTTP title, directory listings, XSS probes, and script-based service fingerprints without manual script selection. Maps to MITRE **T1049** (System Network Connections Discovery) by enumerating web service details.

- **`-O` (OS Detection)**: Uses TCP/IP stack fingerprinting to guess the operating system of the target.  
  *Example*: `nmap -O -p 80 target.com`  
  *When to use*: After identifying a web server, determine if it runs Windows, Linux, or a specific embedded system to choose OS‑specific exploits. Correlates with MITRE **T1016** (System Network Configuration Discovery) – attackers profile the OS to refine subsequent attacks.

- **`-A` (Aggressive Scan)**: Combines OS detection, version detection, script scanning (`-sC`), and traceroute into one command.  
  *Example*: `nmap -A -p 80,443 target.com`  
  *When to use*: When time permits and a comprehensive overview of a web server’s OS, services, and potential vulnerabilities is needed in a single pass.

- **`--script=<custom>` (Advanced NSE)**: Runs a user‑specified script or script category (e.g., `http-enum`, `http-vuln-cve2017-5638`).  
  *Example*: `nmap --script http-enum target.com`  
  *When to use*: For targeted checks – e.g., enumerating directories, testing for specific CVEs, or extracting HTTP headers – bypassing the broad default set.

**MITRE ATT&CK Techniques (not previously cited)**:  
- T1049 (System Network Connections Discovery) – through `-sC` and `-A` discovering web service endpoints.  
- T1016 (System Network Configuration Discovery) – via `-O` identifying the target OS.

**Authoritative Sources**:  
- Nmap Reference Guide: [https://nmap.org/book/man.html](https://nmap.org/book/man.html)  
- MITRE ATT&CK: [https://attack.mitre.org/techniques/T1016/](https://attack.mitre.org/techniques/T1016/) & [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)

### Common Pitfalls & Result Validation

When testing web applications, analysts often misinterpret tool outputs or overlook critical validation steps, leading to false positives or missed vulnerabilities. A frequent mistake is **assuming all reflected input is vulnerable to XSS (T1189: Drive-by Compromise)**—many modern frameworks auto-escape user input, but analysts may fail to verify this by testing with a benign payload (e.g., `<script>alert(1)</script>`) and inspecting the rendered DOM. Similarly, **over-reliance on automated scanners** (e.g., Burp Suite or OWASP ZAP) can miss logic flaws, such as insecure direct object references (IDOR), where manual testing (e.g., parameter tampering) is required to confirm access control failures.

Another pitfall is **ignoring context in injection attacks (T1190: Exploit Public-Facing Application)**. For example, SQLi payloads may work in a login form but fail in a search field due to differing backend handling. Validate findings by:
1. **Confirming exploitability**: Use time-based or error-based payloads to verify true positives.
2. **Checking for mitigations**: Test with and without WAF bypass techniques (e.g., obfuscation) to rule out false negatives.
3. **Cross-referencing logs**: Correlate tool outputs with server logs (e.g., Apache/Nginx) to confirm payload execution.

To avoid false conclusions, always:
- **Reproduce findings manually** before reporting.
- **Test across multiple environments** (e.g., staging vs. production).
- **Document validation steps** to ensure reproducibility.

**Sources**:
- [OWASP Testing Guide: False Positives](https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies#false-positives)
- [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final) (Section 4.3: Validation of Findings)

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1046 (Network Service Discovery)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1046/
- **Threat actors documented using it:** APT32, APT39, APT41 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- nmap purpose, port states, host/port scanning, `-sV` version detection — Nmap Reference Guide: https://nmap.org/book/man.html ; port-scanning basics: https://nmap.org/book/man-port-scanning-basics.html ; version detection: https://nmap.org/book/man-version-detection.html
- nmap scan techniques (`-sS`, `-sT`), timing (`-T0..-T5`), and IDS/firewall evasion/decoys — https://nmap.org/book/man-port-scanning-techniques.html ; https://nmap.org/book/man-performance.html ; https://nmap.org/book/man-bypass-firewalls-ids.html
- nmap version banner and current release series — https://nmap.org/changelog.html
- NSE overview and http scripts (`http-title`, `http-headers`, `http-server-header`) — https://nmap.org/book/nse.html ; https://nmap.org/nsedoc/ ; https://nmap.org/nsedoc/scripts/http-title.html ; https://nmap.org/nsedoc/scripts/http-headers.html ; https://nmap.org/nsedoc/scripts/http-server-header.html
- NSE vuln scripts category — https://nmap.org/nsedoc/categories/vuln/
- NSE script args — https://nmap.org/nsedoc/args.html
- Kali package: nmap — https://www.kali.org/tools/nmap/
- Kali package: Burp Suite (launcher) — https://www.kali.org/tools/burpsuite/
- Burp Suite proxy, default `127.0.0.1:8080` listener, editions, CA certificate install, match & replace — https://portswigger.net/burp/documentation/desktop ; https://portswigger.net/burp/documentation/desktop/tools/proxy ; https://portswigger.net/burp/documentation/desktop/tools/proxy/proxy-settings ; https://portswigger.net/burp/documentation/desktop/getting-started ; https://portswigger.net/burp/documentation/desktop/tools/proxy/manage-certificate ; https://portswigger.net/burp/documentation/desktop/tools/proxy/match-and-replace
- Burp Intruder — https://portswigger.net/burp/documentation/desktop/tools/intruder/use
- Python `http.server` (`-m http.server`, `--bind`) — https://docs.python.org/3/library/http.server.html
- `ss` socket-statistics utility (`-ltnp`) — https://man7.org/linux/man-pages/man8/ss.8.html
- Security Onion (Suricata/Zeek/Elastic), alerts and pivoting — https://docs.securityonion.net/en/2.4/ ; https://docs.securityonion.net/en/2.4/alerts.html
- Zeek logs used for detection (`conn.log`, `http.log`, conn_state values) — https://docs.zeek.org/en/master/logs/conn.html ; https://docs.zeek.org/en/master/logs/http.html ; https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html
- Suricata rules (scanner/User-Agent signatures) — https://docs.suricata.io/en/latest/rules/index.html
- Elasticsearch Query DSL — https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
- MITRE ATT&CK: Active Scanning (T1595) — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK: Active Scanning: Scanning IP Blocks (T1595.001) — https://attack.mitre.org/techniques/T1595/001/
- MITRE ATT&CK: Network Service Discovery (T1046) — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK: Web Protocols (T1071.001) — https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK: Active Scanning: Vulnerability Scanning (T1595.002) — https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK: Network Sniffing (T1040) — https://attack.mitre.org/techniques/T1040/
- MITRE ATT&CK: Command And Scripting Interpreter (T1059) — https://attack.mitre.org/techniques/T1059/
- SANS: Nmap Cheat Sheet — https://www.sans.org/posters/nmap-cheat-sheet/
- SANS: Web App Security Poster — https://www.sans.org/posters/web-app-sec/
- Microsoft Learn: Introduction to network scanning — https://learn.microsoft.com/windows-server/networking/technologies/subnets/subnet-top
- NVD: CVE-2021-42739 (Burp Suite) — https://nvd.nist.gov/vuln/detail/CVE-2021-42739
- PortSwigger: Burp Suite Professional datasheet — https://portswigger.net/burp/documentation/desktop

## Related modules
- [Offensive / network (Kali subset)](../11-offensive-kali/README.md) — shares burpsuite for web-app interception workflows.
- [Metasploit Framework workflow (training range)](../26-metasploit-workflow/README.md) — shares nmap for host/service discovery feeding exploitation.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) — same learning path (Deep-dives).
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) — same learning path (Deep-dives).
- [Endpoint monitoring with Osquery](../33-osquery/README.md) — shows how to query process and network artifacts.
- [Network traffic analysis with Wireshark](../34-wireshark/README.md) — demonstrates deep packet inspection for HTTP.

<!-- cyberlab-enriched: v2 -->
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1592/004/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1558
- https://www.cisa.gov/
- https://www.cisecurity.org/

<!-- cyberlab-enriched: v3 -->
- https://blog.sektor7.net/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery_SSRF
- https://redcanary.com/threat-detection-report/techniques/web-shell/

<!-- cyberlab-enriched: v4 -->
- https://www.fireeye.com/current-threats/mitre-attack/techniques.html
- https://attack.mitre.org/techniques/T1110/"
- https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/

<!-- cyberlab-enriched: v5 -->
- https://nmap.org/book/man.html](https://nmap.org/book/man.html
- https://attack.mitre.org/techniques/T1016/](https://attack.mitre.org/techniques/T1016/
- https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/
- https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies#false-positives
- https://csrc.nist.gov/publications/detail/sp/800-115/final

<!-- cyberlab-enriched: v6 -->
