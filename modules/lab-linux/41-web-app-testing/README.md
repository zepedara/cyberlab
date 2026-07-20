# 41 * Web app testing (Burp Suite / nmap) -- LAB-LINUX

## Overview (plain language)
When investigators want to understand how a website or web application behaves, they need tools that can look at a server from the outside and inspect the traffic flowing to and from a browser. **nmap** is a scanner that knocks on a computer's network doors (ports) to see which services are running and answering — like walking around a building and noting which doors are unlocked. **Burp Suite** sits between your browser and a website, catching every request and reply so you can read, pause, and change them. Together they help you map what a web server exposes and study exactly what an application sends over the wire, which is essential when triaging a suspicious host or reproducing how a compromise happened.

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

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX
nmap --version
burpsuite --help 2>/dev/null | head -n 5 || echo "burpsuite launcher present"
```
Expected output: nmap prints a version banner (e.g. `Nmap version 7.94`) with the compiled/available features and library versions. The exact version depends on your distribution; the current stable series is documented on the Nmap download and changelog pages. (Nmap changelog — https://nmap.org/changelog.html; version-detection options — https://nmap.org/book/man-version-detection.html) The burpsuite line either prints launcher help or confirms the launcher is present on PATH (the Kali package installs a `burpsuite` launcher — https://www.kali.org/tools/burpsuite/).

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
Expected observable output: script results such as `| http-title: Example Site` and a list of response headers under `http-headers`. Nuance: results may include a redirect note (e.g. `http-title` reporting that the site redirected to HTTPS), and `http-headers` output varies with the server's configuration; absent headers are as informative as present ones.

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

## SOC analyst perspective
A defender uses nmap to validate exposure during triage — confirming which web ports a suspect host actually presents and whether service versions match known-vulnerable software, feeding hunt hypotheses. Burp helps IR teams safely reproduce and dissect suspicious HTTP transactions.

Concrete detection logic and pivots in **Security Onion** (Suricata + Zeek + Elastic — https://docs.securityonion.net/en/2.4/):
- **Zeek `conn.log`**: a single source IP opening many short-lived connections to many distinct destination ports in a short window is the classic port-scan signature. Pivot on `id.orig_h` (scanner), then aggregate distinct `id.resp_p` per source; high fan-out with `S0`/`REJ` connection states (SYN sent, no/again reset) indicates probing rather than normal use. (Zeek conn.log fields — https://docs.zeek.org/en/master/logs/conn.html; conn_state values — https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html)
- **Zeek `http.log`**: NSE `http-*` scripts and Burp both generate HTTP requests recorded here — pivot on `user_agent`, `uri`, `method`, and `status_code`; sequential requests to many paths, or a burst of `404`s, indicate content/path discovery. (Zeek http.log — https://docs.zeek.org/en/master/logs/http.html)
- **Suricata**: the ET/emerging-threats ruleset ships signatures that flag nmap-style scanning and known scanner user-agents; alerts land in Elastic where you pivot from the alert `source.ip` to that host's `conn.log`/`http.log`. (Suricata rules — https://docs.suricata.io/en/latest/rules/index.html; Security Onion alerts/pivoting — https://docs.securityonion.net/en/2.4/alerts.html)

MITRE ATT&CK mapping: **Active Scanning (T1595)** and its sub-technique **Scanning IP Blocks (T1595.001)** for the port/service sweep, **Network Service Discovery (T1046)** for enumerating exposed services, and **Application Layer Protocol: Web Protocols (T1071.001)** for the HTTP inspection/replay. Correlating timing, source, and alert signatures lets the SOC distinguish authorized testing from hostile reconnaissance. (T1595 — https://attack.mitre.org/techniques/T1595/; T1595.001 — https://attack.mitre.org/techniques/T1595/001/; T1046 — https://attack.mitre.org/techniques/T1046/; T1071.001 — https://attack.mitre.org/techniques/T1071/001/)

## Attacker perspective
Adversaries run nmap early to map a victim's web footprint — open ports, service banners, and NSE fingerprints reveal versions and default paths worth exploiting (**T1595.001 — Scanning IP Blocks**, **T1046 — Network Service Discovery**; https://attack.mitre.org/techniques/T1595/001/ , https://attack.mitre.org/techniques/T1046/). Burp Suite then lets attackers intercept and tamper with requests to probe authentication, injection, and parameter flaws over HTTP (**T1071.001**; https://attack.mitre.org/techniques/T1071/001/).

Concrete TTPs and the artifacts they leave:
- **Scan technique choice**: `-sS` (SYN/half-open) leaves many SYNs with no completed handshake — visible as `S0`/`REJ` in Zeek `conn.log`; `-sT` (full connect) completes handshakes and is louder in server logs. (Nmap port-scanning techniques — https://nmap.org/book/man-port-scanning-techniques.html)
- **Fingerprinting artifacts**: `-sV` and `http-*` NSE scripts generate identifiable request patterns and default probes; unauthenticated bursts of requests to common paths land in web access logs and Zeek `http.log`.
- **Tooling signatures**: default nmap/Burp `User-Agent` strings and characteristic header ordering appear in `http.log`; failed-login spikes, unusual request methods, and sequential path scanning are the trails defenders hunt.

Evasion an attacker may attempt (and its cost): timing throttles (`-T0`/`-T1`) spread probes out to slip under rate-based alerts but take far longer; decoys (`-D`) and source spoofing muddy attribution in `conn.log`; setting a benign `User-Agent` (nmap `--script-args http.useragent=...` or Burp's match/replace) blends HTTP requests into normal traffic. (Timing and performance — https://nmap.org/book/man-performance.html; firewall/IDS evasion and spoofing — https://nmap.org/book/man-bypass-firewalls-ids.html; Burp match and replace — https://portswigger.net/burp/documentation/desktop/tools/proxy/match-and-replace) None of these remove the underlying connection records; they only change volume and attribution.

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

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- nmap purpose, port states, host/port scanning, `-sV` version detection — Nmap Reference Guide: https://nmap.org/book/man.html ; port-scanning basics: https://nmap.org/book/man-port-scanning-basics.html ; version detection: https://nmap.org/book/man-version-detection.html
- nmap scan techniques (`-sS`, `-sT`), timing (`-T0..-T5`), and IDS/firewall evasion/decoys — https://nmap.org/book/man-port-scanning-techniques.html ; https://nmap.org/book/man-performance.html ; https://nmap.org/book/man-bypass-firewalls-ids.html
- nmap version banner and current release series — https://nmap.org/changelog.html
- NSE overview and http scripts (`http-title`, `http-headers`, `http-server-header`) — https://nmap.org/book/nse.html ; https://nmap.org/nsedoc/ ; https://nmap.org/nsedoc/scripts/http-title.html ; https://nmap.org/nsedoc/scripts/http-headers.html ; https://nmap.org/nsedoc/scripts/http-server-header.html
- Kali package: nmap — https://www.kali.org/tools/nmap/
- Kali package: Burp Suite (launcher) — https://www.kali.org/tools/burpsuite/
- Burp Suite proxy, default `127.0.0.1:8080` listener, editions, CA certificate install, match & replace — https://portswigger.net/burp/documentation/desktop ; https://portswigger.net/burp/documentation/desktop/tools/proxy ; https://portswigger.net/burp/documentation/desktop/tools/proxy/proxy-settings ; https://portswigger.net/burp/documentation/desktop/getting-started ; https://portswigger.net/burp/documentation/desktop/tools/proxy/manage-certificate ; https://portswigger.net/burp/documentation/desktop/tools/proxy/match-and-replace
- Python `http.server` (`-m http.server`, `--bind`) — https://docs.python.org/3/library/http.server.html
- `ss` socket-statistics utility (`-ltnp`) — https://man7.org/linux/man-pages/man8/ss.8.html
- Security Onion (Suricata/Zeek/Elastic), alerts and pivoting — https://docs.securityonion.net/en/2.4/ ; https://docs.securityonion.net/en/2.4/alerts.html
- Zeek logs used for detection (`conn.log`, `http.log`, conn_state values) — https://docs.zeek.org/en/master/logs/conn.html ; https://docs.zeek.org/en/master/logs/http.html ; https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html
- Suricata rules (scanner/User-Agent signatures) — https://docs.suricata.io/en/latest/rules/index.html
- MITRE ATT&CK: Active Scanning (T1595) — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK: Active Scanning: Scanning IP Blocks (T1595.001) — https://attack.mitre.org/techniques/T1595/001/
- MITRE ATT&CK: Network Service Discovery (T1046) — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK: Web Protocols (T1071.001) — https://attack.mitre.org/techniques/T1071/001/
- SANS: Nmap Cheat Sheet — https://www.sans.org/posters/nmap-cheat-sheet/

## Related modules
- [Offensive / network (Kali subset)](../11-offensive-kali/README.md) — shares burpsuite for web-app interception workflows.
- [Metasploit Framework workflow (training range)](../26-metasploit-workflow/README.md) — shares nmap for host/service discovery feeding exploitation.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) — same learning path (Deep-dives).
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) — same learning path (Deep-dives).

<!-- cyberlab-enriched: v1 -->
