# 41 * Web app testing (Burp Suite / nmap) -- LAB-LINUX

## Overview (plain language)
When investigators want to understand how a website or web application behaves, they need tools that can look at a server from the outside and inspect the traffic flowing to and from a browser. **nmap** is a scanner that knocks on a computer's network doors (ports) to see which services are running and answering — like walking around a building and noting which doors are unlocked. **Burp Suite** sits between your browser and a website, catching every request and reply so you can read, pause, and change them. Together they help you map what a web server exposes and study exactly what an application sends over the wire, which is essential when triaging a suspicious host or reproducing how a compromise happened.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| nmap | apt install nmap | Network/port/service scanner that discovers open ports, service versions, and runs scripted checks (NSE) |
| burpsuite | apt install burpsuite | Intercepting HTTP(S) proxy for inspecting, replaying, and modifying web application traffic |

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
Expected output: nmap prints a version banner (e.g. `Nmap version 7.94`) with compiled features; the burpsuite line either prints launcher help or confirms the launcher is present on PATH.

## Guided walkthrough
1. `nmap -sV` — a service/version scan against a target to see open ports and what software answers.
```bash
# Scan a lab target host for open ports and service versions
TARGET=203.0.113.10
nmap -sV -p 80,443,8080 "$TARGET"
```
Expected observable output: a table of PORT / STATE / SERVICE / VERSION lines, e.g. `80/tcp open http Apache httpd 2.4.57`.

2. `nmap --script` — run HTTP-focused NSE scripts to grab page titles and header details.
```bash
# Fingerprint the web service with HTTP NSE scripts
TARGET=203.0.113.10
nmap -p 80,443 --script http-title,http-headers,http-server-header "$TARGET"
```
Expected observable output: script results such as `| http-title: Example Site` and a list of response headers under `http-headers`.

3. Start Burp Suite and use its proxy to capture traffic. Launch the GUI, then configure your browser to use the Burp proxy listener (default `127.0.0.1:8080`).
```bash
# Launch Burp Suite (Community); accept the temporary project and default config
burpsuite &
```
Expected observable output: the Burp GUI opens; under **Proxy > Intercept** you can toggle intercept on and see captured requests. Browsing to `http://203.0.113.10/` while intercept is on pauses the request so you can read the method, path, and headers.

4. Confirm the Burp listener is bound before browsing.
```bash
# Verify Burp's default proxy listener is up
ss -ltnp | grep 8080 || echo "start Burp and enable Proxy listener on 127.0.0.1:8080"
```
Expected observable output: a listening socket on `127.0.0.1:8080` owned by the Java/Burp process.

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
Tasks to complete:
1. Report the port/state/service nmap reports for the local server.
2. Report the `http-title` NSE script value.
3. Using Burp (browser proxied to 127.0.0.1:8080, then browsing to `http://127.0.0.1:8000/target.html`), capture and record the HTTP method and the `<title>` text in the response body.

## SOC analyst perspective
A defender uses nmap to validate exposure during triage — confirming which web ports a suspect host actually presents and whether service versions match known-vulnerable software, feeding hunt hypotheses. Burp helps IR teams safely reproduce and dissect suspicious HTTP transactions. In **Security Onion**, the same scan traffic surfaces as Zeek `conn.log`/`http.log` entries and Suricata alerts; analysts pivot on the scanner's source IP and rapid port sweeps. This maps to MITRE ATT&CK **Active Scanning (T1595)** and **Application Layer Protocol: Web (T1071.001)**, letting the SOC distinguish authorized testing from hostile reconnaissance by correlating timing, source, and alert signatures.

## Attacker perspective
Adversaries run nmap early to map a victim's web footprint — open ports, service banners, and NSE fingerprints reveal versions and default paths worth exploiting. Burp Suite lets attackers intercept and tamper with requests to probe authentication, injection, and parameter flaws. These actions leave artifacts: bursts of TCP SYNs across many ports, distinctive nmap/Burp User-Agent and header patterns in web access logs, and full request records in Zeek `http.log`. Failed-login spikes, unusual request methods, and sequential path scanning are the trails a defender hunts to attribute reconnaissance and exploitation attempts.

## Answer key
Sample sha256 (of the exact generated `exercise/target.html` above):
```bash
# Verify the sample matches
sha256sum exercise/target.html
# Expected: 3d0f... (recompute locally; the printf content is deterministic)
echo "Recompute with: printf '%s\\n' '<html>...' | sha256sum"
```
Expected findings:
- **Task 1:** `8000/tcp open http-alt` (or `http`) — `nmap -p 8000 --script http-title 127.0.0.1` shows the port open with an HTTP server.
- **Task 2:** `http-title: CyberLab Practice Page` returned by the `http-title` NSE script.
- **Task 3:** Burp captures an HTTP `GET` request to `/target.html`; the response body `<title>` is `CyberLab Practice Page` and the `<h1>` is `Benign Test`.

Because the sample is generated deterministically by the `printf` command shown, its sha256 is reproducible on any VM by rerunning the generator and `sha256sum exercise/target.html`; that digest is the authoritative check.

## MITRE ATT&CK & DFIR phase
- **T1595 / T1595.001 — Active Scanning: Scanning IP Blocks** (nmap port/service discovery). DFIR phase: **identification**.
- **T1046 — Network Service Discovery** (enumerating web services). DFIR phase: **examination**.
- **T1071.001 — Application Layer Protocol: Web Protocols** (Burp HTTP inspection/replay). DFIR phase: **examination / analysis**.

## Sources
- Nmap Reference Guide & NSE documentation — https://nmap.org/book/man.html and https://nmap.org/nsedoc/
- Kali Tools: nmap — https://www.kali.org/tools/nmap/
- Kali Tools: Burp Suite — https://www.kali.org/tools/burpsuite/
- PortSwigger Burp Suite documentation — https://portswigger.net/burp/documentation
- MITRE ATT&CK: Active Scanning (T1595) — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK: Network Service Discovery (T1046) — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK: Web Protocols (T1071.001) — https://attack.mitre.org/techniques/T1071/001/
- SANS: Nmap Cheat Sheet — https://www.sans.org/posters/nmap-cheat-sheet/