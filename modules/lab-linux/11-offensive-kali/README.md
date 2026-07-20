# 11 * Offensive / network (Kali subset) -- LAB-LINUX

## Overview (plain language)
This module introduces the classic Kali "red team" toolkit for probing networks and cracking secrets. In plain terms: some tools go out and *ask questions* of a network — which computers are alive, which doors (ports) are open, and what software is listening. Others try to *guess passwords*, either by talking to a live login service or by attacking scrambled password files (hashes) offline on your own machine. `nmap` maps the network, `metasploit-framework` is a Swiss-army toolbox of exploits and helper modules, `burpsuite` sits between your browser and a website to inspect and tamper with web traffic, `hydra` tries many passwords against a live service, and `john` and `hashcat` crack password hashes offline. You use these ethically only against systems you own or are authorised to test — here, only lab targets.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| nmap | apt install nmap | Network host discovery and port/service scanning |
| metasploit-framework | apt install metasploit-framework | Exploitation framework with modules, payloads, and auxiliary scanners |
| burpsuite | apt install burpsuite | Intercepting web proxy for inspecting/modifying HTTP(S) traffic |
| hydra | apt install hydra | Online (live-service) network login brute-forcer |
| john | apt install john | Offline password-hash cracker (John the Ripper) |
| hashcat | apt install hashcat | Fast GPU/CPU offline password-hash cracker |

Notes on installation: on Kali these tools are shipped and packaged by the distribution (see the per-tool Kali pages linked in **Sources**). The Metasploit Framework is developed and documented by Rapid7 (https://docs.rapid7.com/metasploit/). Hashcat and John the Ripper are open-source projects with their own upstream docs (https://hashcat.net/wiki/ and https://www.openwall.com/john/doc/).

## Learning objectives
- Perform a controlled host/service discovery scan with `nmap` and read the results.
- Use a Metasploit **auxiliary** scanner module without launching any exploit.
- Configure `burpsuite` as an intercepting proxy and capture a single HTTP request.
- Crack a benign, self-generated password hash with both `john` and `hashcat` and compare speed.
- Explain how each tool maps to a MITRE ATT&CK technique and to a defender's detection workflow.

## Environment check
```bash
# Prove each offensive tool is installed on LAB-LINUX
nmap --version
msfconsole --version
hydra -h 2>&1 | head -n 1
john --list=build-info 2>&1 | head -n 1
hashcat --version
# burpsuite is a GUI Java app; confirm the launcher exists
which burpsuite
```
Expected output: `nmap` prints a version banner (e.g. `Nmap version 7.9x`; current stable is 7.9x per https://nmap.org/download.html); `msfconsole --version` prints `Framework Version: 6.x` (Metasploit 6 is the current major line — https://docs.rapid7.com/metasploit/); `hydra` prints its usage banner starting with `Hydra v9.x` (THC-Hydra 9.x — https://github.com/vanhauser-thc/thc-hydra); `john --list=build-info` prints John the Ripper build details (the `--list` option family is documented at https://www.openwall.com/john/doc/OPTIONS.shtml); `hashcat --version` prints `v6.x.x` (hashcat 6.x — https://hashcat.net/hashcat/); `which burpsuite` prints a path such as `/usr/bin/burpsuite` (Kali package — https://www.kali.org/tools/burpsuite/).

## Guided walkthrough
1. `nmap` — discover the loopback host and its open ports safely (localhost only).
```bash
# -sT full TCP connect scan against loopback; -Pn skips ping; scan a small port range
nmap -sT -Pn -p 1-1024 127.0.0.1
```
Why: `-sT` performs a full TCP *connect()* scan, which completes the three-way handshake using the OS socket API rather than crafting raw SYN packets — it needs no root privileges but is noisier and fully logged by the target (documented at https://nmap.org/book/scan-methods-connect-scan.html). `-Pn` treats the host as online and skips host discovery (ping) — appropriate for loopback and for hosts that drop ICMP (https://nmap.org/book/man-host-discovery.html). `-p 1-1024` limits the scan to the well-known/privileged port range to keep the run short.
Expected observable output: a table of `PORT STATE SERVICE` rows. Nmap's port states are `open`, `closed`, `filtered`, `unfiltered`, `open|filtered`, and `closed|filtered` (defined at https://nmap.org/book/man-port-scanning-basics.html). On a stock lab VM most ports show `closed`; any listening local service (e.g. `631/tcp open ipp` for CUPS) is displayed.

2. `metasploit-framework` — run an auxiliary port scanner (no exploit, no payload).
```bash
# Non-interactive: run one auxiliary module against loopback then exit
msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS 127.0.0.1; set PORTS 1-100; run; exit"
```
Why: `-q` suppresses the startup banner and `-x` runs a semicolon-separated command string then hands back control (both documented at https://docs.rapid7.com/metasploit/msfconsole-commands-tutorial/). Auxiliary modules perform scanning, fuzzing, and enumeration but do **not** deliver exploit payloads, so this step is safe and generates no shellcode. The `auxiliary/scanner/portscan/tcp` module and its `RHOSTS`/`PORTS` options are part of the Metasploit module tree (https://docs.rapid7.com/metasploit/).
Expected observable output: lines like `[+] 127.0.0.1:  - 127.0.0.1:22 - TCP OPEN` for any open port, followed by `Auxiliary module execution completed`.

3. `hydra` — show the built-in service coverage (documentation only; no live attack here).
```bash
# List the protocols hydra can target; safe, prints help text only
hydra -U ssh 2>&1 | head -n 5
```
Why: `-U` prints module-specific usage/help for the named service module (here `ssh`) and exits without contacting any host — a safe way to review supported options. The full protocol list and option syntax are documented upstream at https://github.com/vanhauser-thc/thc-hydra.
Expected observable output: usage/help text describing the `ssh` module options (no network traffic generated).

4. `burpsuite` — launch the proxy (GUI). In the lab, set your browser proxy to `127.0.0.1:8080`, then Proxy ▸ Intercept ▸ toggle **on** and reload a page to capture one request.
```bash
# Start Burp; the GUI opens and listens on 127.0.0.1:8080 by default
burpsuite &
```
Why: Burp's default Proxy listener binds to `127.0.0.1:8080`; the browser must be pointed at that listener so requests flow through Burp for inspection/modification (documented by PortSwigger at https://portswigger.net/burp/documentation/desktop/tools/proxy). Intercept holds requests so you can view/edit them before forwarding.
Expected observable output: the Burp Suite window opens; `ss -ltnp | grep 8080` then shows a Java process listening on `127.0.0.1:8080`.

5. `john` / `hashcat` — crack the module's benign sample hash (see exercise).
```bash
# Confirm hashcat's benchmark mode works (no target needed)
hashcat -b -m 0 2>&1 | head -n 8
```
Why: `-b` runs benchmark mode and `-m 0` selects hash-mode 0 = MD5, so this measures raw cracking throughput on your hardware without any target file. Hash-mode 0 = MD5 is defined in the hashcat reference (https://hashcat.net/wiki/doku.php?id=example_hashes); benchmark/attack options are in https://hashcat.net/wiki/doku.php?id=hashcat.
Expected observable output: a benchmark line for hash-mode `0` (MD5) reporting a hash rate such as `Speed.#1.........:  1234.5 MH/s` (units scale with CPU vs GPU).

## Hands-on exercise
The file `exercise/lab_hash.txt` contains a single MD5 hash of a **benign, non-secret** word chosen for training. It was generated locally and safely on the analyst VM with:

```bash
# How the sample was created (benign, inert, no egress, no malware)
printf '%s' 'cyberlab' | md5sum | awk '{print $1}' > exercise/lab_hash.txt
```

Sample declaration:
- **Type:** MD5 password-hash text file (ASCII, 32 hex chars + newline).
- **Safe origin:** Generated on-VM from the harmless string `cyberlab`; contains no real credential, no malware, no network egress.
- **exercise/lab_hash.txt sha256:** `818ed600ef221d270821b1a874576c4668251740ce27450624741b7da7df2be5`

Tasks:
1. Crack the hash with `john` (raw MD5) and record the recovered plaintext.
2. Crack the same hash with `hashcat` mode `0` and compare wall-clock time.
3. State which MITRE ATT&CK technique offline hash cracking maps to.

## SOC analyst perspective
As a defender you rarely run these tools against production, but you must *recognise their footprint*. Concrete detection logic and Security Onion pivots:

- **nmap sweeps (T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/).** In Security Onion, a scan lights up Zeek `conn.log` as a burst of short-lived connections from one source to many destination ports/hosts; pivot on `id.orig_h` and count distinct `id.resp_p` per source over a short window. TCP connect scans (`-sT`) show as complete handshakes with immediate teardown; SYN scans show many half-open attempts (`history` fields like `S` with no completion). Suricata portscan/scan rules (Emerging Threats `ET SCAN` category) fire on these patterns. Zeek log reference: https://docs.zeek.org/en/master/logs/conn.html; Security Onion analysis workflow: https://docs.securityonion.net/en/2.4/.
- **Metasploit auxiliary/exploit traffic (T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/).** Often triggers ET signatures and can leave distinctive request bytes; pivot to Zeek `http.log`/`ssl.log` and Suricata alerts in the Alerts/Hunt interfaces.
- **hydra online guessing (T1110 Brute Force / T1110.001 Password Guessing — https://attack.mitre.org/techniques/T1110/001/).** Produces a flood of failed authentications. On Windows pivot to Security event **ID 4625** (an account failed to log on — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625); on Linux/SSH pivot to `/var/log/auth.log` failures (surfaced by Security Onion). Threshold on failures-per-source-per-account per unit time.
- **Burp/web tampering (T1071.001 Application Layer Protocol: Web — https://attack.mitre.org/techniques/T1071/001/).** Looks like HTTP with anomalous headers/methods; pivot on Zeek `http.log` `user_agent`, `method`, and `uri` fields.
- **Offline john/hashcat cracking (T1110.002 Password Cracking — https://attack.mitre.org/techniques/T1110/002/).** Silent on the wire, so the detection opportunity is *upstream*: the credential dump (**T1003 OS Credential Dumping** — https://attack.mitre.org/techniques/T1003/) or the SAM/NTDS access that fed the hashes. On Windows, watch for suspicious access to `ntds.dit`/registry hives and process access to LSASS (Sysmon Event ID 10).

Correlate host EDR, Zeek, and Suricata alerts in Security Onion to reconstruct the intrusion chain.

## Attacker perspective
Offensively these tools form a full reconnaissance-to-credentials pipeline, and each stage maps to concrete ATT&CK TTPs and leaves recoverable artifacts.

- **Reconnaissance with nmap (T1046 — https://attack.mitre.org/techniques/T1046/, T1595 Active Scanning — https://attack.mitre.org/techniques/T1595/).** Maps live hosts and open services. SYN scans (`-sS`, requires root) minimise the attacker's own connection state and can slip past connection-based logging, but still generate many probe packets visible in flow logs; timing templates (`-T0`–`-T5`, https://nmap.org/book/man-performance.html) let an attacker slow scans to evade rate-based detection. Full connect scans (`-sT`) are more likely to appear in application logs on the target.
- **Metasploit (T1190 exploitation, T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/).** Auxiliary scanners enumerate; exploit modules can spawn Meterpreter sessions. Artifacts: payload stagers, distinctive C2 traffic, and sometimes files on disk. Evasion via encoders, staged payloads, and encrypted C2 — but network C2 remains detectable in Zeek/Suricata.
- **Burp (T1071.001 web protocol, T1190).** Manipulates web requests, hunts injection flaws, and bypasses client-side controls. Tampered requests may carry anomalous headers/parameter ordering.
- **hydra (T1110 / T1110.001).** Brute-forces exposed logins (SSH, RDP, HTTP forms), generating large authentication-failure spikes; attackers throttle attempts or spray a few passwords across many accounts (T1110.003 Password Spraying — https://attack.mitre.org/techniques/T1110/003/) to stay under lockout/alert thresholds.
- **john / hashcat (T1110.002 — https://attack.mitre.org/techniques/T1110/002/).** Crack hashes captured from a compromised host. Offline and stealthy, but presupposes an earlier credential-theft event (T1003) that is visible in host telemetry — giving defenders multiple points to catch the activity.

## Answer key
Recovered plaintext for `exercise/lab_hash.txt` is **`cyberlab`**.

```bash
# 1) John the Ripper (raw MD5). --format is explicit to avoid autodetect ambiguity.
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt exercise/lab_hash.txt
john --show --format=Raw-MD5 exercise/lab_hash.txt
```
Expected: `john --show` prints `?:cyberlab` and `1 password hash cracked`. The `--format`, `--wordlist`, and `--show` options are documented at https://www.openwall.com/john/doc/OPTIONS.shtml. (If `rockyou.txt` is gzipped, run `gunzip /usr/share/wordlists/rockyou.txt.gz` first; the `wordlists` package on Kali ships `rockyou.txt.gz` — https://www.kali.org/tools/wordlists/. `cyberlab` is present in that list.)

```bash
# 2) hashcat mode 0 = MD5, straight (dictionary) attack.
hashcat -m 0 -a 0 exercise/lab_hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 0 --show exercise/lab_hash.txt
```
Expected: hashcat reports `Status...........: Cracked` and `--show` prints `<hash>:cyberlab`. Mode `-m 0` = MD5 (https://hashcat.net/wiki/doku.php?id=example_hashes) and `-a 0` = straight/dictionary attack (https://hashcat.net/wiki/doku.php?id=hashcat). Note hashcat is typically faster (higher H/s) than john on the same box, especially with a GPU.

Sample sha256 (must match): `818ed600ef221d270821b1a874576c4668251740ce27450624741b7da7df2be5`

## MITRE ATT&CK & DFIR phase
- **T1046** Network Service Discovery — `nmap`, Metasploit auxiliary scanners (DFIR phase: *identification*). https://attack.mitre.org/techniques/T1046/
- **T1595** Active Scanning — external `nmap` reconnaissance (DFIR phase: *identification*). https://attack.mitre.org/techniques/T1595/
- **T1110** Brute Force — parent technique (DFIR phase: *detection / identification*). https://attack.mitre.org/techniques/T1110/
- **T1110.001** Password Guessing — `hydra` online guessing. https://attack.mitre.org/techniques/T1110/001/
- **T1110.002** Password Cracking — `john`, `hashcat` offline hash cracking (DFIR phase: *examination / analysis*). https://attack.mitre.org/techniques/T1110/002/
- **T1003** OS Credential Dumping — upstream source of hashes fed to crackers (DFIR phase: *analysis*). https://attack.mitre.org/techniques/T1003/
- **T1190** Exploit Public-Facing Application — Metasploit exploit modules, Burp-driven web attacks (DFIR phase: *identification*). https://attack.mitre.org/techniques/T1190/
- **T1071.001** Application Layer Protocol: Web — Burp Suite HTTP tampering (DFIR phase: *examination*). https://attack.mitre.org/techniques/T1071/001/

## Sources
Claim → source mapping (all URLs are official tool docs, project repos, MITRE ATT&CK, Microsoft Learn, SANS, or Security Onion docs):

- nmap `-sT` connect scan behavior — https://nmap.org/book/scan-methods-connect-scan.html
- nmap `-Pn` / host discovery — https://nmap.org/book/man-host-discovery.html
- nmap port states (`open`/`closed`/`filtered`…) — https://nmap.org/book/man-port-scanning-basics.html
- nmap timing templates (`-T0`–`-T5`) / performance — https://nmap.org/book/man-performance.html
- Nmap Reference Guide (general) — https://nmap.org/book/man.html
- Nmap current version/download — https://nmap.org/download.html
- Metasploit Framework docs (Rapid7) — https://docs.rapid7.com/metasploit/
- msfconsole `-q` / `-x` and commands — https://docs.rapid7.com/metasploit/msfconsole-commands-tutorial/
- Metasploit (Kali package) — https://www.kali.org/tools/metasploit-framework/
- Burp Suite Proxy (default 127.0.0.1:8080, intercept) — https://portswigger.net/burp/documentation/desktop/tools/proxy
- Burp Suite (Kali package) — https://www.kali.org/tools/burpsuite/
- Hydra usage / modules (THC-Hydra upstream) — https://github.com/vanhauser-thc/thc-hydra
- Hydra (Kali package) — https://www.kali.org/tools/hydra/
- John the Ripper options (`--format`, `--wordlist`, `--show`, `--list`) — https://www.openwall.com/john/doc/OPTIONS.shtml
- John the Ripper (upstream project) — https://www.openwall.com/john/
- John the Ripper (Kali package) — https://www.kali.org/tools/john/
- hashcat hash-modes / example hashes (mode 0 = MD5) — https://hashcat.net/wiki/doku.php?id=example_hashes
- hashcat options / attack modes (`-a 0`, `-b`) — https://hashcat.net/wiki/doku.php?id=hashcat
- hashcat (project + downloads) — https://hashcat.net/hashcat/
- hashcat (Kali package) — https://www.kali.org/tools/hashcat/
- rockyou wordlist (Kali package) — https://www.kali.org/tools/wordlists/
- Zeek conn.log fields — https://docs.zeek.org/en/master/logs/conn.html
- MITRE ATT&CK T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1595 Active Scanning — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1110 Brute Force — https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1110.001 Password Guessing — https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1110.002 Password Cracking — https://attack.mitre.org/techniques/T1110/002/
- MITRE ATT&CK T1110.003 Password Spraying — https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK T1003 OS Credential Dumping — https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1071.001 Web Protocols — https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/
- Windows Security Event 4625 (failed logon) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- SANS DFIR resources — https://www.sans.org/cyber-security-courses/?focus-area=digital-forensics
- Security Onion documentation — https://docs.securityonion.net/en/2.4/

## Related modules
- [Metasploit Framework workflow (training range)](../26-metasploit-workflow/README.md) -- shares metasploit-framework for hands-on exploitation practice.
- [Password cracking (hashcat / John)](../40-password-cracking/README.md) -- shares hashcat and goes deeper on cracking techniques and hash types.
- [Web app testing (Burp Suite / nmap)](../41-web-app-testing/README.md) -- shares burpsuite and nmap for focused web application assessment.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same Foundations

<!-- cyberlab-enriched: v1 -->
