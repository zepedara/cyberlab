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
Why: `-sT` performs a full TCP *connect()* scan, which completes the three-way handshake using the OS socket API rather than crafting raw SYN packets — it needs no root privileges but is noisier and fully logged by the target (documented at https://nmap.org/book/scan-methods-connect-scan.html). `-Pn` treats the host as online and skips host discovery (ping) — appropriate for loopback and for hosts that drop ICMP (https://nmap.org/book/man-host-discovery.html). `-p 1-1024` limits the scan to the well-known/privileged port range to keep the run short. Nuance: because `-sT` uses the OS `connect()` call, each probe leaves a completed connection in the target's application logs — the opposite of the stealthy half-open `-sS` SYN scan (which never sends the final ACK). This is precisely why `-sT` is more detectable on the target and `-sS` is more detectable at the network flow layer.
Expected observable output: a table of `PORT STATE SERVICE` rows. Nmap's port states are `open`, `closed`, `filtered`, `unfiltered`, `open|filtered`, and `closed|filtered` (defined at https://nmap.org/book/man-port-scanning-basics.html). On a stock lab VM most ports show `closed`; any listening local service (e.g. `631/tcp open ipp` for CUPS) is displayed.

2. `metasploit-framework` — run an auxiliary port scanner (no exploit, no payload).
```bash
# Non-interactive: run one auxiliary module against loopback then exit
msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS 127.0.0.1; set PORTS 1-100; run; exit"
```
Why: `-q` suppresses the startup banner and `-x` runs a semicolon-separated command string then hands back control (both documented at https://docs.rapid7.com/metasploit/msfconsole-commands-tutorial/). Auxiliary modules perform scanning, fuzzing, and enumeration but do **not** deliver exploit payloads, so this step is safe and generates no shellcode. The `auxiliary/scanner/portscan/tcp` module and its `RHOSTS`/`PORTS` options are part of the Metasploit module tree (https://docs.rapid7.com/metasploit/). Nuance: the module opens sequential TCP connections just like `-sT`, so from a defender's flow record it is indistinguishable from an nmap connect scan — the *tool* is not what you detect, the *behaviour* is.
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

- **nmap sweeps (T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/).** In Security Onion, a scan lights up Zeek `conn.log` as a burst of short-lived connections from one source to many destination ports/hosts; pivot on `id.orig_h` and count distinct `id.resp_p` per source over a short window. Detection logic: TCP connect scans (`-sT`) show `conn.log` records with `conn_state` of `SF` (normal establish + teardown) or `RSTO`, and a `history` value beginning with a full handshake (e.g. `ShAdDaf`) — each port fully connected. Half-open SYN scans (`-sS`) instead leave `conn.log` records with `conn_state` `S0` (SYN sent, no reply) or `REJ` and a truncated `history` such as `S` with no completing ACK — a *high count of `S0`/`REJ` records from one `id.orig_h` to many `id.resp_p`* is a strong scan signal. Suricata portscan/scan rules (Emerging Threats `ET SCAN` category) fire on these patterns. Zeek `conn.log` field/`conn_state` reference: https://docs.zeek.org/en/master/logs/conn.html; Security Onion analysis workflow: https://docs.securityonion.net/en/2.4/.
- **Metasploit auxiliary/exploit traffic (T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/).** Often triggers ET signatures and can leave distinctive request bytes; pivot to Zeek `http.log`/`ssl.log` and Suricata alerts in the Alerts/Hunt interfaces. Hunt pivot: default Meterpreter reverse-HTTPS C2 frequently presents self-signed TLS — pivot on Zeek `ssl.log` `validation_status` values indicating a self-signed/untrusted chain and unusual `server_name` (SNI), and on `x509.log` self-signed issuer/subject matches (https://docs.zeek.org/en/master/logs/ssl.html).
- **hydra online guessing (T1110 Brute Force / T1110.001 Password Guessing — https://attack.mitre.org/techniques/T1110/001/).** Produces a flood of failed authentications. On Windows pivot to Security event **ID 4625** (an account failed to log on — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) and correlate the eventual **ID 4624** success with `LogonType 3` (network) to catch a brute-force *breakthrough*; on Linux/SSH pivot to `/var/log/auth.log` `Failed password` lines (surfaced by Security Onion, and by Zeek `ssh.log` `auth_success`/`auth_attempts` fields — https://docs.zeek.org/en/master/logs/ssh.html). Detection logic: threshold on failures-per-source-per-account per unit time; a spike of 4625 immediately followed by a 4624 from the same source IP is the highest-fidelity signal.
- **Burp/web tampering (T1071.001 Application Layer Protocol: Web — https://attack.mitre.org/techniques/T1071/001/).** Looks like HTTP with anomalous headers/methods; pivot on Zeek `http.log` `user_agent`, `method`, and `uri` fields. Hunt pivot: an unmodified Burp browser fingerprint or scanner traffic often shows repetitive `uri` fuzzing with a stable `user_agent`; sudden variation in `status_code` (many 500/403 for one client) also flags tampering.
- **Offline john/hashcat cracking (T1110.002 Password Cracking — https://attack.mitre.org/techniques/T1110/002/).** Silent on the wire, so the detection opportunity is *upstream*: the credential dump (**T1003 OS Credential Dumping** — https://attack.mitre.org/techniques/T1003/) or the SAM/NTDS access that fed the hashes. Detection logic:
  - **LSASS access (T1003.001 — https://attack.mitre.org/techniques/T1003/001/):** Sysmon **Event ID 10** (ProcessAccess) where `TargetImage` ends in `lsass.exe` and `GrantedAccess` includes memory-read masks such as `0x1010`/`0x1410` from a non-system `SourceImage` — a classic Mimikatz/procdump footprint (Sysmon reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
  - **NTDS.dit extraction (T1003.003 — https://attack.mitre.org/techniques/T1003/003/):** on a DC, watch for `ntdsutil`/`vssadmin` shadow-copy creation and access to `%SystemRoot%\NTDS\ntds.dit`; correlate Windows Security **Event ID 4688** (process creation) for `vssadmin.exe create shadow` (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688).
  - **SAM/SECURITY hive access (T1003.002 — https://attack.mitre.org/techniques/T1003/002/):** `reg save HKLM\SAM` / `HKLM\SYSTEM` command lines in 4688 or Sysmon **Event ID 1** (process creation) are a common local-hash-theft precursor.

Threat-hunting pivots to run proactively: (1) in Zeek `conn.log`, aggregate `id.orig_h` by `count(distinct id.resp_p)` and flag any internal host touching >100 ports in <60s; (2) in Elastic, build a failed-then-successful auth sequence on `winlog.event_id:4625` followed by `4624` from the same `source.ip`; (3) hunt Sysmon EID 10 targeting `lsass.exe` from unexpected parents. Correlate host EDR, Zeek, and Suricata alerts in Security Onion to reconstruct the intrusion chain.

## Attacker perspective
Offensively these tools form a full reconnaissance-to-credentials pipeline, and each stage maps to concrete ATT&CK TTPs and leaves recoverable artifacts.

- **Reconnaissance with nmap (T1046 — https://attack.mitre.org/techniques/T1046/, T1595 Active Scanning — https://attack.mitre.org/techniques/T1595/, and specifically T1595.001 Scanning IP Blocks / T1595.002 Vulnerability Scanning — https://attack.mitre.org/techniques/T1595/002/).** Maps live hosts and open services. SYN scans (`-sS`, requires root) minimise the attacker's own connection state and can slip past connection-based logging, but still generate many probe packets visible in flow logs (as bursts of `S0` half-open records in Zeek `conn.log`); timing templates (`-T0`–`-T5`, https://nmap.org/book/man-performance.html) let an attacker slow scans to evade rate-based detection. Full connect scans (`-sT`) are more likely to appear in application logs on the target. Artifacts left: target application/auth logs, firewall/flow records, and (for `-sV` version probes) distinctive service-banner requests.
- **Metasploit (T1190 exploitation, T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/, and T1071.001 web C2).** Auxiliary scanners enumerate; exploit modules can spawn Meterpreter sessions. Artifacts: payload stagers, distinctive C2 traffic, and sometimes files on disk. Evasion via encoders, staged payloads, and encrypted C2 — but network C2 remains detectable in Zeek/Suricata (e.g. self-signed TLS in `ssl.log`/`x509.log`, or beaconing periodicity in `conn.log` connection intervals).
- **Burp (T1071.001 web protocol, T1190).** Manipulates web requests, hunts injection flaws, and bypasses client-side controls. Tampered requests may carry anomalous headers/parameter ordering, a static tool `user_agent`, and repetitive `uri` fuzzing visible in Zeek `http.log`.
- **hydra (T1110 / T1110.001).** Brute-forces exposed logins (SSH, RDP, HTTP forms), generating large authentication-failure spikes (Windows 4625, Zeek `ssh.log` failed `auth_attempts`); attackers throttle attempts or spray a few passwords across many accounts (T1110.003 Password Spraying — https://attack.mitre.org/techniques/T1110/003/) to stay under lockout/alert thresholds — spraying produces *few failures per account but many distinct target accounts from one source*, an inversion of the classic guessing pattern.
- **john / hashcat (T1110.002 — https://attack.mitre.org/techniques/T1110/002/).** Crack hashes captured from a compromised host. Offline and stealthy, but presupposes an earlier credential-theft event (T1003, with sub-techniques T1003.001 LSASS Memory, T1003.002 SAM, T1003.003 NTDS — https://attack.mitre.org/techniques/T1003/003/) that is visible in host telemetry (Sysmon EID 10 on LSASS, 4688 for `vssadmin`/`reg save`) — giving defenders multiple points to catch the activity before a single hash is cracked.

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
- **T1595.002** Vulnerability Scanning — nmap `-sV`/scripting reconnaissance (DFIR phase: *identification*). https://attack.mitre.org/techniques/T1595/002/
- **T1110** Brute Force — parent technique (DFIR phase: *detection / identification*). https://attack.mitre.org/techniques/T1110/
- **T1110.001** Password Guessing — `hydra` online guessing. https://attack.mitre.org/techniques/T1110/001/
- **T1110.002** Password Cracking — `john`, `hashcat` offline hash cracking (DFIR phase: *examination / analysis*). https://attack.mitre.org/techniques/T1110/002/
- **T1110.003** Password Spraying — low-and-slow `hydra` across many accounts (DFIR phase: *identification*). https://attack.mitre.org/techniques/T1110/003/
- **T1003** OS Credential Dumping — upstream source of hashes fed to crackers (DFIR phase: *analysis*). https://attack.mitre.org/techniques/T1003/
- **T1003.001** LSASS Memory — Sysmon EID 10 on `lsass.exe` (DFIR phase: *analysis*). https://attack.mitre.org/techniques/T1003/001/
- **T1003.002** Security Account Manager — `reg save HKLM\SAM` (DFIR phase: *analysis*). https://attack.mitre.org/techniques/T1003/002/
- **T1003.003** NTDS — `ntds.dit`/`vssadmin` extraction on a DC (DFIR phase: *analysis*). https://attack.mitre.org/techniques/T1003/003/
- **T1190** Exploit Public-Facing Application — Metasploit exploit modules, Burp-driven web attacks (DFIR phase: *identification*). https://attack.mitre.org/techniques/T1190/
- **T1071.001** Application Layer Protocol: Web — Burp Suite HTTP tampering, Meterpreter HTTP(S) C2 (DFIR phase: *examination*). https://attack.mitre.org/techniques/T1071/001/
- **T1059** Command and Scripting Interpreter — Metasploit payload execution (DFIR phase: *analysis*). https://attack.mitre.org/techniques/T1059/


### Essential Commands & Features

Below are **high-impact commands and features** for `nmap` and `Metasploit` that extend the module’s core tooling with **service fingerprinting, OS detection, scripted attacks, and timing control**—critical for realistic offensive engagements.

#### **Nmap: Advanced Scanning**
- **Service Version Detection (`-sV`)**
  Identifies running services and versions, enabling precise exploit targeting.
  ```bash
  nmap -sV -p 80,443 192.168.1.1
  ```
  *Use when*: You need to map services to CVEs (e.g., outdated Apache versions).

- **OS Detection (`-O`)**
  Guesses the target OS via TCP/IP stack fingerprinting.
  ```bash
  nmap -O 192.168.1.1
  ```
  *Use when*: Tailoring payloads (e.g., Windows vs. Linux exploits).

- **Aggressive Scan (`-A`)**
  Combines `-sV`, `-O`, traceroute, and default NSE scripts for comprehensive recon.
  ```bash
  nmap -A -T4 192.168.1.1
  ```
  *Use when*: Time is limited, and you need rapid, deep enumeration.

- **NSE Scripts (`--script`)**
  Runs Nmap Scripting Engine (NSE) scripts for vulnerability checks (e.g., `vuln`, `exploit` categories).
  ```bash
  nmap --script vuln -p 445 192.168.1.1
  ```
  *Use when*: Testing for specific CVEs (e.g., EternalBlue via `smb-vuln-ms17-010`).
  **MITRE ATT&CK**: [T1592.004 Gather Victim Host Information: Client Configurations](https://attack.mitre.org/techniques/T1592/004/)

- **Timing Control (`-T4`)**
  Accelerates scans (aggressive timing) without sacrificing accuracy.
  ```bash
  nmap -T4 -p- 192.168.1.1
  ```
  *Use when*: Scanning large networks or evading rate-based detection.

#### **Metasploit: Post-Exploitation**
- **Session Interaction (`sessions -i`)**
  Lists and interacts with active Meterpreter sessions.
  ```bash
  msf6 > sessions -i 1
  ```
  *Use when*: Pivoting or executing post-exploit modules (e.g., `hashdump`).
  **MITRE ATT&CK**:

### Common Pitfalls & Result Validation

Analysts often mistake open ports for exploitable services without verifying the underlying application or patch level. For example, an Nmap version scan might report an outdated OpenSSH, but the actual daemon may be restricted or patched. This can lead to wasted effort attempting T1087 (Account Discovery) via brute-force when the service is actually providing a decoy banner. Similarly, when extracting credentials from memory dumps, analysts may assume captured NTLM hashes are immediately useful, failing to check if the accounts are disabled or the hashes match current password storage (T1555 – Credentials from Password Stores). Always validate findings with a secondary method: use `netcat` or `openssl s_client` to manually inspect banners, or cross-reference service signatures with Shodan or threat intelligence feeds. For credential validation, attempt authentication against a test account using the exact hash format to confirm it is not a stale or deprecated hash. False conclusions also arise when analysts misinterpret tool output—e.g., Metasploit's `smtp_version` auxiliary may report a server as vulnerable to CVE-2020-7247, but a manual probe shows it is patched. Validate every exploitation step by attempting the exploit in a controlled environment and verifying the outcome against the service's actual behavior.

Sources:  
- CVE Details (CVE-2020-7247): https://www.cve.org/CVERecord?id=CVE-2020-7247  
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-7247

## Sources
Claim → source mapping (all URLs are official tool docs, project repos, MITRE ATT&CK, Microsoft Learn, SANS, or Security Onion docs):

- nmap `-sT` connect scan behavior — https://nmap.org/book/scan-methods-connect-scan.html
- nmap `-sS` SYN (half-open) scan behavior — https://nmap.org/book/synscan.html
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
- Zeek conn.log fields / `conn_state` / `history` — https://docs.zeek.org/en/master/logs/conn.html
- Zeek ssl.log / x509 fields (`validation_status`, `server_name`) — https://docs.zeek.org/en/master/logs/ssl.html
- Zeek ssh.log fields (`auth_success`, `auth_attempts`) — https://docs.zeek.org/en/master/logs/ssh.html
- Sysmon (Event ID 1 process create, Event ID 10 ProcessAccess) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- MITRE ATT&CK T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1595 Active Scanning — https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1595.002 Vulnerability Scanning — https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK T1110 Brute Force — https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1110.001 Password Guessing — https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1110.002 Password Cracking — https://attack.mitre.org/techniques/T1110/002/
- MITRE ATT&CK T1110.003 Password Spraying — https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK T1003 OS Credential Dumping — https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK T1003.001 LSASS Memory — https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK T1003.002 Security Account Manager — https://attack.mitre.org/techniques/T1003/002/
- MITRE ATT&CK T1003.003 NTDS — https://attack.mitre.org/techniques/T1003/003/
- MITRE ATT&CK T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1071.001 Web Protocols — https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/
- Windows Security Event 4625 (failed logon) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Windows Security Event 4624 (successful logon / LogonType) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Windows Security Event 4688 (process creation) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- SANS DFIR resources — https://www.sans.org/cyber-security-courses/?focus-area=digital-forensics
- Security Onion documentation — https://docs.securityonion.net/en/2.4/

## Related modules
- [Metasploit Framework workflow (training range)](../26-metasploit-workflow/README.md) -- shares metasploit-framework for hands-on exploitation practice.
- [Password cracking (hashcat / John)](../40-password-cracking/README.md) -- shares hashcat and goes deeper on cracking techniques and hash types.
- [Web app testing (Burp Suite / nmap)](../41-web-app-testing/README.md) -- shares burpsuite and nmap for focused web application assessment.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same Foundations learning path, covering the disk artifacts that credential-dumping leaves behind.

<!-- cyberlab-enriched: v2 -->
- https://attack.mitre.org/techniques/T1592/004/
- https://www.cve.org/CVERecord?id=CVE-2020-7247
- https://nvd.nist.gov/vuln/detail/CVE-2020-7247

<!-- cyberlab-enriched: v3 -->
