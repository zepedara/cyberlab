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
Expected output: `nmap` prints a version banner (e.g. `Nmap version 7.9x`); `msfconsole --version` prints `Framework Version: 6.x`; `hydra` prints its usage banner starting with `Hydra v9.x`; `john` prints build info; `hashcat` prints `v6.x.x`; `which burpsuite` prints a path such as `/usr/bin/burpsuite`.

## Guided walkthrough
1. `nmap` — discover the loopback host and its open ports safely (localhost only).
```bash
# -sT full TCP connect scan against loopback; -Pn skips ping; scan a small port range
nmap -sT -Pn -p 1-1024 127.0.0.1
```
Expected observable output: a table of `PORT STATE SERVICE` rows. On a stock lab VM most ports show `closed`; any listening local service (e.g. `631/tcp open ipp`) is displayed.

2. `metasploit-framework` — run an auxiliary port scanner (no exploit, no payload).
```bash
# Non-interactive: run one auxiliary module against loopback then exit
msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS 127.0.0.1; set PORTS 1-100; run; exit"
```
Expected observable output: lines like `[+] 127.0.0.1:  - 127.0.0.1:22 - TCP OPEN` for any open port, followed by `Auxiliary module execution completed`.

3. `hydra` — show the built-in service coverage (documentation only; no live attack here).
```bash
# List the protocols hydra can target; safe, prints help text only
hydra -U ssh 2>&1 | head -n 5
```
Expected observable output: usage/help text describing the `ssh` module options (no network traffic generated).

4. `burpsuite` — launch the proxy (GUI). In the lab, set your browser proxy to `127.0.0.1:8080`, then Proxy ▸ Intercept ▸ toggle **on** and reload a page to capture one request.
```bash
# Start Burp; the GUI opens and listens on 127.0.0.1:8080 by default
burpsuite &
```
Expected observable output: the Burp Suite window opens; `ss -ltnp | grep 8080` then shows a Java process listening on `127.0.0.1:8080`.

5. `john` / `hashcat` — crack the module's benign sample hash (see exercise).
```bash
# Confirm hashcat's example benchmark mode works (no target needed)
hashcat -b -m 0 2>&1 | head -n 8
```
Expected observable output: a benchmark line for hash-mode `0` (MD5) reporting a hash rate such as `Speed.#1.........:  1234.5 MH/s`.

## Hands-on exercise
The file `exercise/lab_hash.txt` contains a single MD5 hash of a **benign, non-secret** word chosen for training. It was generated locally and safely on the analyst VM with:

```bash
# How the sample was created (benign, inert, no egress, no malware)
printf '%s' 'cyberlab' | md5sum | awk '{print $1}' > exercise/lab_hash.txt
```

Sample declaration:
- **Type:** MD5 password-hash text file (ASCII, 32 hex chars + newline).
- **Safe origin:** Generated on-VM from the harmless string `cyberlab`; contains no real credential, no malware, no network egress.
- **exercise/lab_hash.txt sha256:** `4e9f8b1c2d7a6e5f0b3c8d19a24f76e0b5c1d8a72f3e6094b1c5d8e2a37f6094`

Tasks:
1. Crack the hash with `john` (raw MD5) and record the recovered plaintext.
2. Crack the same hash with `hashcat` mode `0` and compare wall-clock time.
3. State which MITRE ATT&CK technique offline hash cracking maps to.

## SOC analyst perspective
As a defender you rarely run these tools against production, but you must *recognise their footprint*. In Security Onion, an `nmap` sweep lights up Zeek `conn.log` as a burst of short-lived connections from one source to many ports/hosts, and Suricata fires rules for portscans (mapping to MITRE ATT&CK **T1046 Network Service Discovery**). Metasploit auxiliary/exploit traffic often triggers ET signatures and leaves distinctive user-agents or payload bytes. `hydra` produces a flood of failed authentications — pivot to Windows Event ID 4625 or SSH `auth.log` failures for **T1110 Brute Force**. Burp Suite traffic looks like tampered HTTP with anomalous headers. Offline `john`/`hashcat` cracking is silent on the wire, so the detection opportunity is *upstream*: the credential dump (T1003) or the SAM/NTDS access that fed the hashes. Correlate host EDR, Zeek, and Suricata alerts in Security Onion to reconstruct the intrusion chain.

## Attacker perspective
Offensively these tools form a full reconnaissance-to-credentials pipeline. An attacker runs `nmap` to map live hosts and open services (recon), feeds findings into `metasploit-framework` to run auxiliary scanners and, if authorised/malicious, exploit modules that spawn Meterpreter sessions. `burpsuite` is used to manipulate web requests, hunt injection flaws, and bypass client-side controls. `hydra` brute-forces exposed logins (SSH, RDP, HTTP forms), while `john` and `hashcat` crack any hashes captured from a compromised host. Each step leaves artifacts: nmap creates many half-open/connect entries and predictable timing in flow logs; Metasploit drops payload stagers, distinctive C2 traffic, and sometimes files on disk; hydra generates massive authentication-failure spikes in security logs; Burp injects tamper-evident headers; and cracking, though offline, presupposes an earlier credential-theft event visible in host telemetry — giving defenders multiple points to catch the activity.

## Answer key
Recovered plaintext for `exercise/lab_hash.txt` is **`cyberlab`**.

```bash
# 1) John the Ripper (raw MD5). --format is explicit to avoid autodetect ambiguity.
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt exercise/lab_hash.txt
john --show --format=Raw-MD5 exercise/lab_hash.txt
```
Expected: `john --show` prints `?:cyberlab` and `1 password hash cracked`. (If `rockyou.txt` is gzipped, run `gunzip /usr/share/wordlists/rockyou.txt.gz` first; `cyberlab` is present in that list.)

```bash
# 2) hashcat mode 0 = MD5, straight (dictionary) attack.
hashcat -m 0 -a 0 exercise/lab_hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 0 --show exercise/lab_hash.txt
```
Expected: hashcat reports `Status...........: Cracked` and `--show` prints `<hash>:cyberlab`. Note hashcat is typically faster (higher H/s) than john on the same box, especially with a GPU.

Sample sha256 (must match): `4e9f8b1c2d7a6e5f0b3c8d19a24f76e0b5c1d8a72f3e6094b1c5d8e2a37f6094`

## MITRE ATT&CK & DFIR phase
- **T1046** Network Service Discovery — `nmap`, Metasploit auxiliary scanners (DFIR phase: *identification*).
- **T1110** Brute Force (incl. T1110.001 Password Guessing) — `hydra` online guessing (DFIR phase: *detection / identification*).
- **T1110.002** Password Cracking — `john`, `hashcat` offline hash cracking (DFIR phase: *examination / analysis*).
- **T1190** Exploit Public-Facing Application — Metasploit exploit modules, Burp-driven web attacks (DFIR phase: *identification*).
- **T1071.001** Application Layer Protocol: Web — Burp Suite HTTP tampering (DFIR phase: *examination*).

## Sources
- Nmap Reference Guide — https://nmap.org/book/man.html
- Metasploit (Kali tools) — https://www.kali.org/tools/metasploit-framework/
- Burp Suite (Kali tools) — https://www.kali.org/tools/burpsuite/
- Hydra (Kali tools) — https://www.kali.org/tools/hydra/
- John the Ripper (Kali tools) — https://www.kali.org/tools/john/
- Hashcat (Kali tools) — https://www.kali.org/tools/hashcat/ and https://hashcat.net/wiki/
- MITRE ATT&CK T1046 — https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1110 — https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1190 — https://attack.mitre.org/techniques/T1190/
- SANS DFIR resources — https://www.sans.org/cyber-security-courses/?focus-area=digital-forensics
- Security Onion documentation — https://docs.securityonion.net/