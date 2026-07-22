# 40 * Password cracking (hashcat / John) -- LAB-LINUX

## Overview (plain language)
Passwords are almost never stored as plain text. Instead systems store a scrambled "fingerprint" of the password called a hash. When investigators recover these hashes from a disk image, database dump, or captured network traffic, they often need to know what the original password was. Password crackers like John the Ripper and hashcat take a hash and repeatedly guess passwords — running each guess through the same scrambling function — until a guess produces the exact same hash. John is friendly and great at auto-detecting hash types, while hashcat uses your graphics card (GPU) to try billions of guesses per second. In a lab we use them on tiny, weak, deliberately-known passwords so you can learn the workflow safely.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| john | apt install john | John the Ripper: CPU password cracker with strong hash auto-detection and rule-based mangling |
| hashcat | apt install hashcat | GPU/CPU accelerated password recovery supporting hundreds of hash modes and attack types |

> Sourcing note: Kali packages the community "jumbo" build as `john` and provides `hashcat` prebuilt. See [Kali Tools: john](https://www.kali.org/tools/john/) and [Kali Tools: hashcat](https://www.kali.org/tools/hashcat/). The upstream project pages are [openwall.com/john](https://www.openwall.com/john/) and [hashcat.net](https://hashcat.net/hashcat/).

## Learning objectives
- Identify a hash type and select the correct John format or hashcat mode.
- Run a dictionary attack with both John and hashcat against a benign, known-weak hash.
- Apply a wordlist mangling rule set to expand candidate passwords.
- Interpret cracked/potfile output and confirm recovered plaintext.
- Explain how defenders detect and respond to offline cracking activity.

## Environment check
```bash
# Prove both crackers are installed on LAB-LINUX
john --version 2>&1 | head -n 1
hashcat --version
# Expected: John prints its version banner (e.g. "John the Ripper 1.9.0-jumbo");
# hashcat prints a version string like "v6.2.6".
```
> Notes: The community/jumbo edition reports a version such as `1.9.0-jumbo-1`; a raw upstream (non-jumbo) John reports e.g. `John the Ripper 1.9.0`. Jumbo is what Kali ships and is required for many `--format=` options used below. hashcat 6.2.6 is a real release tag; see the [hashcat releases](https://github.com/hashcat/hashcat/releases) page. Version strings vary by distro — treat the examples as illustrative, not exact.

## Guided walkthrough
1. `john --list=formats` — enumerates every hash format the installed John build understands. This both confirms tool health and, crucially, tells you whether your build is "jumbo" (hundreds of formats) or upstream (a small core set). Knowing the exact format name matters because `--format=` must match, or John will refuse the hash or mis-detect it.
```bash
john --list=formats | tr ',' '\n' | grep -i -m 5 md5
# Expected: prints several md5-related format names (e.g. "Raw-MD5", "md5crypt").
# Nuance: format names are case-insensitive on the command line; "Raw-MD5" is the
# fast unsalted MD5 (hashcat -m 0), while "md5crypt" ($1$...) is the slow salted
# Unix crypt variant (hashcat -m 500). Picking the wrong one wastes time or fails.
```
> `--list=formats` is documented in the John usage/OPTIONS reference: [openwall.com/john/doc/OPTIONS.shtml](https://www.openwall.com/john/doc/OPTIONS.shtml). Format-name/mode equivalences are cross-referenced in the [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) list.

2. Generate a known benign MD5 hash and crack it with John using a tiny inline wordlist. We use a plaintext hash on disk so the lab is fully reproducible and inert. `--wordlist` selects John's straight dictionary mode; `--show` reads the cracked result back out of the potfile rather than re-cracking.
```bash
# Create a benign hash for the plaintext "password123"
echo -n "password123" | md5sum | awk '{print $1}' > exercise/hash.txt
printf 'letmein\npassword123\nqwerty\n' > exercise/wordlist.txt
john --format=raw-md5 --wordlist=exercise/wordlist.txt exercise/hash.txt
john --format=raw-md5 --show exercise/hash.txt
# Expected: John reports "1 password hash cracked, 0 left" then --show prints
# "?:password123" (the "?" is the empty/undefined username field for a bare hash).
# Nuance: on a second run John prints "No password hashes left to crack (see FAQ)"
# because the result is cached in ~/.john/john.pot -- delete that potfile to re-crack.
```
> `--format`, `--wordlist`, `--show` and the `~/.john/john.pot` behavior are documented in [openwall.com/john/doc/OPTIONS.shtml](https://www.openwall.com/john/doc/OPTIONS.shtml) and the John [MODES doc](https://www.openwall.com/john/doc/MODES.shtml). `echo -n` avoids a trailing newline so the hash matches the canonical MD5 of the string.

3. Crack the same hash with hashcat (mode 0 = raw MD5). `-m 0` sets the hash mode, `-a 0` is the straight/dictionary attack mode, and `--potfile-path` isolates results to a lab-local file so previous runs don't hide the work.
```bash
hashcat -m 0 -a 0 exercise/hash.txt exercise/wordlist.txt --potfile-path exercise/hc.pot
hashcat -m 0 --show exercise/hash.txt --potfile-path exercise/hc.pot
# Expected: hashcat status shows "Status...: Cracked" and --show prints
# "<hash>:password123" (e.g. "482c811da5d5b4bc6d497ffa98491e38:password123").
# Nuance: if hashcat reports "All hashes found in potfile" it already cracked this
# hash on a prior run and skipped work -- delete exercise/hc.pot to force a re-crack.
# On a headless VM with no GPU, hashcat falls back to the CPU OpenCL device.
```
> `-m`/`-a` mode numbers, `--show`, and `--potfile-path` are documented in the [hashcat wiki (hashcat command)](https://hashcat.net/wiki/doku.php?id=hashcat) and `-m 0` = raw MD5 is confirmed in [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes). Attack-mode `-a 0` = straight (dictionary) per the [mask/attack modes docs](https://hashcat.net/wiki/doku.php?id=mask_attack).

4. Expand guesses with a rule set (best64) so a small list covers many variants. Rules mutate each candidate (append digits, capitalize, leetspeak, etc.) before hashing, dramatically increasing coverage without a bigger wordlist. `best64.rule` ships with hashcat and is a compact, high-yield default.
```bash
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule \
  exercise/hash.txt exercise/wordlist.txt --potfile-path exercise/hc.pot
# Expected: hashcat applies best64 mutations to each word before hashing; the
# effective keyspace is (words x rules). For this already-cracked hash it will
# report the result from potfile unless exercise/hc.pot is removed first.
# Nuance: on Kali the rules directory is /usr/share/hashcat/rules/ -- confirm the
# exact path with: ls /usr/share/hashcat/rules/best64.rule
```
> Rule-based attacks and the bundled `best64.rule` are documented in the [hashcat rule-based attack wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack). The Kali package installs rules under `/usr/share/hashcat/rules/` per [Kali Tools: hashcat](https://www.kali.org/tools/hashcat/); verify locally rather than assuming.

## Hands-on exercise
**Sample artifact:** `exercise/hash.txt` — a single raw MD5 hex digest of a benign, known-weak passphrase.
**Safe-origin note:** The sample is fully inert (it is a text hash, not malware) and is generated locally with the `md5sum` command shown below. No network egress is required and no live malware is involved. The plaintext is a deliberately weak dictionary word chosen for training.

Reproducible generator:
```bash
mkdir -p exercise
echo -n "password123" | md5sum | awk '{print $1}' > exercise/hash.txt
```

**Task:** Recover the plaintext behind `exercise/hash.txt` using either John or hashcat with the provided `exercise/wordlist.txt`. Report the hash type, the mode/format you used, and the recovered password.

## SOC analyst perspective
Defenders rarely crack passwords in production, but they must detect the credential theft that precedes offline cracking, because the crack itself is silent. Concrete detection logic and Security Onion pivots:

- **DCSync / replication abuse (T1003.006):** In the Elastic/Kibana logs, hunt Windows Security **Event ID 4662** where `Properties` contains the replication GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All) from a non-DC account. Correlate with **4624** logon for that principal. This maps to impacket `secretsdump.py`'s DRSUAPI path. See [Microsoft Learn: Event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662) and MITRE [T1003.006](https://attack.mitre.org/techniques/T1003/006/).
- **LSASS access (T1003.001):** hunt **Sysmon Event ID 10** (ProcessAccess) where `TargetImage` ends in `lsass.exe` with suspicious `GrantedAccess` (e.g. `0x1410`/`0x1010`) — the classic mimikatz/procdump signature. See MITRE [T1003.001](https://attack.mitre.org/techniques/T1003/001/) and [Sysmon docs on Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **NTDS.dit / SAM extraction (T1003.002 / T1003.003):** watch for **Event ID 4688/1** command lines invoking `ntdsutil`, `vssadmin create shadow`, or `reg save hklm\sam`. Volume Shadow Copy creation (**Event ID 8222** / VSS) is a strong precursor signal.
- **LSA Secrets extraction (T1003.004):** monitor for **Event ID 4688** where `Image` is `reg.exe` and `CommandLine` contains `save hklm\security` or `save hklm\system` (to extract LSA secrets via registry). Also detect `secretsdump.py` usage via `python.exe` command lines containing `secretsdump`. See MITRE [T1003.004](https://attack.mitre.org/techniques/T1003/004/).
- **Process Discovery (T1057):** hunt **Sysmon Event ID 1** (Process Create) where `Image` is in (`tasklist.exe`, `qprocess.exe`, `wmic.exe`, `processhacker.exe`) or `CommandLine` contains `tasklist`, `qprocess *`, `wmic process list`, `net view` to identify adversary enumerating processes for LSASS targeting. See MITRE [T1057](https://attack.mitre.org/techniques/T1057/).
- **Network pivots in Security Onion:** Zeek `smb_files.log` / `smb_mapping.log` showing access to `ADMIN$`/`C$` and named pipes (`\srvsvc`, `\samr`, `\drsuapi`) map to remote dumping. Suricata rules in the ET ruleset alert on Responder/LLMNR-NBNS poisoning and impacket signatures — pivot from a Suricata `alert` in Kibana to the corresponding Zeek `conn.log`/`notice.log`. See [Security Onion docs](https://docs.securityonion.net/) and [Zeek SMB logs](https://docs.zeek.org/en/master/logs/smb.html).
- **Threat-hunting pivots:** After detecting LSASS access (Event ID 10), hunt for:
    * Unusual outbound connections (Zeek `conn.log` with `service`=- and unusual `duration`/`orig_bytes` ratios)
    * Creation of suspicious files in `%TEMP%` or `%APP_DATA%` (Zeek `files.log` with `mime_type`=`application/x-dosexec` and unusual file names)
    * Anomalous privileged logons (Windows Event ID 4624 with `Logon Type`=4 (batch) or 5 (service) from unexpected sources)

Because the crack runs offline, the network is quiet during it — so the investigative pivot is always the *dump* event. Correlate host EDR/Sysmon alerts for hive/LSASS access against the timeline, then assume any dumped hash is now recoverable and force credential resets (T1078 follow-on). Analysts also run John/hashcat defensively to audit their own password-policy strength against recovered hashes.

## Attacker perspective
An attacker uses John and hashcat *after* a foothold and credential dump — from SAM/SYSTEM hives, `ntds.dit`, `/etc/shadow`, or captured NetNTLMv2 challenge/responses via Responder. Concrete TTPs and the artifacts they leave:

- **Offline cracking (T1110.002):** the crack itself runs on the attacker's own GPU rig, so it produces essentially **no network footprint** — this is the whole point of offline cracking and the reason resets must follow any dump. See MITRE [T1110.002](https://attack.mitre.org/techniques/T1110/002/).
- **Sourcing the hashes:**
  - `reg save HKLM\SAM` + `HKLM\SYSTEM`, or `impacket-secretsdump` local/remote — leaves **4688/Sysmon 1** command-line and, remotely, SMB admin-share + `\samr`/`\drsuapi` pipe access (T1003.002/.003/.006).
  - `ntdsutil "ac i ntds" "ifm" ...` or `vssadmin create shadow` to copy a locked `ntds.dit` — leaves **VSS creation events** and disk artifacts (T1003.003).
  - **LSA Secrets extraction via registry (T1003.004):** using `reg save hklm\security` or `impacket-secretsdump -samples` leaves **Event ID 4688** with `reg.exe` command lines and creates `SECURITY.hive` files in temp directories.
  - **Responder / LLMNR-NBNS poisoning** to capture NetNTLMv2, then hashcat `-m 5600` — leaves poisoned-name responses observable on the wire (T1557.001, [MITRE T1557.001](https://attack.mitre.org/techniques/T1557/001/)); hashcat mode 5600 = NetNTLMv2 per [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes).
- **Process Discovery (T1057):** attackers run `tasklist`, `qprocess *`, or `wmic process list` to identify lsass.exe PID before opening a handle — leaves **Sysmon Event ID 1** with these command lines and **Event ID 10** shortly after.
- **Post-crack use (T1078 Valid Accounts):** recovered plaintext enables lateral movement, privilege escalation, and persistence with legitimate credentials — surfacing as anomalous logons (4624/4648) at odd hours or from new hosts. Look for:
    * Logons to domain controllers from non-DC hosts (Event ID 4624 with `Logon Type`=3 and `TargetUserName`=krbtgt)
    * New service installations (Event ID 4697) using recovered credentials
- **Evasion:** cracking offline avoids account-lockout and auth-log noise entirely; attackers also clear the security log (T1070.001), stage dumps in ADS or temp paths (look for `ADS:` in Sysmon Event ID 11 file creation), and time-throttle logons with cracked creds to blend in. See MITRE [T1070.001](https://attack.mitre.org/techniques/T1070/001/).

## Answer key
- Hash type: raw MD5 (John `--format=raw-md5`, hashcat `-m 0`).
- Recovered plaintext: `password123`.
- Commands that produce the finding:
```bash
john --format=raw-md5 --wordlist=exercise/wordlist.txt exercise/hash.txt
john --format=raw-md5 --show exercise/hash.txt
# or
hashcat -m 0 -a 0 exercise/hash.txt exercise/wordlist.txt --potfile-path exercise/hc.pot
hashcat -m 0 --show exercise/hash.txt --potfile-path exercise/hc.pot
```
- Sample sha256 (of `exercise/hash.txt`, i.e. the sha256 of the 32-char MD5 hex string + trailing newline): reproduce and verify with:
```bash
sha256sum exercise/hash.txt
# Expected digest:
# 818ed600ef221d270821b1a874576c4668251740ce27450624741b7da7df2be5  exercise/hash.txt
# (If your local digest differs, confirm the file contains exactly the 32-char MD5
#  of "password123" -> 482c811da5d5b4bc6d497ffa98491e38 with a single trailing newline.)
```

## MITRE ATT&CK & DFIR phase
- **T1110.002** — Brute Force: Password Cracking (offline). https://attack.mitre.org/techniques/T1110/002/
- **T1003** — OS Credential Dumping (the precursor that supplies the hashes), with sub-techniques **T1003.001** (LSASS), **T1003.002** (SAM), **T1003.003** (NTDS), **T1003.004** (LSA Secrets), **T1003.006** (DCSync). https://attack.mitre.org/techniques/T1003/
- **T1057** — Process Discovery (enumerating processes to target LSASS). https://attack.mitre.org/techniques/T1057/
- **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning (NetNTLMv2 capture feeding cracking). https://attack.mitre.org/techniques/T1557/001/
- **T1078** — Valid Accounts (post-crack use of recovered credentials). https://attack.mitre.org/techniques/T1078/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs (evasion). https://attack.mitre.org/techniques/T1070/001/
- **DFIR phase:** Examination / Analysis (recovering plaintext from seized hashes) supporting Identification and Containment (forcing resets on exposed accounts).


### Essential Commands & Features

Hashcat’s **mask attacks** (`-a 3`) and **hybrid modes** (`-a 6`/`-a 7`) enable targeted brute-forcing by combining wordlists with customizable patterns. Below are the most critical undemonstrated commands and features, including incremental and mask-based attacks, to optimize password cracking for real-world scenarios.

#### **1. Incremental Mode (`--increment`)**
Use when the password length is unknown but likely falls within a range. This mode tests all lengths sequentially from `--increment-min` to `--increment-max`.
**Example**: Crack a WPA2 handshake (hash mode `22000`) with lengths 4–8 using a custom charset:
```bash
hashcat -m 22000 -a 3 --increment --increment-min 4 --increment-max 8 handshake.hc22000 ?d?d?d?d?d?d?d?d
```
*Applies to*: [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (when targeting weak patterns).

---

#### **2. Mask Attacks (`-a 3`)**
Use when partial password structure is known (e.g., "password123" → `?l?l?l?l?l?l?l?d?d?d`). Masks use placeholders:
- `?l` = lowercase, `?u` = uppercase, `?d` = digits, `?s` = special chars.
**Example**: Crack an NTLM hash (`-m 1000`) with a known prefix ("Summer") and 2-digit suffix:
```bash
hashcat -m 1000 -a 3 hashes.txt Summer?d?d
```
*Applies to*: [T1187 Forced Authentication](https://attack.mitre.org/techniques/T1187/) (when cracking relayed hashes with predictable formats).

---

#### **3. Hybrid Modes (`-a 6`/`-a 7`)**
Combine wordlists with masks for efficiency. Use `-a 6` (wordlist + mask) or `-a 7` (mask + wordlist).
**Example**: Append 2 digits to each word in `rockyou.txt` for a SHA-1 hash (`-m 100`):
```bash
hashcat -m 100 -a 6 hashes.txt rockyou.txt ?d?d
```

**Key Flags**:
- `--potfile-disable`: Ignore hashcat’s potfile (force re-cracking).
- `--show`: Display cracked hashes from a previous session.

**Sources**:
-

### Threat Hunting & Detection Engineering
To detect password cracking attempts, threat hunters can monitor Windows Event ID 4625 (Failed Logon) and analyze the `LogonType` field to identify potential brute-force attacks. Additionally, they can inspect Zeek's `http` log to identify suspicious HTTP requests with high failure rates, indicating potential password spraying attempts. These tactics are associated with [T1589](https://attack.mitre.org/techniques/T1589/) - "Verify Security Software" and [T1204](https://attack.mitre.org/techniques/T1204/) - "User Execution", where attackers may attempt to verify the security software configuration or execute malicious code to crack passwords. Threat hunters can pivot on these findings by analyzing network logs for unusual patterns, such as multiple failed login attempts from a single IP address, and inspecting system logs for signs of malicious code execution. For more information on threat hunting and detection engineering, visit the [Cybersecurity and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) website or the [National Institute of Standards and Technology (NIST)](https://www.nist.gov/) Special Publication 800-53.


### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, password cracking is a post-exploitation tactic used to escalate privileges, move laterally, or maintain persistence within a compromised environment. Attackers often target hashed credentials (e.g., NTLM, Kerberos, or cached domain credentials) obtained via techniques like **T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow** (Linux) or **T1555.003 Credentials from Password Stores: Credentials from Web Browsers** (Windows). Once acquired, these hashes are cracked offline using tools like Hashcat or John the Ripper, leveraging GPU acceleration to brute-force weak or common passwords.

**Concrete TTPs:**
- **Offline Cracking:** Attackers exfiltrate hashed credentials (e.g., `/etc/shadow`, `NTDS.dit`, or browser credential stores) and crack them in a controlled environment to avoid detection.
- **Rule-Based Attacks:** Custom wordlists (e.g., `rockyou.txt`) are combined with mangling rules (e.g., `best64.rule`) to optimize cracking efficiency.
- **Pass-the-Hash (PtH):** If plaintext passwords cannot be recovered, attackers may reuse NTLM hashes directly via **T1550.002 Use Alternate Authentication Material: Pass the Hash**.

**Artifacts & Detection:**
- **Logs:** Failed authentication attempts (Event ID 4625 on Windows), unusual process execution (e.g., `hashcat.exe` or `john`), or large file transfers (exfiltrated credential stores).
- **Network:** Unusual outbound connections to command-and-control (C2) servers during exfiltration or tool downloads.
- **Filesystem:** Temporary files (e.g., `.potfile` for Hashcat) or modified registry keys (e.g., `HKLM\SECURITY\Cache` for cached credentials).

**Evasion Considerations:**
- **Timing:** Cracking is performed offline to avoid triggering rate-limiting or account lockouts.
- **Tool Obfuscation:** Attackers rename binaries (e.g., `hashcat.exe` → `svchost.exe`) or use living-off-the-land binaries (LOLBins) to blend in.
- **Credential Dumping:** Techniques like **T1003.008** are often combined with **T1486 Data Encrypted for Impact** (ransomware) to distract defenders.

**Sources:**
- [MITRE ATT&CK: T1003.008](https://attack.mitre.org/techniques/T1003/008/)
- [Cracking Passwords with Hashcat (SANS Internet Storm Center)](https

### Common Pitfalls & Result Validation

When performing password cracking, analysts often fall into avoidable traps that lead to false conclusions or wasted resources. A frequent mistake is **ignoring account lockout policies** (MITRE ATT&CK [T1110.004: Brute Force: Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)), which can trigger defensive responses like account lockouts or alerts, tipping off defenders. Always verify lockout thresholds before launching attacks, and use throttled or targeted approaches (e.g., wordlist-based attacks) to minimize noise.

Another critical error is **failing to validate cracked credentials** in the target environment. For example, a hash cracked offline (e.g., from a dump) may not work due to **password rotation policies** or **multi-factor authentication (MFA)** requirements (MITRE ATT&CK [T1556.006: Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)). Always test credentials in a controlled, non-disruptive manner—such as via a low-privilege service or API—to confirm their validity before assuming access.

To avoid false positives, cross-reference cracked passwords with **known breach datasets** (e.g., Have I Been Pwned) or **password complexity requirements** of the target system. For instance, if a cracked password lacks required special characters, it may be a false match. Document your methodology, including tool versions (e.g., Hashcat), wordlists, and rule sets, to ensure reproducibility and peer review.

**Sources:**
- [OWASP Testing Guide: Password Cracking](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Password_Policy)
- [CrackStation: Password Cracking Methodology](https://crackstation.net/cracking-passwords.htm)


### Essential Commands & Features

Once you’ve cracked hashes, **retrieve results efficiently** with these commands:

- **Hashcat’s `--show`** – Display cracked passwords from a previous session without re-running the attack. Use when you need to review results stored in the potfile.
  ```bash
  hashcat -m 1000 hashes.txt --show
  ```
- **Hashcat’s `--left`** – Show uncracked hashes only. Critical for assessing remaining targets after partial success.
  ```bash
  hashcat -m 1000 hashes.txt --left
  ```
- **Hashcat’s `--potfile-disable`** – Bypass the potfile to force re-cracking (e.g., testing rule variations). Combine with `--restore` to resume interrupted sessions.
  ```bash
  hashcat -m 1000 hashes.txt rockyou.txt --potfile-disable
  hashcat --restore
  ```

- **John’s `--show`** – List cracked passwords from a John session. Essential for post-attack reporting.
  ```bash
  john --show hashes.txt
  ```
- **John’s `--rules=single`** – Apply "single crack" mode rules (e.g., mangling usernames). Useful for weak password patterns tied to user data (MITRE ATT&CK **T1087.002 Account Discovery: Domain Account**).
  ```bash
  john --format=nt hashes.txt --wordlist=users.txt --rules=single
  ```
- **John’s `--loopback`** – Reuse cracked passwords as wordlist inputs. Effective for credential reuse attacks (MITRE ATT&CK **T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting**).
  ```bash
  john --format=nt hashes.txt --loopback
  ```

**Sources:**
- [Hashcat Wiki: Restore/Show](https://hashcat.net/wiki/doku.php?id=restore)
- [Openwall John the Ripper Docs: Rules](https://www.openwall.com/john/doc/RULES.shtml)

We need to output a subsection markdown: "### Detection Signatures & Reference Artifacts". Then include three parts in order:

1. YARA code block: minimal valid YARA rule with rule <Name> { meta:, strings:, condition: }.
- strings: block must have specific indicators >=6 chars. So at least one string literal of length >=6 characters.
- condition must use filesize limit AND the strings. So condition: filesize < 100K and all of ($str1, $str2) maybe.

- Must reference every $var defined in strings in condition.

2. Sigma rule: YAML code block, minimal valid Sigma rule with title:, logsource: (real product/category), detection: containing a named selection plus a condition: that references it. Not condition: *.

So detection: selection: ... ; condition: selection.

3. Reference artifacts / IOCs markdown table with benign sample indicators: sha256 hash, filename, host/network artifacts. Use only documentation IPs (192.0.2.x/198.51.100.x/203.0.113.x) or defanged values (example[.]com, hxxp://). No real routable IPs or domains.

Also include ONE MITRE ATT&CK technique by ID + exact canonical name (not in the listed excluded list). So we need to pick a technique not in that excluded list. Let's see excluded list includes many but we can choose e.g., T1059 (Command and Scripting Interpreter) is not excluded? The list includes T1057, T1070, T1078, T1110, T1187, T1204, T1486, T1550.002, T1555.003, T1556, T1556.006, T1557, T1557.001, T1558.003, T1589. So T1059 is allowed. Or T1005 (Data from Local System) is not excluded. Let's pick T1059.001 (PowerShell) maybe? Actually sub-technique also okay as long as not in list. The list doesn't include T1059.001. It includes T1059? Not listed. So we can use T1059: Command and Scripting Interpreter (canonical name). Or T1059.001: PowerShell.

We need "ONE MITRE ATT&CK technique by ID + exact canonical name (NOT in [list])". So we can put "T1059 – Command and Scripting Interpreter". Ensure not in list.

Also include ONE authoritative source URL. Could be MITRE ATT&CK page: https://attack.mitre.org/techniques/T1059/ .

Now produce the subsection.

Make sure YARA rule is valid. Example:

rule PasswordCracker_Educational
{
    meta:
        description = "Detects benign password cracking sample used in training"
        author = "Security Trainer"
        reference = "https://example.com/training"
    strings:
        $hashcat = "hashcat64.exe" nocase
        $john = "john-the-ripper" nocase
        $brute = "bruteforce" nocase
    condition:
        filesize < 200KB and ($hashcat or $john or $brute)
}

Make sure each $var referenced in condition is defined: yes.

Sigma rule: minimal valid with title, logsource, detection with selection and condition referencing selection.

Example:

title: Suspicious Password Cracking Tool Execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\hashcat64.exe'
        OR Image|endswith: '\john.exe'
    condition: selection

But need named selection plus condition referencing it. Could be:

detection:
    sel:
        Image|endswith: '\hashcat64.exe'
        OR Image|endswith: '\john.exe'
    condition: sel

Yes.

Now reference artifacts table:

| Indicator Type | Value |
|----------------|-------|
| SHA256 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (that's empty file hash, but maybe better use a sample hash like "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"? Actually need plausible benign sample. Use a fake hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c787cba9876543210fedcba987". Must be 64 hex chars. We'll produce something like "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4


### Essential Commands & Features
To further enhance password cracking capabilities, it's crucial to explore additional features and commands in tools like hashcat and John the Ripper. Hashcat's mask attack (-a 3) allows for a customizable attack using a user-defined mask, which can be particularly useful when you have some knowledge about the password's structure. For example, `hashcat -m 0 -a 3 example.hash ?l?l?l?d` attempts to crack a hash using a mask that specifies a password composed of three lowercase letters followed by a digit. Hybrid modes (-a 6/7) combine dictionary and mask attacks, offering a powerful way to crack passwords that are based on dictionary words but with modifications. John the Ripper's --loopback and --single modes are also valuable, with --loopback allowing you to feed the output of one cracking mode back into another, and --single attempting to crack each password individually using a variety of methods. These techniques align with the goals of [T1625: Graphical User Interface](https://attack.mitre.org/techniques/T1625/) and [T1211: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1211/), highlighting the importance of understanding and utilizing advanced password cracking methods for both offensive and defensive cybersecurity practices. For more detailed information and examples, refer to the official documentation at [https://www.hackingarticles.in/category/hashcat/](https://www.hackingarticles.in/category/hashcat/) and [https://www.openwall.com/john/doc/](https://www.openwall.com/john/doc/).

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Password Set to Never Expire via WMI** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmi_password_never_expire.yml; license: Detection Rule License / DRL):

```yaml
title: Password Set to Never Expire via WMI
id: 7864a175-3654-4824-9f0d-f0da18ab27c0
status: experimental
description: |
    Detects the use of wmic.exe to modify user account settings and explicitly disable password expiration.
references:
    - https://www.huntress.com/blog/the-unwanted-guest
author: "Daniel Koifman (KoifSec)"
date: 2025-07-30
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1047
    - attack.t1098
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:   # Example command simulated:  wmic  useraccount where name='guest' set passwordexpires=false
        - Image|endswith: '\wmic.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'useraccount'
            - ' set '
            - 'passwordexpires'
            - 'false'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activity
level: medium
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/mal_passwordstate_backdoor.yar, author: Florian Roth (Nextron Systems)):

```yara
rule MAL_Passwordstate_Moserware_Backdoor_Apr21_1 {
   meta:
      description = "Detects backdoor used in Passwordstate incident"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://thehackernews.com/2021/04/passwordstate-password-manager-update.html"
      date = "2021-04-25"
      hash1 = "c2169ab4a39220d21709964d57e2eafe4b68c115061cbb64507cfbbddbe635c6"
      hash2 = "f23f9c2aaf94147b2c5d4b39b56514cd67102d3293bdef85101e2c05ee1c3bf9"
      id = "061de3ae-c404-5e4a-a16b-b3b208b1ae7f"
   strings:
      $x1 = "https://passwordstate-18ed2.kxcdn.com" wide

      $s1 = " ProxyUserName, ProxyPassword FROM [SystemSettings]" wide fullword
      $s2 = "PasswordstateService.Passwordstate.Crypto" wide
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari" wide fullword

      $op1 = { 00 4c 00 4e 00 43 00 4c 00 49 00 31 00 31 00 3b 00 00 17 }
      $op2 = { 4c 00 49 00 31 00 31 00 3b 00 00 17 50 00 72 00 }
      $op3 = { 61 00 74 00 65 00 2d 00 31 00 38 00 65 00 64 00 32 00 2e 00 6b 00 78 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      1 of ($x*) or 3 of them
}
```

**Real-world context (MITRE T1003.006 -- OS Credential Dumping: DCSync):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1003/006/ -- real in-the-wild use includes Scattered Spider, Mustang Panda, APT29.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `40_password_cracking_benign_sample.txt` |
| sample sha256 | `3d0aae9b1e11915647b6550655395c70cb8b53848b5209eb1ce4d845ac304c66` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 40-password-cracking -- for detection-rule testing only
' |
### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1110.002 (Brute Force: Password Cracking)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1110/002/
- **Threat actors documented using it:** APT3, FIN6 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- John options `--format` / `--wordlist` / `--show` / `--list=formats`, potfile `~/.john/john.pot` — [openwall.com/john/doc/OPTIONS.shtml](https://www.openwall.com/john/doc/OPTIONS.shtml)
- John cracking modes (dictionary/single/incremental) — [openwall.com/john/doc/MODES.shtml](https://www.openwall.com/john/doc/MODES.shtml)
- John project home / jumbo edition & version banner — [openwall.com/john/](https://www.openwall.com/john/)
- Kali packaging of `john` — [kali.org/tools/john](https://www.kali.org/tools/john/)
- hashcat `-m` hash-mode / `-a` attack-mode / `--show` / `--potfile-path` usage — [hashcat wiki: hashcat command](https://hashcat.net/wiki/doku.php?id=hashcat)
- hashcat attack modes (`-a 0` straight) — [hashcat wiki: mask attack / attack modes](https://hashcat.net/wiki/doku.php?id=mask_attack)
- hashcat mode numbers: `-m 0` raw MD5, `-m 500` md5crypt, `-m 5600` NetNTLMv2 — [hashcat wiki: example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- hashcat `best64.rule` / rule-based attacks — [hashcat wiki: rule-based attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
- hashcat version tags (v6.2.6) — [github.com/hashcat/hashcat/releases](https://github.com/hashcat/hashcat/releases)
- Kali packaging of `hashcat` and rules under `/usr/share/hashcat/rules/` — [kali.org/tools/hashcat](https://www.kali.org/tools/hashcat/)
- Windows Event 4662 (replication GUIDs / DCSync) — [Microsoft Learn: Event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
- Sysmon (Event ID 10 ProcessAccess, Event ID 1 process create) — [Microsoft Learn: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Windows Event 4688 (process creation with command line) — [Microsoft Learn: Event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- Windows Event 8222 (Volume Shadow Copy Service) — [Microsoft Learn: Event 8222](https://learn.microsoft.com/en-us/windows/win32/vss/event-8222)
- MITRE ATT&CK T1110.002 Password Cracking — [attack.mitre.org/techniques/T1110/002/](https://attack.mitre.org/techniques/T1110/002/)
- MITRE ATT&CK T1003 OS Credential Dumping (+ .001/.002/.003/.004/.006) — [attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)
- MITRE ATT&CK T1057 Process Discovery — [attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)
- MITRE ATT&CK T1557.001 LLMNR/NBT-NS Poisoning — [attack.mitre.org/techniques/T1557/001/](https://attack.mitre.org/techniques/T1557/001/)
- MITRE ATT&CK T1078 Valid Accounts — [attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)
- MITRE ATT&CK T1070.001 Clear Windows Event Logs — [attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)
- Security Onion documentation (Suricata/Zeek/Elastic pivots) — [docs.securityonion.net](https://docs.securityonion.net/)
- Zeek SMB logs (smb_files.log / smb_mapping.log) — [docs.zeek.org SMB logs](https://docs.zeek.org/en/master/logs/smb.html)
- Zeek conn.log fields (service, duration, orig_bytes) — [docs.zeek.org conn.log](https://docs.zeek.org/en/master/logs/conn.html)
- Zeek files.log (mime_type) — [docs.zeek.org files.log](https://docs.zeek.org/en/master/logs/files.html)
- SANS DFIR blog & posters (credential access / cracking guidance) — [sans.org/blog](https://www.sans.org/blog/)
- MITRE ATT&CK T1003.004 LSA Secrets — [attack.mitre.org/techniques/T1003/004/](https://attack.mitre.org/techniques/T1003/004/)
- Microsoft Windows Registry hive backup via reg save — [learn.microsoft.com/windows-server/administration/windows-commands/reg-save](https://learn.microsoft.com/windows-server/administration/windows-commands/reg-save)
- Impacket secretsdump usage — [github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)

## Related modules
- [Offensive / network (Kali subset)](../11-offensive-kali/README.md) -- shares hashcat
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives)
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives)
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives)

<!-- cyberlab-enriched: v2 -->
- https://attack.mitre.org/techniques/T1110/003/
- https://attack.mitre.org/techniques/T1187/
- https://attack.mitre.org/techniques/T1589/
- https://attack.mitre.org/techniques/T1204/
- https://www.cisa.gov/
- https://www.nist.gov/

<!-- cyberlab-enriched: v3 -->
- https://attack.mitre.org/techniques/T1003/008/
- https://attack.mitre.org/techniques/T1110/004/
- https://attack.mitre.org/techniques/T1556/006/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Password_Policy
- https://crackstation.net/cracking-passwords.htm

<!-- cyberlab-enriched: v4 -->
- https://hashcat.net/wiki/doku.php?id=restore
- https://www.openwall.com/john/doc/RULES.shtml
- https://attack.mitre.org/techniques/T1059/
- https://example.com/training"

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1625/
- https://attack.mitre.org/techniques/T1211/
- https://www.hackingarticles.in/category/hashcat/](https://www.hackingarticles.in/category/hashcat/
- https://www.openwall.com/john/doc/](https://www.openwall.com/john/doc/
- https://attack.mitre.org/techniques/T1111
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1211
- https://yara.readthedocs.io/en/v4.0.0/
- https://sigma-docs.github.io/
- https://attack.mitre.org/

<!-- cyberlab-enriched: v6 -->
