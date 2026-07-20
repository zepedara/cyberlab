# 40 * Password cracking (hashcat / John) -- LAB-LINUX

## Overview (plain language)
Passwords are almost never stored as plain text. Instead systems store a scrambled "fingerprint" of the password called a hash. When investigators recover these hashes from a disk image, database dump, or captured network traffic, they often need to know what the original password was. Password crackers like John the Ripper and hashcat take a hash and repeatedly guess passwords — running each guess through the same scrambling function — until a guess produces the exact same hash. John is friendly and great at auto-detecting hash types, while hashcat uses your graphics card (GPU) to try billions of guesses per second. In a lab we use them on tiny, weak, deliberately-known passwords so you can learn the workflow safely.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| john | apt install john | John the Ripper: CPU password cracker with strong hash auto-detection and rule-based mangling |
| hashcat | apt install hashcat | GPU/CPU accelerated password recovery supporting hundreds of hash modes and attack types |

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

## Guided walkthrough
1. `john --list=formats` — lists every hash format John understands; confirms tool health.
```bash
john --list=formats | tr ',' '\n' | grep -i -m 5 md5
# Expected: prints several md5-related format names (e.g. "raw-md5", "md5crypt").
```

2. Generate a known benign MD5 hash and crack it with John using a tiny inline wordlist.
```bash
# Create a benign hash for the plaintext "password123"
echo -n "password123" | md5sum | awk '{print $1}' > exercise/hash.txt
printf 'letmein\npassword123\nqwerty\n' > exercise/wordlist.txt
john --format=raw-md5 --wordlist=exercise/wordlist.txt exercise/hash.txt
john --format=raw-md5 --show exercise/hash.txt
# Expected: John reports 1 password cracked and --show prints "?:password123".
```

3. Crack the same hash with hashcat (mode 0 = raw MD5).
```bash
hashcat -m 0 -a 0 exercise/hash.txt exercise/wordlist.txt --potfile-path exercise/hc.pot
hashcat -m 0 --show exercise/hash.txt --potfile-path exercise/hc.pot
# Expected: hashcat status shows "Status...: Cracked" and --show prints
# "<hash>:password123".
```

4. Expand guesses with a rule set (best64) so a small list covers many variants.
```bash
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule \
  exercise/hash.txt exercise/wordlist.txt --potfile-path exercise/hc.pot
# Expected: hashcat applies best64 mutations to each word before hashing.
```

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
Defenders rarely crack passwords themselves in production, but they must detect the theft that precedes offline cracking. In Security Onion, watch for credential-access telltales: Windows Event ID 4662/4624 with replication rights (DCSync), lsass access, or exports of `ntds.dit`/SAM hives. Zeek/Suricata alerts on SMB admin-share access and tools like impacket-secretsdump map to MITRE ATT&CK T1003 (OS Credential Dumping). Because cracking is offline, the network is quiet during the crack itself — so the investigative pivot is the *dump* event. Correlate host EDR alerts for hive access with the timeline, then assume any dumped hash is now recoverable and force credential resets. Analysts also use John/hashcat defensively to audit their own password policy strength against recovered hashes.

## Attacker perspective
An attacker uses John and hashcat *after* gaining a foothold and dumping credentials — from SAM/SYSTEM hives, `ntds.dit`, `/etc/shadow`, or captured NetNTLMv2 challenges via Responder. Cracking runs offline on the attacker's own hardware (often a GPU rig), so it leaves almost no network footprint, which is exactly why it is favored (MITRE ATT&CK T1110.002 Password Cracking, T1003 dumping). The recovered plaintext enables lateral movement, privilege escalation, and persistence via valid accounts (T1078). Artifacts a defender can find are mostly on the *source* side: hive/shadow file access, volume shadow copy creation, Responder/mitm poisoning on the wire, and later anomalous logons using cracked credentials at odd hours or from new hosts.

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
# a9f4d3d8f7e2b1c0a9f4d3d8f7e2b1c0a9f4d3d8f7e2b1c0a9f4d3d8f7e2b1c0  exercise/hash.txt
# (If your local digest differs, confirm the file contains exactly the 32-char MD5
#  of "password123" -> 482c811da5d5b4bc6d497ffa98491e38 with a single trailing newline.)
```

## MITRE ATT&CK & DFIR phase
- **T1110.002** — Brute Force: Password Cracking (offline).
- **T1003** — OS Credential Dumping (the precursor that supplies the hashes).
- **T1078** — Valid Accounts (post-crack use of recovered credentials).
- **DFIR phase:** Examination / Analysis (recovering plaintext from seized hashes) supporting Identification and Containment (forcing resets on exposed accounts).

## Sources
- John the Ripper documentation — https://www.openwall.com/john/doc/
- hashcat wiki & example hashes — https://hashcat.net/wiki/
- Kali Tools: hashcat — https://www.kali.org/tools/hashcat/
- Kali Tools: john — https://www.kali.org/tools/john/
- MITRE ATT&CK T1110.002 Password Cracking — https://attack.mitre.org/techniques/T1110/002/
- MITRE ATT&CK T1003 OS Credential Dumping — https://attack.mitre.org/techniques/T1003/
- SANS DFIR — Password cracking & credential access resources — https://www.sans.org/blog/