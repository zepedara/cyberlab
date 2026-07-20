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
- **Network pivots in Security Onion:** Zeek `smb_files.log` / `smb_mapping.log` showing access to `ADMIN$`/`C$` and named pipes (`\srvsvc`, `\samr`, `\drsuapi`) map to remote dumping. Suricata rules in the ET ruleset alert on Responder/LLMNR-NBNS poisoning and impacket signatures — pivot from a Suricata `alert` in Kibana to the corresponding Zeek `conn.log`/`notice.log`. See [Security Onion docs](https://docs.securityonion.net/) and [Zeek SMB logs](https://docs.zeek.org/en/master/logs/smb.html).

Because the crack runs offline, the network is quiet during it — so the investigative pivot is always the *dump* event. Correlate host EDR/Sysmon alerts for hive/LSASS access against the timeline, then assume any dumped hash is now recoverable and force credential resets (T1078 follow-on). Analysts also run John/hashcat defensively to audit their own password-policy strength against recovered hashes.

## Attacker perspective
An attacker uses John and hashcat *after* a foothold and credential dump — from SAM/SYSTEM hives, `ntds.dit`, `/etc/shadow`, or captured NetNTLMv2 challenge/responses via Responder. Concrete TTPs and the artifacts they leave:

- **Offline cracking (T1110.002):** the crack itself runs on the attacker's own GPU rig, so it produces essentially **no network footprint** — this is the whole point of offline cracking and the reason resets must follow any dump. See MITRE [T1110.002](https://attack.mitre.org/techniques/T1110/002/).
- **Sourcing the hashes:**
  - `reg save HKLM\SAM` + `HKLM\SYSTEM`, or `impacket-secretsdump` local/remote — leaves **4688/Sysmon 1** command-line and, remotely, SMB admin-share + `\samr`/`\drsuapi` pipe access (T1003.002/.003/.006).
  - `ntdsutil "ac i ntds" "ifm" ...` or `vssadmin create shadow` to copy a locked `ntds.dit` — leaves **VSS creation events** and disk artifacts (T1003.003).
  - **Responder / LLMNR-NBNS poisoning** to capture NetNTLMv2, then hashcat `-m 5600` — leaves poisoned-name responses observable on the wire (T1557.001, [MITRE T1557.001](https://attack.mitre.org/techniques/T1557/001/)); hashcat mode 5600 = NetNTLMv2 per [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes).
- **Post-crack use (T1078 Valid Accounts):** recovered plaintext enables lateral movement, privilege escalation, and persistence with legitimate credentials — surfacing as anomalous logons (4624/4648) at odd hours or from new hosts.
- **Evasion:** cracking offline avoids account-lockout and auth-log noise entirely; attackers also clear the security log (T1070.001), stage dumps in ADS or temp paths, and time-throttle logons with cracked creds to blend in. See MITRE [T1070.001](https://attack.mitre.org/techniques/T1070/001/).

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
- **T1003** — OS Credential Dumping (the precursor that supplies the hashes), with sub-techniques **T1003.001** (LSASS), **T1003.002** (SAM), **T1003.003** (NTDS), **T1003.006** (DCSync). https://attack.mitre.org/techniques/T1003/
- **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning (NetNTLMv2 capture feeding cracking). https://attack.mitre.org/techniques/T1557/001/
- **T1078** — Valid Accounts (post-crack use of recovered credentials). https://attack.mitre.org/techniques/T1078/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs (evasion). https://attack.mitre.org/techniques/T1070/001/
- **DFIR phase:** Examination / Analysis (recovering plaintext from seized hashes) supporting Identification and Containment (forcing resets on exposed accounts).

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
- MITRE ATT&CK T1110.002 Password Cracking — [attack.mitre.org/techniques/T1110/002/](https://attack.mitre.org/techniques/T1110/002/)
- MITRE ATT&CK T1003 OS Credential Dumping (+ .001/.002/.003/.006) — [attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)
- MITRE ATT&CK T1557.001 LLMNR/NBT-NS Poisoning — [attack.mitre.org/techniques/T1557/001/](https://attack.mitre.org/techniques/T1557/001/)
- MITRE ATT&CK T1078 Valid Accounts — [attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)
- MITRE ATT&CK T1070.001 Clear Windows Event Logs — [attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)
- Security Onion documentation (Suricata/Zeek/Elastic pivots) — [docs.securityonion.net](https://docs.securityonion.net/)
- Zeek SMB logs (smb_files.log / smb_mapping.log) — [docs.zeek.org SMB logs](https://docs.zeek.org/en/master/logs/smb.html)
- SANS DFIR blog & posters (credential access / cracking guidance) — [sans.org/blog](https://www.sans.org/blog/)

## Related modules
- [Offensive / network (Kali subset)](../11-offensive-kali/README.md) -- shares hashcat for the offensive-side cracking workflow.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); recover credential material from memory to feed cracking.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); hunt the dumping tools that precede offline cracking.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); carve SAM/NTDS artifacts from disk images.

<!-- cyberlab-enriched: v1 -->
