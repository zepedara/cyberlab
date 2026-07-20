# 47 * Scenario: ransomware memory investigation -- LAB-LINUX

## Overview (plain language)
Imagine a workstation gets locked by ransomware and someone captures a snapshot of everything the computer was holding in its memory (RAM). This module teaches you how to open that snapshot and look inside it. RAM contains a treasure map: which programs were running, what web addresses they talked to, and even leftover text and keys. We use three tools together. Volatility 3 reads the raw memory file and lists processes, network connections, and injected code. YARA scans the same memory for known "signatures" of bad software. bulk_extractor sweeps through the memory blindly and pulls out useful bits like URLs, email addresses, and crypto artifacts. Together they help you reconstruct what the ransomware did.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | apt install volatility3 | Framework to extract processes, network, and injected code from a RAM capture |
| YARA | apt install yara | Pattern-matching engine to flag malware signatures inside memory or files |
| bulk_extractor | apt install bulk-extractor | Bulk scanner that carves URLs, emails, and other IOCs from raw data without a filesystem |

## Learning objectives
- Enumerate running processes and suspicious parent/child relationships in a memory image using Volatility 3.
- Extract network connections and command-line arguments tied to a ransomware process.
- Scan a memory image with a custom YARA rule and interpret hits.
- Carve indicators of compromise (URLs, ransom-note strings) from RAM with bulk_extractor.

## Environment check
```bash
# Prove all three tools are installed on LAB-LINUX (SIFT/REMnux)
vol --info | head -n 3
yara --version
bulk_extractor -V
```
Expected output: Volatility 3 prints its plugin banner, `yara` prints a version like `4.x.x`, and `bulk_extractor` prints a version string such as `bulk_extractor 2.0.x`.

## Guided walkthrough
1. `vol -f memory.raw windows.info` — confirms the image is readable and shows OS build/kernel details you need before running other plugins.
```bash
vol -f memory.raw windows.info
```
Expected: a table showing the profile, kernel base, and system time of the capture.

2. `vol -f memory.raw windows.pslist` — lists processes; look for oddly-named binaries running from temp directories.
```bash
vol -f memory.raw windows.pslist | grep -i -E "lock|crypt|ransom|encrypt"
```
Expected: one or more matching PIDs if a ransomware-like process is present.

3. `vol -f memory.raw windows.cmdline` — reveals the full command line for each process.
```bash
vol -f memory.raw windows.cmdline
```
Expected: a table mapping PID to command line; ransomware often shows an executable launched from `%TEMP%` or `%APPDATA%`.

4. `vol -f memory.raw windows.netscan` — shows open/closed network sockets to spot C2 callbacks.
```bash
vol -f memory.raw windows.netscan | grep ESTABLISHED
```
Expected: rows with foreign IPs such as 203.0.113.10 tied to a suspicious PID.

5. Scan the raw memory with a YARA rule for ransom-note strings.
```bash
yara -s ransom.yar memory.raw
```
Expected: rule name plus matched offsets/strings when the note text is found.

6. Carve indicators with bulk_extractor into an output directory.
```bash
bulk_extractor -o be_out memory.raw
cat be_out/url.txt | grep -i http | head
```
Expected: a populated `be_out/` directory; `url.txt` and `email.txt` contain carved indicators.

## Hands-on exercise
Investigate the sample memory image in this module's `exercise/` directory.

- **Sample type:** a small benign/inert raw memory-like blob (`exercise/memory.raw`) — it is NOT a real infected RAM capture and contains NO live malware; it is a plain file seeded with harmless ransom-note strings and a fake C2 URL so the tools produce realistic hits with zero risk.
- **Safe origin / generation:** the file is generated locally with the reproducible command below (no network egress). It only contains ASCII strings and random padding.

Reproducible generator (creates the exact benign sample):
```bash
mkdir -p exercise
{
  head -c 4096 /dev/zero
  printf 'YOUR FILES HAVE BEEN ENCRYPTED! Contact evilmail@example.com to recover.\n'
  printf 'Payment portal: http://203.0.113.10/pay\n'
  printf 'LOCKBIT_TEST_MARKER ransom.note.decrypt\n'
  head -c 4096 /dev/urandom
} > exercise/memory.raw
sha256sum exercise/memory.raw
```

Tasks:
1. Use `yara` with the rule below to confirm the ransom-note marker.
2. Use `bulk_extractor` to carve the C2 URL and the contact email.

Provided YARA rule (`exercise/ransom.yar`):
```bash
cat > exercise/ransom.yar <<'EOF'
rule ransom_note_test
{
    strings:
        $a = "HAVE BEEN ENCRYPTED"
        $b = "LOCKBIT_TEST_MARKER"
    condition:
        any of them
}
EOF
```

## SOC analyst perspective
A defender treats a captured memory image as ground truth when disk logs may be tampered. In an incident, you ingest network alerts from Security Onion (Suricata/Zeek) that flag a suspicious outbound connection to 203.0.113.10, then pivot to the endpoint's RAM capture. Volatility 3's `windows.netscan` and `windows.cmdline` corroborate the Zeek `conn.log` entry and reveal the process behind it, mapping to ATT&CK T1486 (Data Encrypted for Impact) and T1071 (Application Layer Protocol) for C2. YARA hits on ransom-note strings let you confirm the family and pivot IOCs into Security Onion for retroactive hunting. bulk_extractor rapidly surfaces carved URLs/emails to build the IOC list you push to detection rules and threat-intel enrichment.

## Attacker perspective
An attacker deploying ransomware runs an encryptor from a temporary path, often injecting into or spawning from a legitimate process to blend in (T1055 Process Injection, T1036 Masquerading). They contact a C2 or payment portal and drop a ransom note file across directories. These actions leave rich residue in RAM: the encryptor's command line, network sockets to the C2, the ransom-note template string, and sometimes encryption keys or configuration blobs still resident in the heap. Even if the attacker deletes the on-disk binary and note after encryption, the memory image preserves process listings, unlinked strings, and socket structures — exactly what Volatility 3, YARA, and bulk_extractor recover.

## Answer key
- **YARA:** `rule ransom_note_test` matches on `$a` ("HAVE BEEN ENCRYPTED") and `$b` ("LOCKBIT_TEST_MARKER").
```bash
yara -s exercise/ransom.yar exercise/memory.raw
```
Expected: `ransom_note_test exercise/memory.raw` with matched offsets for both strings.

- **bulk_extractor URL + email:** the carved C2 URL is `http://203.0.113.10/pay` and the contact email is `evilmail@example.com`.
```bash
bulk_extractor -o exercise/be_out exercise/memory.raw
grep -i "203.0.113.10" exercise/be_out/url.txt
grep -i "evilmail@example.com" exercise/be_out/email.txt
```
Expected: both greps return the seeded indicators.

- **Sample sha256:** because the benign sample includes random padding, its digest varies per generation. Record the digest printed by the generator's `sha256sum exercise/memory.raw` as the authoritative value for your build. To create a fixed, reproducible digest, replace the two `head -c ... /dev/urandom`/`/dev/zero` lines with `head -c 8192 /dev/zero` (all-zero padding); that deterministic variant yields a stable sha256 you can pin in CI.

## MITRE ATT&CK & DFIR phase
- **T1486** Data Encrypted for Impact — the ransomware encryption behavior.
- **T1071** Application Layer Protocol — C2/payment-portal communication observed via netscan.
- **T1055** Process Injection — potential injected encryptor code in memory.
- **T1027** Obfuscated/masqueraded artifacts recovered from RAM strings.
- **DFIR phases:** identification (triage the alert), examination/analysis (Volatility 3 + YARA + bulk_extractor on the image), and reporting (IOC list from carved indicators).

## Sources
- Volatility 3 documentation — https://volatility3.readthedocs.io/
- The Volatility Foundation — https://www.volatilityfoundation.org/
- YARA documentation — https://yara.readthedocs.io/
- bulk_extractor (Digital Corpora / forensicswiki) — https://github.com/simsong/bulk_extractor
- REMnux tool listings — https://docs.remnux.org/
- SANS SIFT Workstation — https://www.sans.org/tools/sift-workstation/
- MITRE ATT&CK T1486 — https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1055 — https://attack.mitre.org/techniques/T1055/
- Kali Tools (yara) — https://www.kali.org/tools/yara/