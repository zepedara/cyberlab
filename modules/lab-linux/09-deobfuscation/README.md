# 09 * Deobfuscation -- LAB-LINUX

## Overview (plain language)
Malware authors rarely leave their code, URLs, or commands out in the open. They hide them by scrambling the bytes with simple math (like XOR), by wrapping text in Base64, or by chaining several encodings together. These "deobfuscation" tools are the decoder rings that reverse that hiding. CyberChef is a visual recipe builder that decodes and transforms data step by step; xortool and XORSearch help you find and break single-byte or multi-byte XOR keys hidden in a file; and base64dump extracts and decodes Base64 blobs buried inside scripts and documents. Together they turn scrambled gibberish back into readable strings, IP addresses, and instructions an analyst can act on.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| CyberChef | (preinstalled on REMnux; `cyberchef` opens local copy) | Browser-based "cyber Swiss-army knife" for chaining decode/transform recipes |
| xortool | `pip3 install xortool` (preinstalled on REMnux) | Guesses XOR key length and most probable multi-byte XOR key |
| base64dump | (Didier Stevens suite on REMnux; `base64dump.py`) | Finds and decodes Base64/other encoded blobs embedded in a file |
| XORSearch | (Didier Stevens suite on REMnux; `XORSearch`) | Brute-forces XOR/ROL/ROT/SHIFT keys to find a known plaintext string |

## Learning objectives
- Identify the encoding scheme (XOR, Base64, ROL) used to obfuscate a payload artifact.
- Recover a single-byte and multi-byte XOR key using XORSearch and xortool.
- Extract and decode embedded Base64 blobs from a script using base64dump.
- Reconstruct a plaintext IOC (URL/IP) and describe how to hand it to a SOC for detection.

## Environment check
```bash
# Prove all four deobfuscation tools are present on LAB-LINUX (REMnux)
XORSearch -h 2>&1 | head -n 1
base64dump.py --version 2>&1 | head -n 1
xortool --version
ls /usr/share/remnux/cyberchef 2>/dev/null && echo "CyberChef local copy present"
```
Expected output: `XORSearch` prints its usage/version banner; `base64dump.py` prints a version line (e.g. `base64dump.py 0.0.x`); `xortool` prints a version string; the CyberChef directory listing and confirmation line appear.

## Guided walkthrough
1. `XORSearch` — brute-forces every single-byte XOR/ROL key against a file looking for a known plaintext (here the string `http`), so you can find a hidden URL.
```bash
# Search a file for the string 'http' under all single-byte XOR keys
XORSearch -s exercise/encoded_payload.bin http
```
Expected observable output: one or more lines such as `Found XOR 5A position 0010: http://...` showing the key byte (0x5A) and the recovered plaintext.

2. `base64dump.py` — lists every Base64-looking blob in a file with a numeric ID, then decodes a chosen one.
```bash
# List candidate encoded blobs, then decode blob ID 1
base64dump.py exercise/encoded_payload.bin
base64dump.py -s 1 -d exercise/encoded_payload.bin | head -c 200
```
Expected observable output: a table of blobs (ID, size, encoding, MD5); the `-s 1 -d` decode dumps the readable decoded bytes of blob 1.

3. `xortool` — estimates the most likely XOR key length and the key itself for multi-byte XOR.
```bash
# Guess key length and key; assume printable text is common in the plaintext
xortool -c 20 exercise/encoded_payload.bin
```
Expected observable output: `The most probable key lengths:` histogram, then `Found N possible key(s):` listing candidate keys; decoded output is written to `./xortool_out/`.

4. `cyberchef` — open the local CyberChef and paste a blob to visually chain `From Base64` → `XOR` recipes.
```bash
# Launch the offline CyberChef copy shipped with REMnux
cyberchef &
```
Expected observable output: the browser opens the local CyberChef page (no internet required) where you build a decode recipe.

## Hands-on exercise
Recover the hidden command-and-control URL from the sample.

Sample declaration:
- **File:** `exercise/encoded_payload.bin`
- **Type:** benign, inert binary blob containing a single-byte XOR-encoded URL string plus one embedded Base64 blob. Contains NO executable code and NO live malware.
- **Safe origin:** generated locally for this lab by XOR-encoding a harmless RFC-5737 documentation-range URL (`http://198.51.100.23/update`) with key byte `0x5A`; no network egress. Reproducible offline.
- **sha256:** `06ae969a275e9dce37ed7c1e897f9146ded3b97c14afbad5e65eac1640f8e558`

Task: use XORSearch to find the XOR key and the plaintext URL, use xortool to confirm the key, and use base64dump to decode the embedded Base64 blob. Report the recovered URL and the XOR key byte.

## SOC analyst perspective
Defenders meet obfuscation constantly: phishing macros, PowerShell droppers, and beacon configs almost always Base64- or XOR-encode their URLs and IPs to dodge signatures. Deobfuscating them yields clean IOCs (domains, IPs, mutex names) that you pivot on in Security Onion — searching Zeek `conn.log`/`http.log` and Suricata alerts for the recovered host, then writing a Suricata rule or Zeek intel entry to catch repeat contact. This maps directly to MITRE ATT&CK T1027 (Obfuscated Files or Information) and T1140 (Deobfuscate/Decode Files or Information); recovering the plaintext is the examination step that turns an opaque sample into actionable detection content and hunting hypotheses across the fleet.

## Attacker perspective
Attackers XOR- or Base64-encode strings so static AV, YARA rules, and casual analysts miss embedded URLs, credentials, and shellcode. Single-byte XOR is cheap and defeats naive `strings`; multi-byte XOR and stacked encodings (Base64-then-XOR) raise the bar further, and CyberChef-style "recipes" are even shared to templatize the obfuscation. But the technique leaves artifacts: high-entropy byte runs, decode routines visible in disassembly, the XOR key stored somewhere in the binary, and recognizable Base64 alphabets in scripts. These fingerprints let XORSearch/xortool brute-force the key and let entropy tooling flag the encoded region — so obfuscation delays but does not prevent recovery of the underlying IOCs.

## Answer key
- XOR key byte: **0x5A**
- Recovered URL: **`http://198.51.100.23/update`**
- Sample sha256: `06ae969a275e9dce37ed7c1e897f9146ded3b97c14afbad5e65eac1640f8e558`

Commands that produce the findings:
```bash
# 1. Find the XOR key and plaintext URL
XORSearch -s exercise/encoded_payload.bin http
# -> Found XOR 5A ... http://198.51.100.23/update

# 2. Confirm single-byte key with xortool (key length 1 should dominate)
xortool -l 1 -c 20 exercise/encoded_payload.bin
# -> most probable key length 1; candidate key 0x5A written to ./xortool_out/

# 3. Decode the embedded Base64 blob
base64dump.py exercise/encoded_payload.bin
base64dump.py -s 1 -d exercise/encoded_payload.bin
```

## MITRE ATT&CK & DFIR phase
- **T1027 – Obfuscated Files or Information** (encoding of payload/IOCs).
- **T1027.013 – Encrypted/Encoded File** (XOR/Base64 layering).
- **T1140 – Deobfuscate/Decode Files or Information** (the analyst action performed here).
- **DFIR phase:** Examination / Analysis (extracting and decoding artifacts to derive IOCs after identification).

## Sources
- REMnux Deobfuscation tool docs: https://docs.remnux.org/discover-the-tools/deobfuscate+data
- Didier Stevens — XORSearch: https://blog.didierstevens.com/programs/xorsearch/
- Didier Stevens — base64dump.py: https://blog.didierstevens.com/2015/06/12/base64dump-py/
- xortool (hellman): https://github.com/hellman/xortool
- CyberChef (GCHQ): https://github.com/gchq/CyberChef
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1140: https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/