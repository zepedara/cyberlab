# 21 * YARA rule authoring & threat hunting -- LAB-LINUX

## Overview (plain language)
YARA is a pattern-matching tool built for finding malware. You describe things you expect to see inside a file — pieces of text, byte sequences, or conditions — in a small "rule," and YARA scans files or folders to tell you which ones match. Think of it like a smart search that can look for many clues at once. capa is a companion tool that reads a program and explains, in plain English, what it is *capable* of doing (like "encrypt data" or "contact a web server") by matching known code behaviors. Together they let an analyst hunt for suspicious files across a system and quickly understand what a suspect file might do, without running it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| YARA | apt install yara | Pattern-matching engine for classifying/identifying files and hunting malware with custom rules |
| capa | pip3 install flare-capa | Detects capabilities in executables/shellcode by matching rules against disassembled code |

## Learning objectives
- Write a valid YARA rule using string, hex, and condition sections and compile it without errors.
- Scan a directory recursively with YARA and interpret match output (rule name + matching file).
- Use YARA meta fields and tags to document rule intent for threat hunting.
- Run capa against a sample and map its reported capabilities to MITRE ATT&CK techniques.
- Explain how YARA rules feed detection pipelines (e.g., Security Onion / Strelka).

## Environment check
```bash
# Prove YARA and capa are installed on LAB-LINUX
yara --version
capa --version
```
Expected output: `yara` prints a version like `4.5.0`; `capa` prints a version like `capa 7.x` (and its rules/signature versions). Non-zero exit or "command not found" means the tool is missing.

## Guided walkthrough
1. `yara --help` — shows scan flags such as `-r` (recursive), `-s` (print matching strings), and `-w` (suppress warnings).
```bash
yara --help | head -n 20
```
Expected: a usage summary listing options like `-r`, `-s`, `-w`, `-m` (print meta).

2. Create and compile a simple rule, then verify it parses cleanly.
```bash
cat > /tmp/hunt_eicar.yar <<'EOF'
rule Hunt_EICAR_TestString
{
    meta:
        author      = "lab21"
        description = "Detects the benign EICAR AV test signature"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $hdr   = { 58 35 4F 21 50 25 40 41 50 }
    condition:
        $eicar or $hdr
}
EOF
yara -w /tmp/hunt_eicar.yar /tmp/hunt_eicar.yar
```
Expected: the compile step emits no syntax errors. Scanning the rule file against itself prints `Hunt_EICAR_TestString /tmp/hunt_eicar.yar` because the literal string appears inside it.

3. Scan a directory recursively and print which strings matched.
```bash
yara -r -s /tmp/hunt_eicar.yar /tmp
```
Expected: for each matching file, `Hunt_EICAR_TestString <path>` followed by offset lines like `0x0:$eicar:EICAR-STANDARD-ANTIVIRUS-TEST-FILE`.

4. Ask capa what a binary can do (using a system binary as a safe demo).
```bash
capa -q /bin/ls | head -n 30
```
Expected: an ASCII capability table with columns such as `CAPABILITY` and `ATT&CK` / `MBC`, e.g. entries for file/host interaction. `-q` reduces logging noise.

## Hands-on exercise
Sample artifact: `exercise/eicar_sample.txt` in this module's `exercise/` directory.

- **Type:** ASCII text file containing the industry-standard EICAR anti-malware test string (68 bytes).
- **Safe origin:** This is the official EICAR test signature — a **benign, inert** string designed by anti-malware vendors specifically for testing detection. It is **not** malware, cannot execute, and requires **no network egress**. Generate it locally to avoid any download:
```bash
mkdir -p exercise
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > exercise/eicar_sample.txt
sha256sum exercise/eicar_sample.txt
```
- **sha256:** `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`

Task: Write (or reuse) a YARA rule that detects the EICAR string, scan the `exercise/` directory recursively, and record the matching rule name and file path.

## SOC analyst perspective
Defenders use YARA as the backbone of file-based detection and threat hunting. Analysts codify indicators from an incident (unique strings, byte patterns, PE traits) into rules, then sweep endpoints, mail gateways, and file stores to find every copy of a threat. In Security Onion, files carved by Zeek/Suricata are handed to Strelka, which runs YARA rules at scale and tags matches into Elasticsearch/Kibana for hunting and alerting. capa augments triage by translating a suspect binary into ATT&CK-mapped capabilities (e.g., T1071 C2, T1486 encryption), so a Tier-1 analyst can prioritize without manual reversing. This maps to ATT&CK techniques like T1027 (Obfuscated Files) and T1204 (User Execution) during the identification and examination DFIR phases.

## Attacker perspective
Attackers know defenders write YARA rules, so they actively work to evade them: packing/UPX-compressing payloads to hide strings (T1027.002), XOR/base64-encoding config and C2 URLs, polymorphic string generation, and inserting junk to break byte signatures. Red teamers may even run YARA and capa against their own tooling before delivery to confirm it stays below detection thresholds. Yet these evasions leave artifacts — high-entropy sections, packer stubs, unusual imports, and capa-detectable behaviors like "spawn a process" or "reference cryptography" — that a defender can hunt for. The very obfuscation used to dodge one rule becomes a detectable pattern for another (T1140 Deobfuscate/Decode).

## Answer key
Expected finding: the EICAR sample matches the authored rule.

```bash
# Reproduce the detection
yara -r -s /tmp/hunt_eicar.yar exercise/
```
Expected output:
```
Hunt_EICAR_TestString exercise/eicar_sample.txt
0x24:$eicar:EICAR-STANDARD-ANTIVIRUS-TEST-FILE
0x0:$hdr:X5O!P%@AP
```
Confirm the sample integrity:
```bash
sha256sum exercise/eicar_sample.txt
# 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  exercise/eicar_sample.txt
```
The held-out validator check confirms the rule name `Hunt_EICAR_TestString` matches `exercise/eicar_sample.txt` and that the sha256 equals `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (rules and evasion around packed/encoded payloads).
- **T1027.002** — Software Packing (capa/YARA identify packers and packed samples).
- **T1140** — Deobfuscate/Decode Files or Information.
- **T1204** — User Execution (hunting delivered/executed files).
- **DFIR phases:** Identification (sweeping for known indicators) and Examination/Analysis (capability triage of suspect files).

## Sources
- YARA documentation — https://yara.readthedocs.io/en/stable/
- YARA-X / VirusTotal YARA project — https://github.com/VirusTotal/yara
- Mandiant/FLARE capa — https://github.com/mandiant/capa
- REMnux static-code tools (capa) — https://docs.remnux.org/discover-the-tools/statically+examine+files/executables
- SANS FOR610 / YARA for hunting — https://www.sans.org/blog/how-to-use-yara-rules-to-detect-malware/
- Security Onion + Strelka file analysis — https://docs.securityonion.net/en/2.4/strelka.html
- MITRE ATT&CK T1027 — https://attack.mitre.org/techniques/T1027/
- EICAR test file (safe sample origin) — https://www.eicar.org/download-anti-malware-testfile/