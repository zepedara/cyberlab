# 34 * ClamAV signature scanning -- LAB-LINUX

## Overview (plain language)
Antivirus scanning is one of the fastest ways to triage a suspicious file. ClamAV is an open-source scanner that compares files against a huge database of known-bad "signatures" and flags anything that matches. Think of it like a fingerprint check at a crime scene: if a file's fingerprint is already on file as malicious, ClamAV tells you what it is. YARA is a complementary tool that lets an analyst write their own custom "if you see these bytes or strings, flag it" rules, which is handy for hunting new or targeted threats that no antivirus vendor has catalogued yet. Together they let you go from "I have an unknown file" to "this is probably X malware family" quickly and safely, without ever running the file.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| ClamAV | apt install clamav clamav-daemon | Open-source signature-based antivirus scanner and updater |
| YARA | apt install yara | Pattern-matching engine for writing custom detection rules |

ClamAV ships `clamscan` (standalone scanner), `clamd` (scanning daemon), `clamdscan` (client for the daemon), and `freshclam` (signature updater); see the ClamAV usage docs at https://docs.clamav.net/manual/Usage/Scanning.html. YARA's command-line interface and rule syntax are documented at https://yara.readthedocs.io/en/stable/.

## Learning objectives
- Update ClamAV signature databases and verify integrity with `freshclam` and `clamscan --version`.
- Run a recursive `clamscan` against a directory and interpret FOUND/OK/summary output.
- Author and apply a custom YARA rule with `yara` to match strings inside a sample.
- Compare signature-based (ClamAV) vs. rule-based (YARA) detection and explain when to use each.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX
clamscan --version
freshclam --version
yara --version
```
Expected output: version banners such as `ClamAV 1.x.x/...` for ClamAV, a matching freshclam version line, and a YARA version like `4.x.x`. If any command reports "not found," install via the commands in the Tools covered table. Note that `clamscan --version` also prints the signature database version and its build date after the slash (for example `ClamAV 1.0.3/27000/...`), which confirms `freshclam` has populated a database; the format is documented in the ClamAV scanning manual (https://docs.clamav.net/manual/Usage/Scanning.html).

## Guided walkthrough
1. `freshclam` — downloads/updates the ClamAV signature databases. Run as root or with sudo; expect "database updated" or "up-to-date" messages. WHY: ClamAV can only detect what is in its loaded databases, so an out-of-date engine produces false negatives. The three core databases are `main` (the base signature set), `daily` (frequent incremental updates), and `bytecode` (signatures written in ClamAV's bytecode language for complex detections); these are described in the ClamAV signatures documentation (https://docs.clamav.net/manual/Signatures.html).
```bash
sudo freshclam
```
Expected observable output: lines like `daily.cvd updated` or `daily database is up-to-date`, ending without errors. NUANCE: if `clamav-freshclam` runs as a background service, a manual `freshclam` may report the lock file is held; stop the service first (`sudo systemctl stop clamav-freshclam`) or rely on the daemon's scheduled updates. This behavior is covered in the freshclam configuration docs (https://docs.clamav.net/manual/Usage/Configuration.html#freshclamconf).

2. `clamscan` — scans a path recursively. The `-r`/`--recursive` flag descends into subdirectories, and `-i`/`--infected` prints only infected files. WHY: on a real host tree, printing every `OK` line buries the few detections; `-i` keeps the output focused on hits while the summary still reports how many files were scanned. Flag definitions are in the ClamAV scanning manual (https://docs.clamav.net/manual/Usage/Scanning.html).
```bash
# Scan a directory recursively, showing only detections plus a summary
clamscan -r -i /tmp/samples
```
Expected observable output: any matched file prints `<path>: <SignatureName> FOUND`; a summary block reports "Infected files: N". NUANCE: `clamscan` exits with status `0` when nothing is found, `1` when a virus is found, and `2` on error — useful for scripting triage pipelines (documented in the same scanning manual).

3. `clamscan` with the EICAR test string is a safe way to confirm detection works end to end. WHY: this proves the engine, the database, and file access all work without touching real malware.
```bash
# Write the industry-standard benign EICAR antivirus test file, then scan it
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan /tmp/eicar.com
```
Expected observable output: `/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND` and `Infected files: 1`. NUANCE: the signature name is assigned by ClamAV's database, not by EICAR; the EICAR file itself is defined by EICAR (https://www.eicar.org/download-anti-malware-testfile/) as a harmless standard test string.

4. `yara` — apply a rule file against a target. Rules describe strings/byte patterns and a boolean condition. WHY: YARA lets you encode analyst-derived indicators (family strings, byte sequences) that no AV vendor has signatured yet.
```bash
yara --help | head -n 20
```
Expected observable output: usage text listing options like `-r` (recursive), `-s` (print matching strings and offsets), and `-w` (disable warnings). These options and the rule language are documented at https://yara.readthedocs.io/en/stable/commandline.html and https://yara.readthedocs.io/en/stable/writingrules.html.

## Hands-on exercise
Sample: a benign, inert plain-text file emulating the EICAR antivirus test signature plus a custom marker string. **Safe-origin note:** this is NOT live malware — EICAR is the industry-standard 68-byte harmless test string published by EICAR specifically so scanners can be validated without any real malicious code. It cannot execute or harm the VM.

Generate the sample into this module's `exercise/` directory:
```bash
mkdir -p exercise
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > exercise/sample.txt
printf '\nLAB34_CUSTOM_MARKER_2024' >> exercise/sample.txt
sha256sum exercise/sample.txt
```

Tasks:
1. Update signatures and scan `exercise/sample.txt` with ClamAV. Record the signature name reported.
2. Write a YARA rule named `lab34_marker` that matches the string `LAB34_CUSTOM_MARKER_2024`, save it as `exercise/lab34.yar`, and run it against the sample.
3. Explain in one sentence why ClamAV caught the EICAR portion but not your custom marker.

## SOC analyst perspective
In a SOC, ClamAV is a first-pass triage engine: analysts scan quarantined email attachments, downloaded binaries, or files pulled from a host during incident response to get a fast known-bad verdict before deeper analysis (see the ClamAV scanning manual, https://docs.clamav.net/manual/Usage/Scanning.html). In a Security Onion deployment, files carved from network traffic by Zeek's File Analysis Framework (`extract_files`, documented at https://docs.zeek.org/en/master/frameworks/file-analysis.html) and processed by Strelka (https://github.com/target/strelka) can be run through YARA, and those verdicts enrich alerts you then pivot on in Kibana/Elastic. Concrete pivots: in Security Onion, hunt Zeek `files.log` for extracted file hashes and MIME types, correlate to Suricata `alert` events on the same connection UID, and pivot from a suspicious `md5`/`sha256` to the originating `conn.log` flow (Security Onion docs: https://docs.securityonion.net/en/2.4/zeek.html and https://docs.securityonion.net/en/2.4/suricata.html).

Detection logic to encode: alert when a carved file matches a YARA family rule OR when ClamAV returns a `FOUND` verdict on a host-uploaded artifact; escalate when the same hash appears across multiple hosts (staging/distribution). These detections map to the MITRE ATT&CK "File" data source and support hunting for Ingress Tool Transfer (T1105, https://attack.mitre.org/techniques/T1105/), Obfuscated Files or Information (T1027, https://attack.mitre.org/techniques/T1027/), and Software Packing (T1027.002, https://attack.mitre.org/techniques/T1027/002/) — letting responders prioritize which artifacts warrant memory or disk forensics. A ClamAV or YARA hit on an emailed attachment also supports Phishing (T1566, https://attack.mitre.org/techniques/T1566/) investigations, and User Execution: Malicious File (T1204.002, https://attack.mitre.org/techniques/T1204/002/) when the file was opened on an endpoint.

## Attacker perspective
Attackers know signature-based AV like ClamAV is watching, so they routinely obfuscate, pack, encrypt, or polymorph their payloads specifically to evade static signatures — mapping to Obfuscated Files or Information (T1027, https://attack.mitre.org/techniques/T1027/) and its Software Packing sub-technique (T1027.002, https://attack.mitre.org/techniques/T1027/002/, which explicitly names packers such as UPX). They may test their tooling against public multi-engine scanners to confirm it does not trigger before deploying it. Concrete TTPs and the artifacts they leave:
- Packing with UPX or a custom packer produces high-entropy PE sections, small/anomalous import tables, and recognizable packer stubs — all of which a YARA rule keyed to the stub bytes can still catch (T1027.002).
- Staging tooling by downloading it to disk (Ingress Tool Transfer, T1105) leaves dropper files, browser/download cache entries, and temp artifacts under paths like `/tmp` on Linux or `%TEMP%`/`%APPDATA%` on Windows.
- Encoding/encrypting payloads and decoding at runtime (T1027, T1140 Deobfuscate/Decode Files or Information, https://attack.mitre.org/techniques/T1140/) hides strings from a scanner at rest but the decoded content and the decoder logic remain observable in memory or in the on-disk loader.

Even when the vendor signature misses, a custom YARA rule keyed to family-specific strings or byte patterns can surface the intrusion. Every dropped file, temp artifact, and staged binary is a chance for a defender's YARA sweep to find it.

## Answer key
Sample sha256 (regenerate and confirm with the generator above):
```bash
sha256sum exercise/sample.txt
```
Expected findings and exact commands:

1. ClamAV detection:
```bash
sudo freshclam
clamscan exercise/sample.txt
```
Produces `exercise/sample.txt: Win.Test.EICAR_HDB-1 FOUND` and `Infected files: 1`.

2. Custom YARA rule and run:
```bash
cat > exercise/lab34.yar <<'EOF'
rule lab34_marker
{
    strings:
        $m = "LAB34_CUSTOM_MARKER_2024"
    condition:
        $m
}
EOF
yara -s exercise/lab34.yar exercise/sample.txt
```
Produces `lab34_marker exercise/sample.txt` and, with `-s`, the matched offset and string `$m: LAB34_CUSTOM_MARKER_2024`.

3. Expected explanation: ClamAV only matches patterns present in its signature databases (EICAR is a shipped signature); the custom marker is unique to this exercise, so only a hand-written YARA rule detects it.

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (why attackers evade signature scanning; why YARA custom rules matter). https://attack.mitre.org/techniques/T1027/
- T1027.002 — Software Packing (packed payloads defeat static signatures). https://attack.mitre.org/techniques/T1027/002/
- T1140 — Deobfuscate/Decode Files or Information (runtime decoding hides at-rest strings). https://attack.mitre.org/techniques/T1140/
- T1105 — Ingress Tool Transfer (dropped/downloaded files that get scanned). https://attack.mitre.org/techniques/T1105/
- T1204.002 — User Execution: Malicious File (opened attachment/payload on endpoint). https://attack.mitre.org/techniques/T1204/002/
- DFIR phase: **Identification / Examination** — triaging and classifying suspect files during incident response before deeper reverse engineering.

## Sources
Claim-to-source mapping (all URLs are official/authoritative):

- ClamAV components (`clamscan`, `clamd`, `clamdscan`, `freshclam`), scanning usage, `-r`/`-i` flags, and exit codes — ClamAV scanning manual: https://docs.clamav.net/manual/Usage/Scanning.html
- ClamAV documentation home: https://docs.clamav.net/
- ClamAV signature databases (main/daily/bytecode) and signature format — ClamAV signatures docs: https://docs.clamav.net/manual/Signatures.html
- freshclam configuration and daemon/lock behavior — ClamAV configuration docs: https://docs.clamav.net/manual/Usage/Configuration.html#freshclamconf
- EICAR standard anti-malware test file (68-byte benign string, safe-origin) — EICAR: https://www.eicar.org/download-anti-malware-testfile/
- YARA documentation home and rule-writing syntax — YARA docs: https://yara.readthedocs.io/en/stable/ and https://yara.readthedocs.io/en/stable/writingrules.html
- YARA command-line options (`-r`, `-s`, `-w`) — YARA CLI docs: https://yara.readthedocs.io/en/stable/commandline.html
- Kali Tools — yara: https://www.kali.org/tools/yara/
- Kali Tools — clamav: https://www.kali.org/tools/clamav/
- Zeek File Analysis Framework (file carving/extraction from traffic) — Zeek docs: https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Strelka (file scanning/YARA at scale) — project repo: https://github.com/target/strelka
- Security Onion Zeek integration and logs — Security Onion docs: https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion Suricata integration — Security Onion docs: https://docs.securityonion.net/en/2.4/suricata.html
- MITRE ATT&CK T1027 (Obfuscated Files or Information): https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 (Software Packing): https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 (Deobfuscate/Decode Files or Information): https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1105 (Ingress Tool Transfer): https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1204.002 (User Execution: Malicious File): https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1566 (Phishing): https://attack.mitre.org/techniques/T1566/
- SANS FOR610 Reverse-Engineering Malware (triage context): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- deepen the custom-rule authoring introduced here for proactive hunting.
- [Malware static triage](../08-malware-static-triage/README.md) -- complements ClamAV/YARA verdicts with static PE/string analysis of the same samples.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- applies YARA scanning to memory when payloads are decoded at runtime.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- pairs file-carved YARA verdicts with the network pivots referenced in the SOC section.

<!-- cyberlab-enriched: v1 -->
