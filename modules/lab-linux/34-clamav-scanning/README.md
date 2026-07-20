# 34 * ClamAV signature scanning -- LAB-LINUX

## Overview (plain language)
Antivirus scanning is one of the fastest ways to triage a suspicious file. ClamAV is an open-source scanner that compares files against a huge database of known-bad "signatures" and flags anything that matches. Think of it like a fingerprint check at a crime scene: if a file's fingerprint is already on file as malicious, ClamAV tells you what it is. YARA is a complementary tool that lets an analyst write their own custom "if you see these bytes or strings, flag it" rules, which is handy for hunting new or targeted threats that no antivirus vendor has catalogued yet. Together they let you go from "I have an unknown file" to "this is probably X malware family" quickly and safely, without ever running the file.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| ClamAV | apt install clamav clamav-daemon | Open-source signature-based antivirus scanner and updater |
| YARA | apt install yara | Pattern-matching engine for writing custom detection rules |

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
Expected output: version banners such as `ClamAV 1.x.x/...` for ClamAV, a matching freshclam version line, and a YARA version like `4.x.x`. If any command reports "not found," install via the commands in the Tools covered table.

## Guided walkthrough
1. `freshclam` — downloads/updates the ClamAV signature databases (main, daily, bytecode). Run as root or with sudo; expect "database updated" or "up-to-date" messages.
```bash
sudo freshclam
```
Expected observable output: lines like `daily.cvd updated` or `daily database is up-to-date`, ending without errors.

2. `clamscan` — scans a path recursively. The `-r` flag recurses, `-i` prints only infected files.
```bash
# Scan a directory recursively, showing only detections plus a summary
clamscan -r -i /tmp/samples
```
Expected observable output: any matched file prints `<path>: <SignatureName> FOUND`; a summary block reports "Infected files: N".

3. `clamscan` with the EICAR test string is a safe way to confirm detection works end to end.
```bash
# Write the industry-standard benign EICAR antivirus test file, then scan it
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan /tmp/eicar.com
```
Expected observable output: `/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND` and `Infected files: 1`.

4. `yara` — apply a rule file against a target. Rules describe strings/byte patterns and a condition.
```bash
yara --help | head -n 20
```
Expected observable output: usage text listing options like `-r` (recursive), `-s` (print matching strings), and `-w` (disable warnings).

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
In a SOC, ClamAV is a first-pass triage engine: analysts scan quarantined email attachments, downloaded binaries, or files pulled from a host during incident response to get a fast known-bad verdict before deeper analysis. In a Security Onion deployment, ClamAV or YARA verdicts on files carved from PCAP (via Zeek's `extract_files` / Strelka) enrich alerts and feed hunting workflows. YARA is the analyst's own weapon for detecting threats vendors have not yet signatured — you turn IOCs from a report into a rule and sweep the environment. These detections map to MITRE ATT&CK data-source "File" and support hunting for Ingress Tool Transfer (T1105) and obfuscated payloads (T1027), letting responders prioritize which artifacts warrant memory or disk forensics.

## Attacker perspective
Attackers know signature-based AV like ClamAV is watching, so they routinely obfuscate, pack (e.g., UPX), encrypt, or polymorph their payloads specifically to evade static signatures — mapping to Obfuscated Files or Information (T1027) and its packing sub-technique. They may test their tooling against public engines to confirm it does not trigger before deploying it. However, evasion leaves artifacts: high-entropy sections, packer stubs, unusual imports, and dropper files on disk that a custom YARA rule keyed to family-specific strings or byte patterns can still catch even when the vendor signature misses. Every dropped file, temp artifact, and staged binary is a chance for a defender's YARA sweep to surface the intrusion.

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
- T1027 — Obfuscated Files or Information (why attackers evade signature scanning; why YARA custom rules matter).
- T1027.002 — Software Packing (packed payloads defeat static signatures).
- T1105 — Ingress Tool Transfer (dropped/downloaded files that get scanned).
- DFIR phase: **Identification / Examination** — triaging and classifying suspect files during incident response before deeper reverse engineering.

## Sources
- ClamAV official documentation: https://docs.clamav.net/
- freshclam / clamscan manual: https://linux.die.net/man/1/clamscan
- EICAR standard anti-malware test file: https://www.eicar.org/download-anti-malware-testfile/
- YARA documentation (writing rules): https://yara.readthedocs.io/en/stable/
- Kali Tools — yara: https://www.kali.org/tools/yara/
- Kali Tools — clamav: https://www.kali.org/tools/clamav/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- SANS FOR610 Reverse-Engineering Malware (triage context): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/