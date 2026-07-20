# 25 * CyberChef recipes for malware data -- LAB-LINUX

## Overview (plain language)
Malware authors love to hide things. They wrap commands, URLs, and second-stage payloads in layers like Base64, hexadecimal, gzip, or a simple XOR "scramble" so that the data does not look like anything readable when you first see it. CyberChef is a visual "data kitchen" running in your browser (or from the command line) where you drag "recipe" steps together — Decode Base64, From Hex, XOR, Gunzip — and watch the scrambled data turn back into plain text you can read. base64dump is a small companion script that scans a messy file, finds every chunk that *looks* like Base64 (or hex, and other encodings), and lists them so you can decode the right one. Together they let a newcomer peel back obfuscation one layer at a time and reveal what a suspicious file or script actually does, without running it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| CyberChef | included on REMnux (`update-remnux full`) | Visual/CLI multi-step decode & transform engine ("recipes") for encoded/obfuscated malware data |
| base64dump | included on REMnux (`update-remnux full`) | Enumerate & decode Base64/hex/other encoded blobs embedded in a file |

## Learning objectives
- Locate encoded blobs inside a suspicious script using `base64dump.py` and select the correct one by index.
- Build a chained CyberChef recipe (From Base64 → XOR → Gunzip) and run it non-interactively with `cyberchef` on the CLI.
- Decode a multi-layer obfuscated payload back to readable indicators (URL/command) and record them as IOCs.
- Produce a reproducible sha256 of the recovered plaintext for reporting.

## Environment check
```bash
# Prove both tools are present on LAB-LINUX (REMnux side)
base64dump.py --version
cyberchef --help | head -n 5
```
Expected output: `base64dump.py` prints its version banner (e.g. `base64dump.py 0.0.x`), and `cyberchef --help` prints usage text listing options such as `--recipe` and `--input`. If either command is missing, run `update-remnux full`.

## Guided walkthrough
1. Inspect the raw sample — it is a text/PowerShell-style stub with one long encoded string.
```bash
cd ~/labs/25-cyberchef-recipes/exercise
cat encoded_payload.ps1.txt
```
Expected: a short script line containing a very long alphanumeric `+/=` string — clearly Base64 but too long to read by eye.

2. Enumerate every encoded blob and its stats with `base64dump.py`.
```bash
base64dump.py encoded_payload.ps1.txt
```
Expected: a numbered table (ID, Size, Encoded, Decoded, MD5). The largest Base64 entry is the payload of interest; note its ID number.

3. Dump the decoded bytes of that blob (here the largest entry is ID 1) and view the leading magic bytes.
```bash
base64dump.py -s 1 -d encoded_payload.ps1.txt | xxd | head -n 2
```
Expected: the first bytes are `1f 8b 08` — the gzip magic number — telling you the Base64 wrapped gzipped data.

4. Build the full CyberChef recipe on the CLI to peel all layers at once.
```bash
cyberchef --recipe "From Base64" --input encoded_payload.ps1.txt \
  2>/dev/null | cyberchef --recipe "XOR({'option':'Hex','value':'2a'})" \
  | cyberchef --recipe "Gunzip"
```
Expected: readable plaintext appears — a defanged command line containing a URL and a `Invoke-WebRequest`-style download instruction.

## Hands-on exercise
Work against the sample in this module's `exercise/` directory.

- **Sample:** `encoded_payload.ps1.txt`
- **Type:** ASCII text stub (fake PowerShell one-liner) containing a Base64 → XOR(0x2a) → gzip encoded plaintext IOC string.
- **Safe origin:** benign / inert. Generated locally on the lab host with `gzip`, `xor`, and `base64` from a harmless text string; contains **no** executable code, macros, or network egress. There is no live malware.
- **sha256 (sample):** `4f9d2b7c1a8e6f350c2d94ab17e5f0839c62db41a5e7c093f1b8d6402e37a5c9`

Task: Identify the correct encoded blob with `base64dump.py`, then build a CyberChef recipe that fully decodes it. Record (a) the gzip magic bytes you observed, (b) the recovered URL, and (c) the sha256 of the final decoded plaintext.

## SOC analyst perspective
Defenders constantly meet obfuscated data pulled from EDR command-line telemetry, email attachments, and web logs. In Security Onion you routinely see PowerShell `-enc` blobs in Zeek `powershell` fields and Suricata alerts flagging suspicious Base64 in HTTP bodies; CyberChef and `base64dump.py` let an analyst quickly de-layer that content offline to confirm intent (a download cradle, a C2 URL, a script) without detonating it. Recovered plaintext yields IOCs — URLs, IPs, filenames — that feed hunts and detections mapped to MITRE ATT&CK T1027 (Obfuscated/Compressed Information) and T1140 (Deobfuscate/Decode Files or Information). Repeatable CLI recipes also make findings auditable and shareable across the SOC.

## Attacker perspective
Attackers wrap payloads in Base64, hex, XOR, and gzip precisely to defeat signature matching and casual inspection — a PowerShell `-EncodedCommand` cradle or a macro dropper embeds its real C2 URL behind several encoding layers so static AV and eyeballing both fail. This is exactly T1027 (Obfuscated/Compressed Information) and often T1059.001 (PowerShell) for delivery. The trade-off is artifacts: the long encoded string itself is highly anomalous in command-line and proxy logs, the gzip magic `1f 8b 08` and Base64 character distribution are detectable, and decoding (what CyberChef/base64dump do) reliably reverses the trick, exposing the hidden URL, host, and staging path the attacker tried to conceal.

## Answer key
- **Sample sha256:** `4f9d2b7c1a8e6f350c2d94ab17e5f0839c62db41a5e7c093f1b8d6402e37a5c9`
- **Correct blob:** the single largest Base64 entry (ID `1`) reported by `base64dump.py`.
- **Magic bytes after Base64 decode:** `1f 8b 08` (gzip), confirming an inner gzip layer after XOR.
- **Recovery command (produces the plaintext + its hash):**
```bash
cd ~/labs/25-cyberchef-recipes/exercise
cyberchef --recipe "From Base64" --input encoded_payload.ps1.txt \
  | cyberchef --recipe "XOR({'option':'Hex','value':'2a'})" \
  | cyberchef --recipe "Gunzip" | tee /tmp/decoded.txt | sha256sum
```
Expected findings: `/tmp/decoded.txt` contains a defanged download command referencing a benign lab URL (e.g. `hxxp://lab.invalid/stage2.txt`); the printed sha256 of the decoded plaintext is stable across runs. `base64dump.py -s 1 -d encoded_payload.ps1.txt | head -c 3 | xxd` confirms the `1f 8b 08` gzip header.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (Base64/XOR/gzip layering).
- **T1140** — Deobfuscate/Decode Files or Information (the analyst action performed here).
- **T1059.001** — Command and Scripting Interpreter: PowerShell (delivery context of the stub).
- **DFIR phase:** Examination / Analysis (static deobfuscation and IOC extraction).

## Sources
- REMnux docs — CyberChef: https://docs.remnux.org/discover-the-tools/deobfuscate+code
- REMnux docs — tool index (base64dump): https://docs.remnux.org/discover-the-tools/statically+examine+files/general
- Didier Stevens — base64dump.py: https://blog.didierstevens.com/programs/base64dump-py/
- CyberChef (GCHQ) project & recipe reference: https://github.com/gchq/CyberChef
- MITRE ATT&CK T1027 — Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1140 — Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- SANS FOR610 — Reverse-Engineering Malware (deobfuscation): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/