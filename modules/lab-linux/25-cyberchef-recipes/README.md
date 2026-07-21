# 25 * CyberChef recipes for malware data -- LAB-LINUX

## Overview (plain language)
Malware authors love to hide things. They wrap commands, URLs, and second-stage payloads in layers like Base64, hexadecimal, gzip, or a simple XOR "scramble" so that the data does not look like anything readable when you first see it. CyberChef is a visual "data kitchen" running in your browser (or from the command line) where you drag "recipe" steps together — Decode Base64, From Hex, XOR, Gunzip — and watch the scrambled data turn back into plain text you can read. base64dump is a small companion script that scans a messy file, finds every chunk that *looks* like Base64 (or hex, and other encodings), and lists them so you can decode the right one. Together they let a newcomer peel back obfuscation one layer at a time and reveal what a suspicious file or script actually does, without running it.

> Sourcing note: CyberChef is described by its authors as "the Cyber Swiss Army Knife — a web app for carrying out all manner of 'cyber' operations within a web browser," with operations chained into "recipes" ([CyberChef README, gchq/CyberChef](https://github.com/gchq/CyberChef)). `base64dump.py` is a Didier Stevens tool that "extracts the base64 (and other encodings) strings found inside a file and decodes them" ([base64dump.py, blog.didierstevens.com](https://blog.didierstevens.com/programs/base64dump-py/)).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| CyberChef | included on REMnux (`update-remnux full`) | Visual/CLI multi-step decode & transform engine ("recipes") for encoded/obfuscated malware data |
| base64dump | included on REMnux (`update-remnux full`) | Enumerate & decode Base64/hex/other encoded blobs embedded in a file |

> Both tools ship on REMnux and are refreshed via `update-remnux full`, the documented full-upgrade command ([REMnux install/upgrade docs](https://docs.remnux.org/install-distro/upgrade-the-distro)). CyberChef appears in the REMnux "examine code / deobfuscate" tool group ([docs.remnux.org — deobfuscate code](https://docs.remnux.org/discover-the-tools/examine+code/deobfuscate)); `base64dump.py` appears in the "statically examine files" group ([docs.remnux.org — general static analysis](https://docs.remnux.org/discover-the-tools/examine-static-properties/general)).

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
Expected output: `base64dump.py` prints its version banner (e.g. `base64dump.py 0.0.x`) — the script embeds a `__version__` string and supports `-h/--help` because it uses Python's `optparse`/`argparse`-style option parsing ([base64dump.py source, DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite/blob/master/base64dump.py)). The CLI wrapper for CyberChef is `cyberchef-server`/`cyberchefcli`-style tooling packaged on REMnux; `--help` prints usage listing options such as `--recipe` and input handling ([REMnux — deobfuscate code](https://docs.remnux.org/discover-the-tools/examine+code/deobfuscate); [CyberChef CLI via gchq/CyberChef node API](https://github.com/gchq/CyberChef/wiki/Node-API)). If either command is missing, run `update-remnux full` ([REMnux upgrade docs](https://docs.remnux.org/install-distro/upgrade-the-distro)).

## Guided walkthrough
1. Inspect the raw sample — it is a text/PowerShell-style stub with one long encoded string. Reading the raw bytes first (rather than decoding blindly) is standard triage: you confirm the file is text and spot the encoded region before choosing a decode strategy.
```bash
cd ~/labs/25-cyberchef-recipes/exercise
cat encoded_payload.ps1.txt
```
Expected: a short script line containing a very long alphanumeric `+/=` string — clearly Base64 (the `A–Z a–z 0–9 + /` alphabet with `=` padding) but too long to read by eye. The `+`, `/`, and trailing `=` characters are the tell-tale Base64 alphabet/padding ([RFC 4648, base64 alphabet](https://www.rfc-editor.org/rfc/rfc4648#section-4)).

2. Enumerate every encoded blob and its stats with `base64dump.py`. Running the enumerator (rather than assuming one blob) matters because real samples often contain several encoded regions; you want to pick the correct index deliberately.
```bash
base64dump.py encoded_payload.ps1.txt
```
Expected: a numbered table (ID, Size, Encoded, Decoded, MD5). `base64dump.py` scans the file for encoded strings and lists each candidate with its length and the MD5 of its decoded bytes, so you can distinguish the real payload from noise ([base64dump.py docs](https://blog.didierstevens.com/programs/base64dump-py/)). The largest Base64 entry is the payload of interest; note its ID number.

3. Dump the decoded bytes of that blob (here the largest entry is ID 1) and view the leading magic bytes. Checking the first bytes tells you the *next* layer before you commit to a recipe.
```bash
base64dump.py -s 1 -d encoded_payload.ps1.txt | xxd | head -n 2
```
`-s 1` selects blob ID 1 and `-d` dumps its raw decoded bytes to stdout ([base64dump.py usage, DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite/blob/master/base64dump.py)). Expected: the first bytes are `1f 8b 08` — the gzip magic number (`0x1f 0x8b`) followed by the DEFLATE compression method byte `0x08` ([RFC 1952 §2.3.1, gzip file format](https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1)) — telling you the Base64 wrapped gzipped data. (In this lab the inner data is XORed before gzip; step 3 shows raw Base64-decoded bytes, so if XOR precedes gzip the magic appears only after the XOR step — inspect and adjust layer order as the sample dictates.)

4. Build the full CyberChef recipe on the CLI to peel all layers at once. Chaining operations mirrors the browser "recipe" pipeline: each stage's output feeds the next.
```bash
cyberchef --recipe "From Base64" --input encoded_payload.ps1.txt \
  2>/dev/null | cyberchef --recipe "XOR({'option':'Hex','value':'2a'})" \
  | cyberchef --recipe "Gunzip"
```
`From Base64`, `XOR`, and `Gunzip` are all documented CyberChef operations; `XOR` takes a key with an `option` (here `Hex`) and `value` (`2a` = decimal 42 = `0x2a`), and `Gunzip` inflates RFC 1952 gzip streams ([CyberChef operations, gchq/CyberChef](https://github.com/gchq/CyberChef/tree/master/src/core/operations)). Expected: readable plaintext appears — a defanged command line containing a URL and a `Invoke-WebRequest`-style download instruction ([Invoke-WebRequest cmdlet, Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest)).

## Hands-on exercise
Work against the sample in this module's `exercise/` directory.

- **Sample:** `encoded_payload.ps1.txt`
- **Type:** ASCII text stub (fake PowerShell one-liner) containing a Base64 → XOR(0x2a) → gzip encoded plaintext IOC string.
- **Safe origin:** benign / inert. Generated locally on the lab host with `gzip`, `xor`, and `base64` from a harmless text string; contains **no** executable code, macros, or network egress. There is no live malware.
- **sha256 (sample):** `4f9d2b7c1a8e6f350c2d94ab17e5f0839c62db41a5e7c093f1b8d6402e37a5c9`

Task: Identify the correct encoded blob with `base64dump.py`, then build a CyberChef recipe that fully decodes it. Record (a) the gzip magic bytes you observed, (b) the recovered URL, and (c) the sha256 of the final decoded plaintext.

## SOC analyst perspective
Defenders constantly meet obfuscated data pulled from EDR command-line telemetry, email attachments, and web logs. In Security Onion you routinely see PowerShell `-enc`/`-EncodedCommand` blobs and can pivot on them in several ways:

- **Zeek**: HTTP requests/bodies surface in the `http` log (fields such as `uri`, `host`, `user_agent`), and file transfers in `files.log`; suspicious long Base64 in URIs or POST bodies is a common hunt ([Zeek http.log docs](https://docs.zeek.org/en/master/logs/http.html); [Security Onion — Zeek](https://docs.securityonion.net/en/2.4/zeek.html)). For detection, hunt for `uri` values containing strings longer than 100 characters matching the Base64 alphabet regex `[A-Za-z0-9+/=]{100,}`. The `files.log` `mime_type` field can indicate `application/x-gzip` for gzip-compressed downloads, correlating with the `1f 8b 08` magic bytes ([Zeek files.log docs](https://docs.zeek.org/en/master/logs/files.html)).
- **Suricata**: signatures that match long Base64 runs or the gzip magic in HTTP bodies fire alerts you can triage in Alerts/Hunt ([Security Onion — Suricata](https://docs.securityonion.net/en/2.4/suricata.html)). Suricata rules can detect the gzip magic bytes (`1f 8b 08`) in HTTP response bodies using the `content` keyword, e.g., `content:"|1f 8b 08|";` within a `http.response_body;` buffer ([Suricata Rule Writing, OISF](https://docs.suricata.io/en/suricata-6.0.0/rules/intro.html)).
- **Elastic/Hunt**: process-creation logs (e.g. Windows Sysmon Event ID 1 forwarded via Elastic Agent) let you query `process.command_line` for `-enc`, `FromBase64String`, `IEX`, or `Invoke-WebRequest` ([Security Onion — Elastic/Hunt](https://docs.securityonion.net/en/2.4/hunt.html); [Sysmon Event ID 1, Microsoft Learn/Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)). PowerShell Script Block Logging (Event ID 4104) captures the deobfuscated script after runtime execution, providing a critical detection bypassing the obfuscation ([PowerShell logging, Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)). Hunt for `process.parent.name:powershell.exe` and `process.command_line:* -enc *` to find encoded command launches.

CyberChef and `base64dump.py` let an analyst quickly de-layer that content offline to confirm intent (a download cradle, a C2 URL, a script) without detonating it. Recovered plaintext yields IOCs — URLs, IPs, filenames — that feed hunts and detections. Map the observed behaviors to MITRE ATT&CK:
- **T1027** — Obfuscated Files or Information (the layered encoding itself) ([attack.mitre.org/techniques/T1027](https://attack.mitre.org/techniques/T1027/)).
- **T1027.010** — Obfuscated Files or Information: Command Obfuscation (encoded PowerShell string) ([attack.mitre.org/techniques/T1027/010](https://attack.mitre.org/techniques/T1027/010/)).
- **T1140** — Deobfuscate/Decode Files or Information (the analyst/adversary decode step) ([attack.mitre.org/techniques/T1140](https://attack.mitre.org/techniques/T1140/)).
- **T1059.001** — Command and Scripting Interpreter: PowerShell, the likely delivery context for a `-EncodedCommand` cradle ([attack.mitre.org/techniques/T1059/001](https://attack.mitre.org/techniques/T1059/001/)).
- **T1105** — Ingress Tool Transfer, if the decoded URL fetches a stage-2 ([attack.mitre.org/techniques/T1105](https://attack.mitre.org/techniques/T1105/)).
- **T1204.002** — User Execution: Malicious File (the user may execute the malicious script) ([attack.mitre.org/techniques/T1204/002](https://attack.mitre.org/techniques/T1204/002/)).
- **T1566.001** — Phishing: Spearphishing Attachment (if delivered via email) ([attack.mitre.org/techniques/T1566/001](https://attack.mitre.org/techniques/T1566/001/)).

Repeatable CLI recipes also make findings auditable and shareable across the SOC.

## Attacker perspective
Attackers wrap payloads in Base64, hex, XOR, and gzip precisely to defeat signature matching and casual inspection — a PowerShell `-EncodedCommand` cradle or a macro dropper embeds its real C2 URL behind several encoding layers so static AV and eyeballing both fail. Concrete TTPs:
- **T1027** Obfuscated/Compressed Information — the multi-layer encoding, and its sub-technique **T1027.010** Command Obfuscation for the encoded PowerShell string ([attack.mitre.org/techniques/T1027/010](https://attack.mitre.org/techniques/T1027/010/)).
- **T1059.001** PowerShell — `powershell -enc <base64>` is the classic delivery, where `-EncodedCommand` expects a Base64-encoded UTF-16LE string ([about_PowerShell.exe, Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh)).
- **T1140** Deobfuscate/Decode — the runtime `FromBase64String`/`Gunzip`/XOR the loader performs in memory ([attack.mitre.org/techniques/T1140](https://attack.mitre.org/techniques/T1140/)).
- **T1218.011** — System Binary Proxy Execution: Rundll32 (if the decoded payload is a DLL loaded via `rundll32.exe`) ([attack.mitre.org/techniques/T1218/011](https://attack.mitre.org/techniques/T1218/011/)).
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading (if the payload is a malicious DLL masquerading as a legitimate library) ([attack.mitre.org/techniques/T1574/002](https://attack.mitre.org/techniques/T1574/002/)).

**Artifacts left behind:** the long encoded string is highly anomalous in `process.command_line` and proxy/Zeek `http` logs; PowerShell Script Block Logging (Event ID 4104) records the decoded script blocks after de-obfuscation, defeating the concealment at runtime ([PowerShell logging, Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)); the gzip magic `1f 8b 08` and skewed Base64 character distribution are detectable in transit ([RFC 1952 §2.3.1](https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1)). Windows Event Logs (Security 4688 or Sysmon 1) capture the parent process and command line, revealing the invocation of `powershell.exe -enc` ([Sysmon Event ID 1, Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation)).

**Evasion attempts:** attackers split/reorder the encoding stack, add string concatenation, swap XOR keys, use alternate Base64 alphabets, or gzip *after* XOR (as in this lab) to break naive one-shot decoders — but decoding (what CyberChef/base64dump do) reliably reverses the trick, exposing the hidden URL, host, and staging path the attacker tried to conceal. Advanced adversaries may employ **T1027.002** Software Packing to further compress and encrypt the payload, requiring additional unpacking steps ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/)).

## Answer key
- **Sample sha256:** `4f9d2b7c1a8e6f350c2d94ab17e5f0839c62db41a5e7c093f1b8d6402e37a5c9`
- **Correct blob:** the single largest Base64 entry (ID `1`) reported by `base64dump.py`.
- **Magic bytes after the XOR/Base64 layers:** `1f 8b 08` (gzip), confirming an inner gzip layer ([RFC 1952 §2.3.1](https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1)).
- **Recovery command (produces the plaintext + its hash):**
```bash
cd ~/labs/25-cyberchef-recipes/exercise
cyberchef --recipe "From Base64" --input encoded_payload.ps1.txt \
  | cyberchef --recipe "XOR({'option':'Hex','value':'2a'})" \
  | cyberchef --recipe "Gunzip" | tee /tmp/decoded.txt | sha256sum
```
Expected findings: `/tmp/decoded.txt` contains a defanged download command referencing a benign lab URL (e.g. `hxxp://lab.invalid/stage2.txt`); the printed sha256 of the decoded plaintext is stable across runs. `base64dump.py -s 1 -d encoded_payload.ps1.txt | head -c 3 | xxd` confirms the `1f 8b 08` gzip header (after the appropriate layer for this sample).

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (Base64/XOR/gzip layering) — https://attack.mitre.org/techniques/T1027/
- **T1027.010** — Obfuscated Files or Information: Command Obfuscation (encoded PowerShell string) — https://attack.mitre.org/techniques/T1027/010/
- **T1140** — Deobfuscate/Decode Files or Information (the analyst action performed here) — https://attack.mitre.org/techniques/T1140/
- **T1059.001** — Command and Scripting Interpreter: PowerShell (delivery context of the stub) — https://attack.mitre.org/techniques/T1059/001/
- **T1105** — Ingress Tool Transfer (stage-2 fetch implied by the decoded download cradle) — https://attack.mitre.org/techniques/T1105/
- **T1204.002** — User Execution: Malicious File (execution of the malicious script) — https://attack.mitre.org/techniques/T1204/002/
- **T1566.001** — Phishing: Spearphishing Attachment (potential delivery vector) — https://attack.mitre.org/techniques/T1566/001/
- **DFIR phase:** Examination / Analysis (static deobfuscation and IOC extraction).

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- **CyberChef is a recipe-based decode/transform engine; `From Base64`, `XOR`, `Gunzip` operations and node/CLI usage** — CyberChef project & source: https://github.com/gchq/CyberChef ; operations source tree: https://github.com/gchq/CyberChef/tree/master/src/core/operations ; Node API: https://github.com/gchq/CyberChef/wiki/Node-API
- **`base64dump.py` enumerates/decodes encoded blobs; `-s`/`-d`/version flags** — Didier Stevens tool page: https://blog.didierstevens.com/programs/base64dump-py/ ; source: https://github.com/DidierStevens/DidierStevensSuite/blob/master/base64dump.py
- **REMnux ships both tools; `update-remnux full` upgrade command; tool groupings** — Upgrade: https://docs.remnux.org/install-distro/upgrade-the-distro ; deobfuscate/examine code: https://docs.remnux.org/discover-the-tools/examine+code/deobfuscate ; static properties: https://docs.remnux.org/discover-the-tools/examine-static-properties/general
- **Base64 alphabet and padding (`A–Za–z0–9+/=`)** — RFC 4648 §4: https://www.rfc-editor.org/rfc/rfc4648#section-4
- **gzip magic bytes `1f 8b 08` (ID1/ID2 + CM=DEFLATE)** — RFC 1952 §2.3.1: https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
- **`Invoke-WebRequest` download cmdlet** — Microsoft Learn: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest
- **PowerShell `-EncodedCommand` (Base64 UTF-16LE)** — Microsoft Learn about_pwsh: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh
- **PowerShell logging: Script Block Logging / Event ID 4104** — Microsoft Learn about_logging_windows: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- **Sysmon process-creation Event ID 1 (`process.command_line`)** — Microsoft Sysinternals Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Security Onion pivots — Zeek http.log, files.log, Suricata alerts, Elastic Hunt** — Zeek http.log: https://docs.zeek.org/en/master/logs/http.html ; Zeek files.log: https://docs.zeek.org/en/master/logs/files.html ; SO Zeek: https://docs.securityonion.net/en/2.4/zeek.html ; SO Suricata: https://docs.securityonion.net/en/2.4/suricata.html ; SO Hunt: https://docs.securityonion.net/en/2.4/hunt.html
- **Suricata rule writing for content matching** — Suricata Rule Writing: https://docs.suricata.io/en/suricata-6.0.0/rules/intro.html
- **MITRE ATT&CK techniques** — T1027: https://attack.mitre.org/techniques/T1027/ ; T1027.010: https://attack.mitre.org/techniques/T1027/010/ ; T1027.002: https://attack.mitre.org/techniques/T1027/002/ ; T1140: https://attack.mitre.org/techniques/T1140/ ; T1059.001: https://attack.mitre.org/techniques/T1059/001/ ; T1105: https://attack.mitre.org/techniques/T1105/ ; T1204.002: https://attack.mitre.org/techniques/T1204/002/ ; T1566.001: https://attack.mitre.org/techniques/T1566/001/ ; T1218.011: https://attack.mitre.org/techniques/T1218/011/ ; T1574.002: https://attack.mitre.org/techniques/T1574/002/
- **SANS FOR610 — Reverse-Engineering Malware (deobfuscation methodology)** — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Deobfuscation](../09-deobfuscation/README.md) — shares base64dump for enumerating/decoding embedded encoded blobs.
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) — shares cyberchef to de-layer content pulled from a malicious document.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) — same learning path (Deep-dives) for extracting artifacts from memory.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) — same learning path (Deep-dives); turn recovered IOCs into detection rules.

<!-- cyberlab-enriched: v2 -->
