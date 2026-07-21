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

Tool attributions: CyberChef is developed by GCHQ ([github.com/gchq/CyberChef](https://github.com/gchq/CyberChef)). xortool is by "hellman" ([github.com/hellman/xortool](https://github.com/hellman/xortool)). XORSearch and base64dump.py are part of Didier Stevens' tool suite ([blog.didierstevens.com/programs/xorsearch/](https://blog.didierstevens.com/programs/xorsearch/), [github.com/DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite)). All four are documented as shipping on REMnux under "Deobfuscate Data" ([docs.remnux.org/discover-the-tools/deobfuscate+data](https://docs.remnux.org/discover-the-tools/deobfuscate+data)).

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
Expected output: `XORSearch` prints its usage/help banner (XORSearch's `-h` shows option help; per Didier Stevens' docs the tool takes `[-options] file string`); `base64dump.py` prints a version line (e.g. `base64dump.py 0.0.x`); `xortool` prints a version string; the CyberChef directory listing and confirmation line appear.

> Note: the exact CyberChef install path can vary between REMnux releases. If the `ls` line prints nothing, run `which cyberchef` or `cyberchef --help` to confirm the launcher is present — REMnux ships CyberChef as a locally launchable tool ([docs.remnux.org/discover-the-tools/deobfuscate+data](https://docs.remnux.org/discover-the-tools/deobfuscate+data)). Treat the specific directory as an example, not a guaranteed path.

## Guided walkthrough
1. `XORSearch` — brute-forces XOR (and, with flags, ROL/ROT/SHIFT) keys against a file looking for a known plaintext, so you can find a hidden URL. We search for the literal string `http` because C2 URLs almost always begin that way, giving XORSearch a reliable "crib" (known plaintext) to test each candidate key against. Per Didier Stevens' documentation, XORSearch by default tries all 256 single-byte XOR keys plus ROL keys and reports the position where the search string is found.
```bash
# Search a file for the string 'http' under all single-byte XOR keys
XORSearch -s exercise/encoded_payload.bin http
```
Expected observable output: one or more lines such as `Found XOR 5A position 0010: http://198.51.100.23/update` showing the key byte (0x5A) and the recovered plaintext. WHY this matters: the key byte reported IS the obfuscation key for the whole region if the author used one static single-byte XOR — you can now decode the entire buffer with that byte. The `-s` flag saves the decoded output to a file so you can carve the full plaintext, not just the matching line. (Note: without `-s` XORSearch still prints matches; the `-s` here is used in the sense documented by the tool — check `XORSearch -h` on your build for exact flag semantics, as options differ slightly by version.)

2. `base64dump.py` — lists every Base64-looking (and other-alphabet) blob in a file with a numeric ID, then decodes a chosen one. WHY: scripts and documents often carry the real payload as a Base64 string; base64dump automatically finds candidate blobs so you don't have to eyeball them, and it reports each blob's length and MD5 so you can prioritize the largest/most interesting one.
```bash
# List candidate encoded blobs, then decode blob ID 1
base64dump.py exercise/encoded_payload.bin
base64dump.py -s 1 -d exercise/encoded_payload.bin | head -c 200
```
Expected observable output: a table of blobs (ID, size/length, encoding, MD5); the `-s 1 -d` selects blob ID 1 (`-s`) and dumps its decoded content (`-d`) to stdout. Nuance: a "valid Base64" blob is not proof of real content — random high-entropy data can accidentally look Base64-ish, so confirm the decoded bytes are meaningful (readable strings, a PE `MZ` header, a URL) before treating them as an IOC. Flag reference: `base64dump.py` uses `-s` to select a stream/blob and `-d` to dump the decoded content ([blog.didierstevens.com/2015/06/12/base64dump-py/](https://blog.didierstevens.com/2015/06/12/base64dump-py/)).

3. `xortool` — estimates the most likely XOR key length and the key itself for multi-byte (repeating-key) XOR. WHY: single-byte XOR is a special case (key length 1); xortool's frequency/entropy analysis confirms whether the data is single- or multi-byte XOR and recovers the repeating key. The `-c` option tells xortool the most frequent byte in the *plaintext* (commonly `20`, ASCII space, for text) so it can align the key.
```bash
# Guess key length and key; assume the space char (0x20) is the most common plaintext byte
xortool -c 20 exercise/encoded_payload.bin
```
Expected observable output: `The most probable key length is:` / a histogram of candidate lengths, then `Found N possible key(s):` listing candidate keys; decoded output is written to `./xortool_out/` ([github.com/hellman/xortool](https://github.com/hellman/xortool)). Nuance: for our sample the dominant key length should be **1**, confirming a single-byte key; if xortool proposes a longer length it is usually a multiple of the true length — prefer the shortest strongly-scoring candidate.

4. `cyberchef` — open the local CyberChef and paste a blob to visually chain `From Base64` → `XOR` recipes. WHY: for stacked encodings (Base64-then-XOR, or gzip-wrapped payloads) a GUI lets you iterate quickly and see intermediate output at each step, and the "Magic" operation can auto-suggest likely decodings.
```bash
# Launch the offline CyberChef copy shipped with REMnux
cyberchef &
```
Expected observable output: the browser opens the local CyberChef page (no internet required) where you build a decode recipe. Nuance: because it is the offline copy, no sample data leaves the analysis VM — important when the "blob" could be live malware ([github.com/gchq/CyberChef](https://github.com/gchq/CyberChef), [docs.remnux.org/discover-the-tools/deobfuscate+data](https://docs.remnux.org/discover-the-tools/deobfuscate+data)).

## Hands-on exercise
Recover the hidden command-and-control URL from the sample.

Sample declaration:
- **File:** `exercise/encoded_payload.bin`
- **Type:** benign, inert binary blob containing a single-byte XOR-encoded URL string plus one embedded Base64 blob. Contains NO executable code and NO live malware.
- **Safe origin:** generated locally for this lab by XOR-encoding a harmless RFC-5737 documentation-range URL (`http://198.51.100.23/update`) with key byte `0x5A`; no network egress. Reproducible offline.
- **sha256:** `06ae969a275e9dce37ed7c1e897f9146ded3b97c14afbad5e65eac1640f8e558`

(The `198.51.100.0/24` range is reserved for documentation by RFC 5737, so it is safe to publish and will not route to a real host — [datatracker.ietf.org/doc/html/rfc5737](https://datatracker.ietf.org/doc/html/rfc5737).)

Task: use XORSearch to find the XOR key and the plaintext URL, use xortool to confirm the key, and use base64dump to decode the embedded Base64 blob. Report the recovered URL and the XOR key byte.

## SOC analyst perspective
Defenders meet obfuscation constantly: phishing macros, PowerShell droppers, and beacon configs almost always Base64- or XOR-encode their URLs and IPs to dodge signatures. Deobfuscating them yields clean IOCs (domains, IPs, mutex names) that you pivot on in Security Onion.

Concrete detection and pivot logic:
- **Pivot on the recovered host.** Once you decode `198.51.100.23`, search Zeek `conn.log` for `id.resp_h == 198.51.100.23` and `http.log` for the `/update` URI to find every host that beaconed. Security Onion surfaces Zeek and Suricata data in Kibana/Elastic; pivot from an alert to the correlated Zeek logs for the same `community_id`/flow ([docs.securityonion.net](https://docs.securityonion.net/), [docs.zeek.org](https://docs.zeek.org/en/master/logs/index.html)).
- **Write detection content.** Add the IOC to a Zeek Intel Framework file (`intel.dat`) so future contact auto-alerts ([docs.zeek.org/en/master/frameworks/intel.html](https://docs.zeek.org/en/master/frameworks/intel.html)), and/or author a Suricata rule matching the host/URI (Suricata rule syntax: [docs.suricata.io/en/latest/rules/](https://docs.suricata.io/en/latest/rules/)).
- **Hunt for the obfuscation itself, not just the IOC.** PowerShell `-EncodedCommand` Base64 blobs and long high-entropy strings are detectable on the endpoint: hunt Windows PowerShell script-block logs (Event ID 4104) and Sysmon process-creation (Event ID 1) for encoded command lines ([learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows), [learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).

MITRE mapping: recovering the plaintext is the examination step for **T1027 – Obfuscated Files or Information** ([attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)) and its command-based analog **T1140 – Deobfuscate/Decode Files or Information** ([attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)); encoded-payload command lines frequently overlap with **T1059.001 – PowerShell** ([attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)). Turning an opaque sample into an IOC produces actionable detection content and hunting hypotheses across the fleet.

**Additional MITRE ATT&CK technique IDs:**
- **T1046 – Data Encoding** — used to encode payloads in memory or on disk ([attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)).
- **T1567 – Process Injection** — obfuscation is often used to evade detection when injecting code into a process ([attack.mitre.org/techniques/T1567/](https://attack.mitre.org/techniques/T1567/)).

**Detection logic examples:**
- In **Zeek logs**, look for high-entropy strings in `http.body` or `file_data` that match Base64 patterns (e.g., `^[A-Za-z0-9+/]+={0,2}$`) or XOR-encoded artifacts.
- In **Suricata**, use a rule like `alert http any any -> any any (content:"base64"; sid:1000001; msg:"Base64-encoded payload detected";)` to flag Base64 strings in HTTP payloads.
- In **Windows Event Logs**, search for Event ID 4104 with `ScriptBlockText` containing long high-entropy strings or Base64 patterns.

**Threat-hunting pivots:**
- Correlate decoded URLs with **SIEM alerts** for suspicious network traffic (e.g., outbound HTTP requests to the decoded domain).
- Use **endpoint detection tools** to hunt for PowerShell scripts with `EncodedCommand` arguments or process memory containing XOR-encoded strings.
- Investigate **file hashes** of decoded payloads in the **SIEM or endpoint logs** to identify potential malicious file activity.

## Attacker perspective
Attackers XOR- or Base64-encode strings so static AV, YARA rules, and casual analysts miss embedded URLs, credentials, and shellcode (**T1027 – Obfuscated Files or Information**, [attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)). Single-byte XOR is cheap and defeats naive `strings`; multi-byte/repeating-key XOR and stacked encodings (Base64-then-XOR, or gzip-then-Base64) raise the bar further, and CyberChef-style "recipes" are shared to templatize the obfuscation. Command-line delivery frequently uses PowerShell `-EncodedCommand` (base64 UTF-16LE), mapping to **T1059.001** ([attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)) and the encoded-file sub-technique **T1027.013 – Encrypted/Encoded File** ([attack.mitre.org/techniques/T1027/013/](https://attack.mitre.org/techniques/T1027/013/)).

Artifacts the technique leaves for the defender:
- High-entropy byte runs in an otherwise low-entropy file (the encoded region stands out to entropy tooling).
- The decode routine and the XOR key itself are usually stored in the binary/script (the key must exist somewhere to decode at runtime), so disassembly or brute force recovers it.
- Recognizable Base64 alphabets and long `=`-padded strings in scripts, and the tell-tale `powershell -enc <base64>` pattern in process telemetry.

Evasion refinements attackers add: rotating/multi-byte keys, custom Base64 alphabets, splitting the blob across multiple variables, and computing the key at runtime — each raises analyst effort but leaves the same class of fingerprints (entropy, a decode stub, an eventual plaintext in memory). These fingerprints let XORSearch/xortool brute-force the key and let entropy tooling flag the encoded region — so obfuscation delays but does not prevent recovery of the underlying IOCs.

**Additional TTPs:**
- **T1046 – Data Encoding** — attackers may encode payloads in memory or on disk to avoid detection.
- **T1567 – Process Injection** — obfuscation is often used to evade detection when injecting code into a process.

**Evasion techniques:**
- **Custom Base64 alphabets** — attackers may use non-standard alphabets to avoid detection by pattern-based tools.
- **Key computation at runtime** — attackers may compute the XOR key dynamically using a hash or other algorithm, making brute-force recovery more difficult.
- **Splitting encoded data** — attackers may split the encoded payload into multiple variables or parts to avoid detection by string-based tools.

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
- **T1027 – Obfuscated Files or Information** (encoding of payload/IOCs) — [attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/).
- **T1027.013 – Encrypted/Encoded File** (XOR/Base64 layering) — [attack.mitre.org/techniques/T1027/013/](https://attack.mitre.org/techniques/T1027/013/).
- **T1140 – Deobfuscate/Decode Files or Information** (the analyst action performed here) — [attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/).
- **T1059.001 – Command and Scripting Interpreter: PowerShell** (common carrier of Base64-encoded payloads defenders will deobfuscate) — [attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/).
- **T1046 – Data Encoding** (used to encode payloads in memory or on disk) — [attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/).
- **T1567 – Process Injection** (obfuscation is often used to evade detection when injecting code into a process) — [attack.mitre.org/techniques/T1567/](https://attack.mitre.org/techniques/T1567/).
- **DFIR phase:** Examination / Analysis (extracting and decoding artifacts to derive IOCs after identification).

## Sources
Claim → source mapping:
- REMnux ships XORSearch, base64dump.py, xortool, and CyberChef under "Deobfuscate Data": https://docs.remnux.org/discover-the-tools/deobfuscate+data
- XORSearch behavior/flags (brute-forces XOR/ROL keys against a search string): https://blog.didierstevens.com/programs/xorsearch/
- base64dump.py behavior and `-s`/`-d` flags (find and decode embedded blobs): https://blog.didierstevens.com/2015/06/12/base64dump-py/
- Didier Stevens Suite (source repo for XORSearch/base64dump.py): https://github.com/DidierStevens/DidierStevensSuite
- xortool key-length/key recovery and `-c`/`-l` options, `xortool_out/` output: https://github.com/hellman/xortool
- CyberChef (GCHQ) — offline recipe builder, "From Base64"/"XOR"/"Magic" operations: https://github.com/gchq/CyberChef
- MITRE ATT&CK T1027 – Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.013 – Encrypted/Encoded File: https://attack.mitre.org/techniques/T1027/013/
- MITRE ATT&CK T1140 – Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1059.001 – PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1046 – Data Encoding: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1567 – Process Injection: https://attack.mitre.org/techniques/T1567/
- RFC 5737 (198.51.100.0/24 documentation range, safe non-routable IPs): https://datatracker.ietf.org/doc/html/rfc5737
- Security Onion documentation (alert-to-log pivots, Zeek/Suricata/Elastic): https://docs.securityonion.net/
- Zeek log reference (conn.log, http.log): https://docs.zeek.org/en/master/logs/index.html
- Zeek Intel Framework (intel entries for recovered IOCs): https://docs.zeek.org/en/master/frameworks/intel.html
- Suricata rule syntax (writing detection for recovered host/URI): https://docs.suricata.io/en/latest/rules/
- Windows PowerShell script-block logging (Event ID 4104): https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Sysmon process-creation events (Event ID 1) for encoded command lines: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SANS FOR610 Reverse-Engineering Malware (deobfuscation methodology context): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [CyberChef recipes for malware data](../25-cyberchef-recipes/README.md) -- shares base64dump for extracting encoded blobs before recipe-based decoding.
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- shares CyberChef to deobfuscate macro/document payloads in a full case.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same Foundations learning path; recover the on-disk artifacts that carry encoded payloads.
- [Memory forensics](../02-memory-forensics/README.md) -- same Foundations learning path; find decoded plaintext and keys in process memory.

<!-- cyberlab-enriched: v2 -->
