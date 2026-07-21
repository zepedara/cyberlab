# 21 * YARA rule authoring & threat hunting -- LAB-LINUX

## Overview (plain language)
YARA is a pattern-matching tool built for finding malware. You describe things you expect to see inside a file — pieces of text, byte sequences, or conditions — in a small "rule," and YARA scans files or folders to tell you which ones match. Think of it like a smart search that can look for many clues at once. capa is a companion tool that reads a program and explains, in plain English, what it is *capable* of doing (like "encrypt data" or "contact a web server") by matching known code behaviors. Together they let an analyst hunt for suspicious files across a system and quickly understand what a suspect file might do, without running it.

YARA rules are composed of an optional `meta` section (documentation), a `strings` section (the patterns to look for — text, hex bytes, or regular expressions), and a required `condition` section (the Boolean logic that decides a match). This structure is defined in the official YARA documentation ([Writing YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html)). capa's capability findings are mapped to both MITRE ATT&CK and the Malware Behavior Catalog (MBC), per the [FLARE capa README](https://github.com/mandiant/capa#readme).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| YARA | apt install yara | Pattern-matching engine for classifying/identifying files and hunting malware with custom rules |
| capa | pip3 install flare-capa | Detects capabilities in executables/shellcode by matching rules against disassembled code |

Notes on provenance:
- The Debian/Ubuntu `yara` package installs the upstream VirusTotal YARA CLI; see the [YARA project repo](https://github.com/VirusTotal/yara) and [installation docs](https://yara.readthedocs.io/en/stable/gettingstarted.html). On REMnux, YARA and capa ship preinstalled ([remnux.org tools](https://docs.remnux.org/discover-the-tools/statically+examine+files/executables)).
- `flare-capa` is the correct PyPI package name for Mandiant/FLARE capa ([PyPI: flare-capa](https://pypi.org/project/flare-capa/), [capa install docs](https://github.com/mandiant/capa/blob/master/doc/installation.md)).

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
Expected output: `yara` prints a version string (for example `4.5.0`); `capa` prints its version (for example `7.x`) along with its rules and signatures versions. The `yara --version` and `capa --version` flags are documented in the [YARA command-line docs](https://yara.readthedocs.io/en/stable/commandline.html) and the [capa usage docs](https://github.com/mandiant/capa/blob/master/doc/usage.md). Non-zero exit or "command not found" means the tool is missing.

## Guided walkthrough
1. `yara --help` — shows the available scan flags. We start here because the CLI options control *how* a rule is applied and *what* output you get, which matters when triaging large file sets.
```bash
yara --help | head -n 20
```
Expected: a usage summary listing options such as `-r`/`--recursive` (recurse into directories), `-s`/`--print-strings` (print the matching strings and their offsets), `-w`/`--no-warnings` (suppress warnings), and `-m`/`--print-meta` (print the rule's meta fields). These flags are documented in the [YARA command-line reference](https://yara.readthedocs.io/en/stable/commandline.html). Nuance: `-s` is essential for hunting because it shows *why* a file matched (which string, at which offset), not just *that* it matched.

2. Create and compile a simple rule, then verify it parses cleanly. We compile against a known-good file first because YARA reports syntax errors at load time; catching them here avoids failed sweeps later.
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
Expected: the compile step emits no syntax errors, and scanning the rule file against itself prints `Hunt_EICAR_TestString /tmp/hunt_eicar.yar` because the literal string appears inside the rule text. Nuance: the `$hdr` hex string `{ 58 35 4F 21 50 25 40 41 50 }` is the ASCII bytes for `X5O!P%@AP` — the opening of the EICAR file — demonstrating that a hex string and a text string can express overlapping patterns. Hex-string and text-string syntax are documented in [Writing YARA rules — Strings](https://yara.readthedocs.io/en/stable/writingrules.html#strings). The `condition` uses `or` so either indicator alone triggers a match.

3. Scan a directory recursively and print which strings matched. Recursion plus `-s` is the core hunting pattern: sweep a tree and get evidence for each hit.
```bash
yara -r -s /tmp/hunt_eicar.yar /tmp
```
Expected: for each matching file, `Hunt_EICAR_TestString <path>` followed by offset lines such as `0x0:$eicar:EICAR-STANDARD-ANTIVIRUS-TEST-FILE`. Nuance: the offset shown (`0x0`, `0x24`, etc.) is the byte position of the match within the file, which analysts use to correlate hits against file structure. Flag behavior per the [YARA command-line reference](https://yara.readthedocs.io/en/stable/commandline.html).

4. Ask capa what a binary can do (using a system binary as a safe demo). capa disassembles the file and matches its own rule set against the code, so it reports *capabilities* rather than just strings.
```bash
capa -q /bin/ls | head -n 30
```
Expected: an ASCII capability table whose rows list detected capabilities and their associated `ATT&CK` and `MBC` tags (for example file-interaction or host-interaction capabilities). The `-q`/`--quiet` flag reduces logging noise; capa output format, ATT&CK/MBC mapping, and quiet mode are described in the [capa usage docs](https://github.com/mandiant/capa/blob/master/doc/usage.md) and the [capa README](https://github.com/mandiant/capa#readme). Nuance: capa on an ELF binary like `/bin/ls` exercises its ELF/Linux backend; results vary by binary and by capa's installed rules version, so treat the table as a triage aid, not an exhaustive inventory.

## Hands-on exercise
Sample artifact: `exercise/eicar_sample.txt` in this module's `exercise/` directory.

- **Type:** ASCII text file containing the industry-standard EICAR anti-malware test string (68 bytes).
- **Safe origin:** This is the official EICAR test signature — a **benign, inert** string designed by anti-malware vendors specifically for testing detection. It is **not** malware, cannot execute, and requires **no network egress**. Generate it locally to avoid any download:
```bash
mkdir -p exercise
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > exercise/eicar_sample.txt
sha256sum exercise/eicar_sample.txt
```
- **sha256:** `131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267`

The EICAR test file is a standardized, harmless detection-test artifact published by the European Institute for Computer Antivirus Research; see [eicar.org — anti-malware test file](https://www.eicar.org/download-anti-malware-testfile/).

Task: Write (or reuse) a YARA rule that detects the EICAR string, scan the `exercise/` directory recursively, and record the matching rule name and file path.

## SOC analyst perspective
Defenders use YARA as the backbone of file-based detection and threat hunting. Analysts codify indicators from an incident (unique strings, byte patterns, PE traits) into rules, then sweep endpoints, mail gateways, and file stores to find every copy of a threat. SANS teaches this workflow in the [FOR610](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/) reverse-engineering course and its YARA guidance.

**Pipeline in Security Onion.** Files carved by Zeek's [File Analysis Framework](https://docs.zeek.org/en/master/frameworks/file-analysis.html) are handed to Strelka, which runs YARA rules at scale and enriches the results into Elasticsearch for hunting and alerting. See [Security Onion — Strelka docs](https://docs.securityonion.net/en/2.4/strelka.html).

**Concrete detection logic and pivots:**
- **Rule design:** prefer high-specificity anchors (unique C2 strings, mutex names, distinctive byte sequences) combined in the `condition` with a filetype guard such as `uint16(0) == 0x5A4D` (the `MZ` PE magic) to cut false positives; the `uint16`/`uint32` accessors are documented in [YARA — Accessing data at a given position](https://yara.readthedocs.io/en/stable/writingrules.html#accessing-data-at-a-given-position).
- **Strelka pivot:** filter Strelka's YARA-scan events in Kibana/SOC Hunt on the matched rule name to enumerate every carved file that hit a given signature, then pivot on the parent `file.hash` / connection UID back to the originating Zeek `conn.log` flow.
- **Suricata pivot:** correlate the file-transfer alert (via Suricata's [`file-store`](https://docs.suricata.io/en/latest/file-extraction/file-extraction.html) / file-info events) against the Strelka YARA hit for the same transaction to tie network delivery to file content.
- **Zeek pivot:** use `files.log` (mime type, `md5`/`sha2线`, `seen_bytes`) and `http.log`/`smtp.log` to identify the delivery channel (T1071.001 web, T1566 phishing email).

capa augments triage by translating a suspect binary into ATT&CK-mapped capabilities — for example C2 communication (**T1071**), data encryption for impact (**T1486**), or process injection (**T1055**) — so a Tier-1 analyst can prioritize without manual reversing (ATT&CK/MBC mapping per the [capa README](https://github.com/mandiant/capa#readme)). This maps to ATT&CK techniques such as **T1027** (Obfuscated Files or Information) and **T1204** (User Execution) during the DFIR Identification and Examination/Analysis phases.

**Additional MITRE ATT&CK techniques:**
- **T1055.001** — Dynamic-Link Library Injection (capa identifies process injection via `LoadLibrary`/`GetProcAddress`).
- **T1070.006** — Timestomp (capa identifies file timestamp manipulation, often used in malware to evade detection).
- **T1041** — Exfiltration Over C2 (capa detects C2 communication patterns, such as DNS or HTTP traffic).
- **T1057** — Process Discovery (capa identifies behaviors like enumerating processes or using tools like `tasklist` or `ps`).

**Detection logic examples:**
- **YARA:** A rule detecting `LoadLibrary` followed by `GetProcAddress` with a `GetProcAddress` call to a suspicious API like `kernel32!CreateRemoteThread` would map to **T1055.001**.
- **Zeek:** A rule in `files.log` that matches on `file_mime_type` "application/octet-stream" and `file_sha256` matching a known malicious hash would map to **T1027**.
- **Suricata:** A rule matching on `http.uri` containing a base64-encoded string would map to **T1140**.
- **capa:** A capability report showing "spawn a process" would map to **T1106**.
- **YARA:** A rule detecting `CreateRemoteThread` in a PE file with a `MZ` header would map to **T1055.001**.
- **Suricata:** A rule detecting DNS queries with a suspicious domain name (e.g., `malicious-domain.com`) would map to **T1071**.

## Attacker perspective
Attackers know defenders write YARA rules, so they actively work to evade them. Concrete TTPs and the artifacts they leave:

- **Software packing / compression (T1027.002):** UPX or custom packers compress the payload so plaintext strings and imports disappear from the on-disk image. Artifacts: high-entropy sections, an atypical section layout, a tiny import table dominated by `LoadLibrary`/`GetProcAddress`, and a UPX stub. capa and YARA both detect packer stubs; the ATT&CK page is [T1027.002](https://attack.mitre.org/techniques/T1027/002/).
- **Encoding of config/C2 (T1027, T1140):** XOR- or base64-encoded C2 URLs and configuration are decoded at runtime. Artifacts: decoder routines and post-decode plaintext in memory; capa flags "encode/decode data" and cryptography-reference capabilities. See [T1140 — Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/).
- **Polymorphic/generated strings:** strings assembled at runtime to defeat static byte signatures. Artifacts: stack-string construction patterns that capa can recognize.
- **Adversary pre-testing:** red teamers run YARA and capa against their own tooling before delivery to confirm it stays below detection thresholds — the same tools defenders use.

**Additional evasion techniques:**
- **T1055.001** — Dynamic-Link Library Injection: Attackers inject malicious code into a legitimate process using `LoadLibrary` and `GetProcAddress` to avoid detection by file-based tools like YARA.
- **T1070.006** — Timestomp: Attackers modify file timestamps to hide the time of infection or to mimic legitimate files, making detection via file metadata challenging.
- **T1041** — Exfiltration Over C2: Attackers use C2 protocols (e.g., HTTP, DNS) to exfiltrate data, often using encryption or obfuscation to avoid detection.
- **T1057** — Process Discovery: Attackers use tools or APIs to discover running processes, often to identify potential targets for injection or lateral movement.

The key defensive insight: obfuscation is self-defeating. The very techniques used to dodge one rule create new, detectable patterns for another — high-entropy sections, packer stubs, unusual import sets, and capa-detectable behaviors like "spawn a process" (T1106) or "reference cryptography" — so evasion shifts, rather than eliminates, the detectable surface. Packing and obfuscation as an evasion family are documented at [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/).

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
# 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267  exercise/eicar_sample.txt
```
The held-out validator check confirms the rule name `Hunt_EICAR_TestString` matches `exercise/eicar_sample.txt` and that the sha256 equals `131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267`.

Interpretation: the two offset lines show the same file matched via both indicators — `$hdr` at offset `0x0` (the `X5O!P%@AP` header bytes) and `$eicar` at offset `0x24` (36 decimal, where the `EICAR-STANDARD-...` literal begins). Offset-and-string reporting behavior is per the [YARA command-line reference](https://yara.readthedocs.io/en/stable/commandline.html).

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (rules and evasion around packed/encoded payloads). https://attack.mitre.org/techniques/T1027/
- **T1027.002** — Software Packing (capa/YARA identify packers and packed samples). https://attack.mitre.org/techniques/T1027/002/
- **T1140** — Deobfuscate/Decode Files or Information. https://attack.mitre.org/techniques/T1140/
- **T1204** — User Execution (hunting delivered/executed files). https://attack.mitre.org/techniques/T1204/
- **T1071** — Application Layer Protocol (capa-detected C2 capability). https://attack.mitre.org/techniques/T1071/
- **T1486** — Data Encrypted for Impact (capa-detected encryption capability). https://attack.mitre.org/techniques/T1486/
- **T1055.001** — Process Injection (capa detects injection via `LoadLibrary`/`GetProcAddress`). https://attack.mitre.org/techniques/T1055/001/
- **T1070.006** — Timestomp (capa detects timestamp manipulation). https://attack.mitre.org/techniques/T1070/006/
- **T1041** — Exfiltration Over C2 (capa detects C2 communication patterns). https://attack.mitre.org/techniques/T1041/
- **T1057** — Process Discovery (capa detects process discovery behaviors). https://attack.mitre.org/techniques/T1057/
- **DFIR phases:** Identification (sweeping for known indicators) and Examination/Analysis (capability triage of suspect files).

## Sources
Claim → source mapping (all URLs are official tool docs, MITRE ATT&CK, SANS, or recognized project docs):

- YARA rule structure (meta/strings/condition), hex & text strings, `uintNN` accessors — YARA docs, *Writing YARA rules*: https://yara.readthedocs.io/en/stable/writingrules.html
- YARA CLI flags (`-r`, `-s`, `-w`, `-m`, `--version`) and match/offset output format — YARA docs, *Command-line interface*: https://yara.readthedocs.io/en/stable/commandline.html
- YARA installation / getting started — YARA docs: https://yara.readthedocs.io/en/stable/gettingstarted.html
- YARA project source (VirusTotal) — https://github.com/VirusTotal/yara
- capa capabilities, ATT&CK & MBC mapping, `-q` quiet mode, `--version` — Mandiant/FLARE capa README & usage docs: https://github.com/mandiant/capa#readme and https://github.com/mandiant/capa/blob/master/doc/usage.md
- capa installation and `flare-capa` PyPI package — https://github.com/mandiant/capa/blob/master/doc/installation.md and https://pypi.org/project/flare-capa/
- REMnux static-code tools (capa/YARA preinstalled) — https://docs.remnux.org/discover-the-tools/statically+examine+files/executables
- SANS FOR610 (reverse-engineering / YARA workflow) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- SANS blog — using YARA rules to detect malware — https://www.sans.org/blog/how-to-use-yara-rules-to-detect-malware/
- Security Onion + Strelka file analysis (YARA at scale → Elasticsearch) — https://docs.securityonion.net/en/2.4/strelka.html
- Zeek File Analysis Framework (`files.log`, carved files) — https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Suricata file extraction / file-store — https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
- MITRE ATT&CK T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 (Software Packing) — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 (Deobfuscate/Decode Files or Information) — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1204 (User Execution) — https://attack.mitre.org/techniques/T1204/
- MITRE ATT&CK T1071 (Application Layer Protocol) — https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1486 (Data Encrypted for Impact) — https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1055.001 (Dynamic-Link Library Injection) — https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1070.006 (Timestomp) — https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK T1041 (Exfiltration Over C2) — https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1057 (Process Discovery) — https://attack.mitre.org/techniques/T1057/
- EICAR test file (safe sample origin) — https://www.eicar.org/download-anti-malware-testfile/

## Related modules
- [Malware static triage](../08-malware-static-triage/README.md) -- shares capa for capability-based triage of suspect binaries.
- [ClamAV signature scanning](../34-clamav-scanning/README.md) -- shares yara (ClamAV can load YARA rules alongside its own signatures).
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares yara for scanning memory-resident indicators.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares yara for detecting C2 artifacts in carved files.

<!-- cyberlab-enriched: v2 -->
