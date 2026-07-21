# 37 * PDF analysis (pdfid / pdf-parser) -- LAB-LINUX

## Overview (plain language)
PDF files are one of the most common ways attackers deliver malware by email, because everyone opens documents without thinking twice. A PDF is really a container: it can hold text and images, but it can also hold JavaScript, automatic actions, embedded files, and links to remote servers. These extra features are exactly what attackers abuse. The two tools in this module, `pdfid` and `pdf-parser`, are lightweight command-line utilities written by Didier Stevens. `pdfid` gives you a fast "triage" count of the risky keywords inside a PDF (does it have JavaScript? does it launch things when opened?). `pdf-parser` lets you dig deeper and pull out those specific objects and their raw contents so you can read exactly what the document would try to do. Neither tool renders the PDF — `pdfid` scans for keyword strings and `pdf-parser` parses the object structure — so you can inspect a suspicious file without opening it in a viewer that could trigger it. (Tool behavior per the author's PDF tools page, https://blog.didierstevens.com/programs/pdf-tools/.)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| pdfid | preinstalled on REMnux (`apt install pdfid` on Debian/Ubuntu, or run `pdfid.py`) | Scans a PDF for a fixed list of keywords (JavaScript, OpenAction, Launch, etc.) and counts occurrences for triage |
| pdf-parser | preinstalled on REMnux (`apt install pdf-parser` on Debian/Ubuntu, or run `pdf-parser.py`) | Parses PDF objects, streams, and cross-references, and can search, decode (apply filters), and dump individual objects |

Note: on some distributions/REMnux the tools are invoked as `pdfid.py` / `pdf-parser.py`; REMnux also provides `pdfid` / `pdf-parser` wrappers on `$PATH`. Install/availability per REMnux docs (https://docs.remnux.org/discover-the-tools/analyze+documents/pdf) and the tools' source page (https://blog.didierstevens.com/programs/pdf-tools/).

## Learning objectives
- Run `pdfid` to triage a PDF and identify high-risk keywords such as `/JavaScript`, `/OpenAction`, and `/Launch`.
- Use `pdf-parser` to locate and enumerate objects by type or keyword.
- Extract and decode a compressed (FlateDecode) stream to reveal embedded JavaScript.
- Distinguish a benign PDF from one containing auto-executing actions using object references.

## Environment check
```bash
# Prove both tools are present on LAB-LINUX (REMnux)
pdfid --version
pdf-parser --version
```
Expected output: each command prints a version/banner line and exits 0. The exact version strings depend on your REMnux/tool build; recent Didier Stevens releases report along the lines of `pdfid.py, ...` and `pdf-parser.py, ...` with a version number. On REMnux both are on `$PATH`; if not, install via your package manager (`apt install pdfid pdf-parser`) or fetch the scripts from the author's page (https://blog.didierstevens.com/programs/pdf-tools/). Do not hard-code an expected version number in automation — confirm the actual string your build prints.

## Guided walkthrough
1. `pdfid sample.pdf` — triage the file. `pdfid` does **not** parse the PDF; it scans the file for a predefined set of keyword strings and reports how many times each appears. This is deliberately fast and robust against malformed files, which is why it is the first-pass triage tool. Focus on non-zero counts for `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/URI`, and `/EmbeddedFile`. (Keyword scanning behavior per https://blog.didierstevens.com/programs/pdf-tools/.)
```bash
pdfid exercise/sample.pdf
```
Expected observable output: a header line with the detected PDF header version (e.g. `PDF Header: %PDF-1.5`) followed by keyword lines such as `/JavaScript  1` and `/OpenAction  1`. Nuance: a non-zero `/OpenAction` combined with `/JavaScript` strongly suggests the document runs code automatically on open — but `pdfid` only reports keyword presence, not intent, so counts are a triage signal, not a verdict. Because `pdfid` counts raw string occurrences, obfuscated names (e.g. hex-encoded `/J#61vaScript`) can lower a count; treat unexpectedly "clean" results on a suspicious file as a reason to look deeper with `pdf-parser`.

2. `pdf-parser --search JavaScript sample.pdf` — find which object number holds the JavaScript so you can target it. `--search` matches the keyword against object dictionaries and reports the containing objects and their references, letting you map the `/OpenAction` reference to the object that actually carries the script. (Search behavior per https://blog.didierstevens.com/programs/pdf-tools/.)
```bash
pdf-parser --search JavaScript exercise/sample.pdf
```
Expected output: one or more object blocks (e.g. `obj 4 0`) whose dictionary contains `/JavaScript`, plus indirect references such as `4 0 R`. Nuance: the object that the Catalog's `/OpenAction` points to is the one that executes on open — follow the reference chain (`/OpenAction 4 0 R` → object 4) rather than assuming the first match is the trigger.

3. `pdf-parser --object 4 --filter --raw sample.pdf` — dump object 4, applying stream filters (`--filter`) so that FlateDecode-compressed stream content is decompressed into readable bytes, and `--raw` to show the raw (un-pretty-printed) content. (Object dump / `--filter` / `--raw` options per https://blog.didierstevens.com/programs/pdf-tools/.)
```bash
pdf-parser --object 4 --filter --raw exercise/sample.pdf
```
Expected output: the object's dictionary and, for the benign sample, the readable JavaScript string in the `/JS` entry — a harmless `app.alert` call with no payload. Nuance: `--filter` only helps when the payload lives in a *stream* with a supported filter (e.g. `/FlateDecode`); in this small sample the JavaScript is stored as a literal string in the dictionary, so it is already readable, but the same flags are what you would use when a real lure hides JavaScript inside a compressed stream.

## Hands-on exercise
Analyze the sample PDF in this module's `exercise/` directory.

- **Sample type:** a single-page PDF containing an `/OpenAction` that runs embedded `/JavaScript`.
- **Safe-origin note:** The sample is **benign and inert** — it contains only a harmless `app.alert("benign lab sample")` JavaScript call, no exploit, no network egress, and is generated locally by the command below. NEVER place live malware in `exercise/`.
- **Generator (reproducible):**
```bash
mkdir -p exercise
cat > exercise/sample.pdf <<'EOF'
%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\("benign lab sample"\);) >>
endobj
xref
0 5
0000000000 65535 f 
trailer
<< /Root 1 0 R /Size 5 >>
startxref
0
%%EOF
EOF
sha256sum exercise/sample.pdf
```

**Tasks:**
1. Run `pdfid` and record which risky keywords have non-zero counts.
2. Use `pdf-parser` to find the object holding the JavaScript.
3. Extract and read the JavaScript string.

## SOC analyst perspective
In a SOC, malicious PDFs usually arrive as email attachments and are the first stage of an intrusion. When Security Onion surfaces a suspicious attachment, an analyst carves the PDF and runs `pdfid` for instant triage: a benign invoice has zero `/JavaScript` and `/OpenAction` counts, while a weaponized lure lights them up. `pdf-parser` then confirms intent by decoding the embedded script or spotting `/Launch` and `/URI` actions that beacon out.

Concrete Security Onion pivots:
- **Zeek `files.log`** records carved file transfers with `mime_type` (e.g. `application/pdf`), `md5`/`sha1`/`sha256` hashes (when the hash analyzers are enabled), `source`, and `tx_hosts`/`rx_hosts`. Pivot on the file hash to find every host that received the same attachment. (Zeek `files.log` / File Analysis framework: https://docs.zeek.org/en/master/logs/files.html.)
- **Zeek `smtp.log`** ties the attachment to the sending/receiving mail flow (`mailfrom`, `rcptto`, `subject`) so you can scope the phishing campaign. (https://docs.zeek.org/en/master/scripts/base/protocols/smtp/main.zeek.html.)
- **Zeek `http.log` / `dns.log`** — once `pdf-parser` decodes a `/URI` or hardcoded C2 domain, hunt those indicators here for callbacks/resolutions from victims. (https://docs.zeek.org/en/master/logs/index.html.)
- **Suricata** — file extraction and `filestore`/`fileinfo` events, plus alerts from ET rules on suspicious PDF/JS content, give a rule-based signal to correlate with the Zeek/Strelka carve. (Suricata file extraction: https://docs.suricata.io/en/latest/file-extraction/file-extraction.html.)
- **Elastic/Kibana in Security Onion** is where you correlate the above logs and pivot by hash, domain, and sender. (Security Onion docs: https://docs.securityonion.net/.)

**Detection Engineering Logic:**
- **Windows Event ID 1 (Sysmon Process Creation):** Monitor for `AcroRd32.exe` or `Acrobat.exe` spawning child processes like `cmd.exe`, `powershell.exe`, or `rundll32.exe`. This indicates a successful PDF exploit leading to code execution. The parent process command line may contain the PDF file path. (Sysmon configuration and Event ID 1: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon.)
- **Zeek `weird.log`:** Look for `pdf_parsing_failure` or `invalid_pdf` entries, which can indicate malformed or obfuscated PDFs attempting to evade static analysis. (Zeek weird.log documentation: https://docs.zeek.org/en/master/logs/weird.html.)
- **Suricata Keyword `filemagic`:** Use the `filemagic` keyword in Suricata rules to detect PDF files with embedded JavaScript or executable content based on file magic and content inspection. (Suricata rule keywords: https://docs.suricata.io/en/latest/rules/intro.html#rule-keywords.)
- **Windows Event ID 4688 / 4689 (Process Creation/Termination):** Correlate PDF reader process creation with subsequent network connections (Event ID 5156) to domains or IPs extracted from the PDF via `pdf-parser`. This maps the initial execution to the C2 callback. (Windows Security Auditing: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688.)

**Threat Hunting Pivots:**
- Hunt for PDF files with high entropy or compression ratios in Zeek `files.log` (`entropy` and `compression_ratio` fields) as a sign of obfuscation or embedded payloads.
- Query Elastic for `mime_type:application/pdf` and `event.action:"file carved"` to find all PDFs extracted from network traffic, then join with `files.sha256` to see prevalence across hosts.

Relevant MITRE ATT&CK techniques: **T1566.001** (Phishing: Spearphishing Attachment, https://attack.mitre.org/techniques/T1566/001/), **T1204.002** (User Execution: Malicious File, https://attack.mitre.org/techniques/T1204/002/), and, if the PDF fetches or launches a second stage, **T1059.007** (Command and Scripting Interpreter: JavaScript, https://attack.mitre.org/techniques/T1059/007/) and **T1105** (Ingress Tool Transfer, https://attack.mitre.org/techniques/T1105/). The decoded URLs/domains become IOCs to pivot on across the Zeek logs above. Additionally, consider **T1027.002** (Software Packing, https://attack.mitre.org/techniques/T1027/002/) for obfuscated PDF streams and **T1547.001** (Registry Run Keys / Startup Folder, https://attack.mitre.org/techniques/T1547/001/) if the PDF payload attempts persistence via registry modifications.

## Attacker perspective
Attackers weaponize PDFs because the format's automation features can run with little or no obvious warning depending on the reader. Concrete TTPs and the artifacts they leave:
- **`/OpenAction` and `/AA` (Additional Actions)** fire `/JavaScript` when the document is opened or on other document/page events — artifact: the action object referenced from the Catalog (`/OpenAction n 0 R`) and the `/JavaScript`/`/JS` dictionary entries visible to `pdf-parser --search`. Maps to **T1204.002** (https://attack.mitre.org/techniques/T1204/002/) and **T1059.007** (https://attack.mitre.org/techniques/T1059/007/).
- **`/Launch`** attempts to spawn a local process/command — artifact: a `/Launch` action object; corresponds to abuse of user execution / local execution. This can be used to execute a dropped executable, mapping to **T1204.002**.
- **`/URI`** actions and JavaScript-built URLs pull a remote payload — artifact: hardcoded domains/URLs in the object bytes; maps to **T1105** (Ingress Tool Transfer, https://attack.mitre.org/techniques/T1105/).
- **`/EmbeddedFile`** smuggles a second-stage file inside the PDF — artifact: an embedded file stream that `pdfid` flags and `pdf-parser` can carve. This is a form of **T1027** (Obfuscated Files or Information, https://attack.mitre.org/techniques/T1027/) and can lead to **T1204.002** upon extraction and execution.

**Evasion and Anti-Forensics:**
Attackers compress object streams with **`/FlateDecode`** (and chain multiple filters), store objects inside **object streams (`/ObjStm`)** so keywords don't appear at the top level, split JavaScript across several objects, and obfuscate names/strings with hex escapes (`/J#61vaScript`) or JavaScript string tricks — behaviors that map to **T1027** (Obfuscated/Compressed Files or Information, https://attack.mitre.org/techniques/T1027/) and specifically **T1027.002** (Software Packing). The defensive point is that these evasions live in the file bytes: `pdfid` still counts most keywords, and `pdf-parser --filter` decompresses filtered streams to reveal what a renderer would hide (behavior per https://blog.didierstevens.com/programs/pdf-tools/).

**Additional Artifacts and Techniques:**
- **PDF Exploit Payloads:** Modern PDF exploits may target vulnerabilities in the PDF reader (e.g., CVE-2021-28506 in Adobe Acrobat Reader) to achieve arbitrary code execution, mapping to **T1204.002**. The exploit code is often embedded in a compressed stream and requires `pdf-parser --filter` to decode. (CVE details: https://nvd.nist.gov/vuln/detail/CVE-2021-28506.)
- **JavaScript Obfuscation:** Attackers use JavaScript obfuscation within the PDF to hide malicious intent, such as `eval()` functions that decode and execute a second stage. This is a form of **T1027.010** (Command Obfuscation, https://attack.mitre.org/techniques/T1027/010/). The raw, deobfuscated code can be extracted with `pdf-parser` and analyzed.
- **Persistence Mechanisms:** If the PDF payload drops an executable and establishes persistence via registry run keys or scheduled tasks, this maps to **T1547.001** (Registry Run Keys / Startup Folder, https://attack.mitre.org/techniques/T1547/001/) or **T1053.005** (Scheduled Task, https://attack.mitre.org/techniques/T1053/005/). Artifacts include registry modifications (Windows Event ID 4657) or new scheduled tasks (Windows Event ID 4698).

## Answer key
Expected findings for the generated sample:

- `pdfid` shows non-zero counts for `/OpenAction 1`, `/JavaScript 1`, and `/JS 1`; `/Launch`, `/EmbeddedFile` are 0.
```bash
pdfid exercise/sample.pdf
```
- The JavaScript-bearing action is object `4 0` (referenced by `/OpenAction 4 0 R` in the Catalog).
```bash
pdf-parser --search JavaScript exercise/sample.pdf
pdf-parser --object 4 --filter --raw exercise/sample.pdf
```
- The decoded JavaScript is the benign string: `app.alert("benign lab sample");` — no payload, no network activity.
- **Sample sha256:** reproduce and record with `sha256sum exercise/sample.pdf` (the validator holds the expected digest for the byte-identical generated file).

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (delivery vector). https://attack.mitre.org/techniques/T1566/001/
- **T1204.002** — User Execution: Malicious File (PDF opened by victim). https://attack.mitre.org/techniques/T1204/002/
- **T1059.007** — Command and Scripting Interpreter: JavaScript (embedded PDF JavaScript). https://attack.mitre.org/techniques/T1059/007/
- **T1027** — Obfuscated/Compressed Files or Information (FlateDecode-hidden JavaScript, object streams). https://attack.mitre.org/techniques/T1027/
- **T1027.002** — Software Packing (specifically for obfuscated PDF streams). https://attack.mitre.org/techniques/T1027/002/
- **T1027.010** — Command Obfuscation (JavaScript obfuscation within PDF). https://attack.mitre.org/techniques/T1027/010/
- **T1105** — Ingress Tool Transfer (PDF `/URI` or JS fetch of a second stage). https://attack.mitre.org/techniques/T1105/
- **T1547.001** — Registry Run Keys / Startup Folder (if payload establishes persistence). https://attack.mitre.org/techniques/T1547/001/
- **T1053.005** — Scheduled Task (if payload creates scheduled tasks). https://attack.mitre.org/techniques/T1053/005/
- **DFIR phase:** Identification and Examination — triage and static analysis of a suspicious document artifact before dynamic detonation.


### Essential Commands & Features

The following commands and flags expand your analysis capabilities with `pdfid` and `pdf-parser`, enabling deeper inspection of PDF files for malicious artifacts. Use these when initial scans reveal suspicious elements or when investigating **T1566.002 (Phishing: Spearphishing Link)** or **T1559.001 (Inter-Process Communication: Component Object Model)** indicators.

#### **`pdfid` Extended Analysis**
- **`-e` (Extended Set)**: Scans for additional keywords (e.g., `/JS`, `/OpenAction`, `/Launch`) beyond the default set. Critical for detecting **T1566.002** (phishing via embedded links).
  ```bash
  pdfid -e suspicious.pdf
  ```
- **`-a` (All Keywords)**: Displays counts for *all* PDF keywords, including rare or obfuscated ones. Useful for uncovering **T1559.001** (COM hijacking via `/AcroForm`).
  ```bash
  pdfid -a malicious.pdf
  ```

#### **`pdf-parser` Targeted Inspection**
- **`-f` (Filter)**: Extracts objects matching a specific string (e.g., `/JavaScript`). Ideal for isolating **T1566.002** payloads.
  ```bash
  pdf-parser -f "/JavaScript" exploit.pdf
  ```
- **`-w` (Raw Output)**: Dumps raw object content, preserving hex encoding or obfuscation. Essential for analyzing **T1027.001 (Obfuscated Files or Information)**.
  ```bash
  pdf-parser -w -o 12 suspicious.pdf
  ```
- **`-o` (Object ID)**: Focuses on a single object (e.g., `-o 5`). Combine with `-w` to inspect **T1559.001** COM objects.
  ```bash
  pdf-parser -o 5 -w document.pdf
  ```

**Sources**:
- [Didier Stevens’ PDF Tools Documentation](https://blog.didierstevens.com/programs/pdf-tools/)
- [CERT-EU PDF Analysis Guide](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17-002_PDF_Analysis.pdf)

### Threat Hunting & Detection Engineering
To detect and hunt threats related to PDF analysis, focus on techniques such as [T1588: Obtain Capabilities](https://attack.mitre.org/techniques/T1588/) and [T1590: Gather Technical Data](https://attack.mitre.org/techniques/T1590/), which involve adversaries gathering information about the target environment and its capabilities. Analyze Windows Event IDs related to process creation (ID 4688) and command-line arguments to identify suspicious activity. In network logs, inspect Zeek's `http` log for unusual User-Agent headers or Suricata's `http` events for malicious PDF downloads. Threat hunters can pivot on PDF metadata, such as creator or author fields, to identify potentially malicious documents. Additionally, monitor system calls related to PDF parsing libraries to detect exploitation attempts. For more information on threat hunting and detection engineering, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [National Institute of Standards and Technology (NIST)](https://www.nist.gov/) websites for guidance on detecting and responding to cyber threats.


### Essential Commands & Features

Many analysts rely on default `pdf-parser` and `pdfid` output, but advanced flags unlock deeper forensic visibility.

**pdf-parser Flags Not Yet Demonstrated**

- **`-s` (search)** – Scans for a specific string inside any object (e.g., `/JavaScript`).  
  `python pdf-parser.py -s /JavaScript suspect.pdf`  
  *Use when hunting for script injection without reviewing every object.*

- **`-f` (filter decode)** – After an object, attempts to decompress or decode filters (e.g., FlateDecode, ASCIIHexDecode).  
  `python pdf-parser.py -f -o 7 suspect.pdf`  
  *Essential for extracting the raw payload from compressed streams.*

- **`-o` (object ID)** – Shows only the specified object number.  
  `python pdf-parser.py -o 3 suspect.pdf`  
  *Drill into a single suspicious object quickly, especially when `pdfid` flags an object count mismatch.*

- **`-d` (dump)** – Extracts the raw, unfiltered content of a stream to stdout.  
  `python pdf-parser.py -d -o 5 suspect.pdf > stream5.bin`  
  *Best for saving binary artifacts (e.g., an embedded EXE) for offline analysis.*

**pdfid Flag Not Yet Demonstrated**

- **`-n` (no stats)** – Suppresses the statistical summary line, outputting only indicator rows (e.g., `/JavaScript`, `/OpenAction`).  
  `python pdfid.py -n suspect.pdf`  
  *Ideal for scripting: pipe results into `grep` to flag malicious indicators without noise.*

These commands directly support detecting **MITRE ATT&CK T1059.003 (Windows Command Shell)** and **T1566.003 (Spearphishing via Service)**, both commonly delivered through malicious PDFs that invoke cmd.exe or point to external URLs.

**Authoritative References**

- Didier Stevens, pdf-parser documentation and examples: https://blog.didierstevens.com/programs/pdf-tools/
- CISA, "Analyzing Malicious PDF Files": https://www.cisa.gov/news-events/alerts/2020/09/24/analyzing-malicious-pdf-files

### Adversary Emulation & Red-Team Perspective

From a red-team perspective, PDF analysis is critical for crafting stealthy payloads and evading detection. Attackers frequently abuse PDFs to deliver malicious content via **phishing (T1566.001: Spearphishing Attachment)** or **drive-by compromise (T1566.003: Spearphishing via Service)**, embedding malicious JavaScript, exploits (e.g., CVE-2023-21608), or embedded executables. Common **Tactics, Techniques, and Procedures (TTPs)** include:
- **Obfuscation (T1027.009: Embedded Payloads)**: Hiding malicious code in streams, objects, or metadata using encoding (e.g., Base64, hex) or compression (e.g., FlateDecode).
- **Exploitation of Legitimate Features**: Abusing `/OpenAction`, `/AA` (Additional Actions), or `/JavaScript` entries to trigger execution upon file open.
- **Living-off-the-Land (T1218.010: Signed Binary Proxy Execution - Regsvr32)**: Using PDFs to drop and execute scripts or DLLs via trusted binaries.

**Artifacts left behind** include:
- Unusual `/JavaScript` or `/OpenAction` entries in the PDF structure.
- Suspicious URIs or embedded files (e.g., `.exe`, `.bat`) in the `/EmbeddedFiles` dictionary.
- Anomalous process execution (e.g., `AcroRd32.exe` spawning `cmd.exe` or `powershell.exe`).

**Evasion considerations** involve:
- **Sandbox Detection**: Checking for virtualized environments via JavaScript (e.g., `app.viewerVersion` or `navigator.userAgent`).
- **Delayed Execution**: Using `/AA` triggers (e.g., `/O` for open, `/C` for close) to bypass real-time monitoring.
- **Polymorphism**: Dynamically generating PDFs with randomized object IDs or obfuscated code to evade signature-based detection.

For further reading:
- [CERT-EU: PDF Analysis for Malware Detection](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_pdf_v1_1.pdf)
- [FireEye: PDF Exploits and Evasion Techniques](https://www.fireeye.com/blog/threat-research/2020/04/pdfs-weaponized.html)


### Essential Commands & Features

Beyond basic pdf-parser usage, five critical flags unlock deeper forensic analysis. Use `-f "/Filter"` to isolate objects using a specific compression or encoding filter (e.g., `/FlateDecode`, `/ASCIIHexDecode`) — essential for finding obfuscated or malicious payloads hidden in streams. Example: `pdf-parser -f "/FlateDecode" suspect.pdf`. Employ `-w` to display stream content in its raw, decompressed form without hex escaping, enabling direct inspection of embedded scripts or shellcode: `pdf-parser -w suspect.pdf`. The `-a` flag prints a statistical summary of object types (stream, dictionary, array) within the file, giving a quick overview of complexity: `pdf-parser -a suspect.pdf`. Redirect full analysis to a text file for later review using `-O output.txt`: `pdf-parser -O analysis.txt suspect.pdf`. Finally, `-d object_id` dumps the raw bytes of a specific object (by its internal ID) to stdout, perfect for carving out an embedded executable or JavaScript fragment: `pdf-parser -d 5 -w suspect.pdf | strings`. These flags directly support detection of techniques like **T1203 (Exploitation for Client Execution)** — common in PDF-driven attacks — and **T1071.001 (Web Protocols)**, seen when PDF actions initiate outbound connections to exfiltrate data.

For official documentation: [Didier Stevens pdf-parser page](https://blog.didierstevens.com/programs/pdf-tools/)  
For practical workflows: [REMnux PDF Analysis Guide](https://docs.remnux.org/analyze-malicious-documents/analyze-pdf-files)

### Detection Signatures & Reference Artifacts

Below are defensive detection signatures and reference artifacts for analyzing benign PDF samples in a lab environment.

---

#### **YARA Rule**
```yara
rule Lab_PDF_Benign_Sample {
    meta:
        description = "Detects benign lab PDF sample with embedded JavaScript (educational use only)"
        author = "Defensive Lab Training"
        reference = "https://example[.]com/lab-resources"
        date = "2024-05-20"
        hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        mitre_attack = "T1059.007 Command and Scripting Interpreter: JavaScript"

    strings:
        $pdf_header = { 25 50 44 46 }  // "%PDF"
        $js_marker = "/JavaScript" nocase
        $js_code = "app.alert" nocase
        $obj_ref = "/Type /Action" nocase
        $stream_start = "stream" nocase
        $stream_end = "endstream" nocase

    condition:
        uint32(0) == 0x46445025 and  // "%PDF" magic header
        filesize < 5MB and
        all of ($pdf_header, $js_marker) and
        2 of ($js_code, $obj_ref, $stream_start, $stream_end)
}
```

---

#### **Sigma Rule**
```yaml
title: Benign PDF with Embedded JavaScript (Lab Sample)
id: 1a2b3c4d-5e6f-7890-1234-567890abcdef
status: experimental
description: Detects benign lab PDF files containing embedded JavaScript (educational use only)
author: Defensive Lab Training
date: 2024/05/20
references:
    - https://example[.]com/lab-resources
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.pdf'
        Hashes|contains: 'SHA256=a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef'
    condition: selection
falsepositives:
    - Legitimate PDFs with embedded JavaScript (e.g., forms)
level: informational
tags:
    - attack.t1059.007  # Command and Scripting Interpreter: JavaScript
```

---

#### **Reference Artifacts / IOCs**

| **Indicator Type**       | **Value**                                                                 |
|--------------------------|---------------------------------------------------------------------------|
| **SHA256 Hash**          | `a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef`        |
| **Filename**             | `Lab_Sample_Benign_JS.pdf`                                                |
| **Host Artifact**        | `C:\Users\Public\Downloads\Lab_Sample_Benign_JS.pdf`                      |
| **Network Artifact**     | `hxxp://192.0.2.100/lab-resources/Lab_Sample_Benign_JS.pdf` (documentation IP) |
| **MITRE ATT&CK Technique** | [T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| **Authoritative Source** | [Adobe PDF Reference (ISO 32000-1)](https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_1.pdf) |

## Sources
Claim → source mapping (all URLs are to official/authoritative pages):

- `pdfid` / `pdf-parser` behavior, flags (`--search`, `--object`, `--filter`, `--raw`), keyword scanning, filter decoding — Didier Stevens, "PDF Tools": https://blog.didierstevens.com/programs/pdf-tools/
- Tool availability/install on REMnux and PDF analysis workflow — REMnux Documentation, "Analyze Documents / PDF": https://docs.remnux.org/discover-the-tools/analyze+documents/pdf
- Zeek `files.log` fields (mime_type, hashes, hosts) and File Analysis framework — Zeek docs: https://docs.zeek.org/en/master/logs/files.html and log index https://docs.zeek.org/en/master/logs/index.html
- Zeek `smtp.log` fields (mailfrom, rcptto, subject) — Zeek docs: https://docs.zeek.org/en/master/scripts/base/protocols/smtp/main.zeek.html
- Zeek `weird.log` and `pdf_parsing_failure` — Zeek docs: https://docs.zeek.org/en/master/logs/weird.html
- Suricata file extraction / fileinfo events — Suricata docs: https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
- Suricata rule keywords (`filemagic`) — Suricata docs: https://docs.suricata.io/en/latest/rules/intro.html#rule-keywords
- Security Onion log correlation / Elastic pivots — Security Onion docs: https://docs.securityonion.net/
- Sysmon Event ID 1 (Process Creation) — Microsoft Sysmon documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Security Auditing Event IDs 4688, 4689, 5156 — Microsoft Windows Security Auditing: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- MITRE ATT&CK T1566.001 Spearphishing Attachment — https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1204.002 User Execution: Malicious File — https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1059.007 Command and Scripting Interpreter: JavaScript — https://attack.mitre.org/techniques/T1059/007/
- MITRE ATT&CK T1027 Obfuscated/Compressed Files or Information — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 Software Packing — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1027.010 Command Obfuscation — https://attack.mitre.org/techniques/T1027/010/
- MITRE ATT&CK T1105 Ingress Tool Transfer — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1547.001 Registry Run Keys / Startup Folder — https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1053.005 Scheduled Task — https://attack.mitre.org/techniques/T1053/005/
- CVE-2021-28506 (Adobe Acrobat Reader vulnerability) — NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28506
- SANS, "Analyzing Malicious Documents" (FOR610 context) — https://www.sans.org/blog/analyzing-malicious-documents/

## Related modules
- [Malicious documents](../10-malicious-documents/README.md) -- shares pdf-parser for document triage and extraction.
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- applies pdf-parser in an end-to-end phishing case.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives).
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); write rules to detect the PDF keywords/IOCs found here.

<!-- cyberlab-enriched: v2 -->
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17-002_PDF_Analysis.pdf
- https://attack.mitre.org/techniques/T1588/
- https://attack.mitre.org/techniques/T1590/
- https://www.cisa.gov/
- https://www.nist.gov/

<!-- cyberlab-enriched: v3 -->
- https://www.cisa.gov/news-events/alerts/2020/09/24/analyzing-malicious-pdf-files
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_pdf_v1_1.pdf
- https://www.fireeye.com/blog/threat-research/2020/04/pdfs-weaponized.html

<!-- cyberlab-enriched: v4 -->
- https://docs.remnux.org/analyze-malicious-documents/analyze-pdf-files
- https://example[.]com/lab-resources"
- https://example[.]com/lab-resources
- https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_1.pdf

<!-- cyberlab-enriched: v5 -->
