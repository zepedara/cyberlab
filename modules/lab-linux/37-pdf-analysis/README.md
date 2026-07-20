# 37 * PDF analysis (pdfid / pdf-parser) -- LAB-LINUX

## Overview (plain language)
PDF files are one of the most common ways attackers deliver malware by email, because everyone opens documents without thinking twice. A PDF is really a container: it can hold text and images, but it can also hold JavaScript, automatic actions, embedded files, and links to remote servers. These extra features are exactly what attackers abuse. The two tools in this module, `pdfid` and `pdf-parser`, are lightweight command-line utilities written by Didier Stevens. `pdfid` gives you a fast "triage" count of the risky keywords inside a PDF (does it have JavaScript? does it launch things when opened?). `pdf-parser` lets you dig deeper and pull out those specific objects and their raw contents so you can read exactly what the document would try to do. Neither tool opens or renders the PDF, so you can inspect a suspicious file safely without triggering it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| pdfid | apt install pdfid (preinstalled on REMnux) | Quickly counts suspicious PDF keywords (JavaScript, OpenAction, Launch, etc.) for triage |
| pdf-parser | apt install pdf-parser (preinstalled on REMnux) | Parses and extracts individual PDF objects, streams, and their decoded contents |

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
Expected output: each command prints a version/banner line (e.g. `pdfid 0.2.x` and `pdf-parser 0.7.x`) and exits 0. On REMnux both are on `$PATH`; if not, `apt install pdfid pdf-parser`.

## Guided walkthrough
1. `pdfid sample.pdf` — triage the file; it prints a table counting how many times each dangerous keyword appears. Focus on non-zero counts for `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, and `/EmbeddedFile`.
```bash
pdfid exercise/sample.pdf
```
Expected observable output: a header with the PDF version followed by keyword lines such as `/JavaScript  1` and `/OpenAction  1`, indicating the document runs code automatically when opened.

2. `pdf-parser --search JavaScript sample.pdf` — find which object number holds the JavaScript so you can target it.
```bash
pdf-parser --search JavaScript exercise/sample.pdf
```
Expected output: one or more object blocks (e.g. `obj 5 0`) whose dictionary contains `/JavaScript` and a reference like `5 0 R`.

3. `pdf-parser --object 5 --filter --raw sample.pdf` — dump object 5, applying stream filters (`--filter`) so FlateDecode-compressed content is decompressed into readable text.
```bash
pdf-parser --object 5 --filter --raw exercise/sample.pdf
```
Expected output: the decoded object contents, including the readable JavaScript string (for the benign sample this is a harmless `app.alert` call — no payload).

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
In a SOC, malicious PDFs usually arrive as email attachments and are the first stage of an intrusion. When Security Onion surfaces a suspicious attachment (via Zeek `files.log`, Suricata file extraction, or a Strelka/YARA hit), an analyst carves the PDF from the PCAP and runs `pdfid` for instant triage: a benign invoice has zero `/JavaScript` and `/OpenAction` counts, while a weaponized lure lights them up. `pdf-parser` then confirms intent by decoding the embedded script or spotting `/Launch` and `/URI` actions that beacon out. This maps to MITRE ATT&CK T1566.001 (Spearphishing Attachment) and T1204.002 (User Execution: Malicious File); the decoded URLs/domains become IOCs to pivot on in Zeek `dns.log` and `http.log` for hunting other victims.

## Attacker perspective
Attackers weaponize PDFs because the format's automation features run without obvious warnings. They embed `/OpenAction` or `/AA` (Additional Actions) that fire `/JavaScript` the moment the file opens, use `/Launch` to spawn a local process, `/URI` to pull a remote payload, or `/EmbeddedFile` to smuggle a second-stage binary. To evade detection they compress object streams with FlateDecode, split JavaScript across multiple objects, or obfuscate it with hex/escape encoding. The artifacts left behind for a defender are exactly what these tools reveal: the presence of those keywords in the raw structure, the object numbers and cross-references, and — once filters are applied — the decoded script and any hardcoded C2 URL, which a renderer would hide but the file bytes cannot.

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
- **T1566.001** — Phishing: Spearphishing Attachment (delivery vector).
- **T1204.002** — User Execution: Malicious File (PDF opened by victim).
- **T1027** — Obfuscated/Compressed Files or Information (FlateDecode-hidden JavaScript).
- **DFIR phase:** Identification and Examination — triage and static analysis of a suspicious document artifact before dynamic detonation.

## Sources
- Didier Stevens, "pdfid.py" — https://blog.didierstevens.com/programs/pdf-tools/
- Didier Stevens, "pdf-parser.py" — https://blog.didierstevens.com/programs/pdf-tools/
- REMnux Documentation, "Examine Static Properties of Documents / PDF" — https://docs.remnux.org/discover-the-tools/analyze+documents/pdf
- MITRE ATT&CK, T1566.001 Spearphishing Attachment — https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK, T1204.002 User Execution: Malicious File — https://attack.mitre.org/techniques/T1204/002/
- SANS FOR610 / "Analyzing Malicious PDFs" — https://www.sans.org/blog/analyzing-malicious-documents/