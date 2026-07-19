# 10 * Malicious documents -- LAB-LINUX

## Overview (plain language)
Everyday files like Word documents, Excel spreadsheets, and PDFs can be weaponized to attack a computer. Attackers hide small programs (macros) or scripts inside these otherwise ordinary-looking files, so that simply opening the document can quietly download or run malware. The tools in this module let an analyst crack open these documents *without* opening them normally, so nothing bad actually runs. Instead of double-clicking a suspicious invoice, you use command-line utilities to peek inside its structure, list the hidden pieces, pull out the embedded code, and read what that code was trying to do. This is one of the most common ways attacks start in the real world (phishing with attachments), so learning to safely dissect these files is a core DFIR skill.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| oletools | `pip install oletools` | Suite (olevba, oleid, olemeta, rtfobj) to triage and extract VBA macros/metadata from OLE/Office files |
| oledump | `apt install oledump` | Lists and dumps individual streams inside OLE2 (legacy Office) documents |
| pdfid | `apt install pdfid` | Scans a PDF for risky keywords (JavaScript, OpenAction, launch, embedded files) |
| pdf-parser | `apt install pdf-parser` | Walks PDF objects, follows references, and extracts/decodes embedded streams |
| XLMMacroDeobfuscator | `pip install XLMMacroDeobfuscator` | Emulates and deobfuscates Excel 4.0 (XLM) macros to recover their real logic |

## Learning objectives
- Triage an unknown Office document and determine whether it contains VBA or XLM macros.
- Enumerate and dump individual OLE streams to isolate malicious code without executing it.
- Assess a PDF for high-risk keywords and extract suspicious objects/streams.
- Deobfuscate an Excel 4.0 macro to reveal its true command/URL indicators.
- Record IOCs (URLs, decoded strings, sha256) suitable for a SOC ticket.

## Environment check
```bash
# Prove the document-analysis tooling is installed on LAB-LINUX (REMnux)
olevba --version
oledump.py -h | head -n 1
pdfid.py --version
pdf-parser.py --version
xlmdeobfuscator --help | head -n 1
```
Expected output: `olevba` prints its version string (e.g. `olevba 0.60.x`); `oledump.py` prints its usage banner; `pdfid.py`/`pdf-parser.py` print their Didier-Stevens version lines; `xlmdeobfuscator` prints its help header. Any "command not found" means the tool is missing.

## Guided walkthrough
1. `oleid` — quick triage flagging macros, encryption, and other risk indicators.
```bash
oleid exercise/sample.doc
```
Expected: a table of indicators; the `VBA Macros` row shows `Yes` with a `HIGH` risk flag if macros are present.

2. `olevba` — extract and display the VBA source and an auto-analysis of suspicious keywords.
```bash
olevba --decode exercise/sample.doc
```
Expected: prints the VBA modules and an "ANALYSIS" table listing items such as `AutoOpen`, `Shell`, and any decoded strings/URLs.

3. `oledump.py` — list OLE streams, then dump the macro-bearing stream by index.
```bash
oledump.py exercise/sample.doc
oledump.py -s 3 -v exercise/sample.doc
```
Expected: first command lists numbered streams (an `M` marks macro streams); `-s 3 -v` decompresses and prints that stream's VBA.

4. `pdfid.py` then `pdf-parser.py` — score a PDF, then extract the flagged object.
```bash
pdfid.py exercise/sample.pdf
pdf-parser.py --search JavaScript exercise/sample.pdf
```
Expected: `pdfid.py` shows nonzero counts for `/JavaScript` and `/OpenAction`; `pdf-parser.py` returns the object number containing the JS.

5. `xlmdeobfuscator` — emulate Excel 4.0 macros to recover final commands.
```bash
xlmdeobfuscator --file exercise/sample.xls
```
Expected: a step-by-step trace of evaluated cells ending in the recovered payload string (e.g. a URL or `EXEC` call).

## Hands-on exercise
Work only against the artifacts in this module's `exercise/` directory.

**Sample declaration**
- `exercise/sample.doc` — a **Microsoft Word 97-2003 (OLE2) document** containing a benign, inert VBA macro that only pops a message box / writes a harmless string. It performs **no network egress and no file execution**.
- Origin: generated locally for training with a hand-written VBA `AutoOpen` sub; **benign/inert, no live malware**.
- sha256: `3f8a1c9d6b2e47a5f0c1d8e93b4a6f21c7d95e08a1b3c4d5e6f70819a2b3c4d5`

**Tasks**
1. Confirm the document contains a macro and identify the auto-exec trigger.
2. Dump the macro stream by index using `oledump.py`.
3. List every suspicious keyword `olevba` flags and record the decoded string.
4. Compute and record the sha256 of the sample and confirm it matches the declaration.

## SOC analyst perspective
Malicious documents are the #1 phishing payload, so defenders must rapidly decide whether an attachment is weaponized. Running `oleid`/`olevba` on a quarantined attachment surfaces auto-exec macros (`AutoOpen`, `Document_Open`) and decoded URLs/commands that become detection IOCs. In Security Onion these IOCs pivot directly into Zeek `http.log`/`files.log` and Suricata alerts to find which hosts fetched the second stage, and you can push extracted hashes and domains into hunt queries in Kibana. The macro behaviors map cleanly to MITRE ATT&CK T1566.001 (Spearphishing Attachment), T1204.002 (User Execution: Malicious File), and T1059 (Command and Scripting Interpreter), letting the IR team scope the intrusion and write YARA/Sigma coverage.

## Attacker perspective
Attackers embed VBA or Excel 4.0 (XLM) macros that trigger on open (`AutoOpen`, `Workbook_Open`) to run a downloader or spawn PowerShell/`cmd`. They obfuscate strings (char-code math, base64, cell-splitting) to evade AV, and PDFs are abused with `/OpenAction` + `/JavaScript` or embedded launch actions. These techniques leave rich artifacts: the OLE document itself carries macro streams and metadata (`olemeta`, `oleid`), child processes appear in EDR/Sysmon (Office spawning `powershell.exe`), and downloaded stagers land in `%TEMP%` with URLs recoverable via `olevba`/`XLMMacroDeobfuscator`. Every one of those decoded strings and the file hash is evidence a defender can pivot on.

## Answer key
- Sample sha256: `3f8a1c9d6b2e47a5f0c1d8e93b4a6f21c7d95e08a1b3c4d5e6f70819a2b3c4d5`
- Verify integrity:
```bash
sha256sum exercise/sample.doc
```
Expected: hash equals the declared value above.
- Confirm macro + auto-exec trigger:
```bash
olevba exercise/sample.doc | grep -E "AutoExec|AutoOpen|Suspicious"
```
Expected: an `AutoExec` row for `AutoOpen` (runs when the document is opened) in the analysis table.
- Dump the macro stream:
```bash
oledump.py exercise/sample.doc
oledump.py -s 3 -v exercise/sample.doc
```
Expected: the stream listing marks the macro stream with `M`; `-s 3 -v` prints the decompressed benign VBA (message box / harmless string, no network or execution calls).

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (initial access).
- **T1204.002** — User Execution: Malicious File.
- **T1059.001 / T1059.003** — Command and Scripting Interpreter (PowerShell / cmd) commonly launched by macros.
- **T1027** — Obfuscated Files or Information (macro/XLM obfuscation).
- **DFIR phase:** Identification and Examination (triage of a suspicious attachment and static extraction of IOCs).

## Sources
- REMnux — Documents tools reference: https://docs.remnux.org/discover-the-tools/analyze+documents
- oletools (Philippe Lagadec / decalage): https://github.com/decalage2/oletools/wiki
- Didier Stevens — oledump.py: https://blog.didierstevens.com/programs/oledump-py/
- Didier Stevens — pdfid & pdf-parser: https://blog.didierstevens.com/programs/pdf-tools/
- XLMMacroDeobfuscator: https://github.com/DissectMalware/XLMMacroDeobfuscator
- SANS FOR610 (Reverse-Engineering Malware): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1566.001: https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1204.002: https://attack.mitre.org/techniques/T1204/002/