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

> **Note on packaging:** These tools ship preinstalled on REMnux, the recommended LAB-LINUX platform for this module. On REMnux the Didier Stevens tools are invoked as `oledump.py`, `pdfid.py`, and `pdf-parser.py`, and oletools commands (`oleid`, `olevba`, `olemeta`, `oledump.py`) are on `PATH`. See the REMnux documents-analysis reference for the canonical tool list (https://docs.remnux.org/discover-the-tools/analyze+documents). The `apt install` names above are approximations for non-REMnux Debian/Kali systems; the authoritative distribution channel for the Didier Stevens tools is his own site/GitHub, and for oletools/XLMMacroDeobfuscator it is PyPI/GitHub (see Sources).

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
Expected output: `olevba` prints its version string (oletools 0.60.x is the current major line per the oletools release history: https://github.com/decalage2/oletools/releases); `oledump.py` prints its usage banner; `pdfid.py`/`pdf-parser.py` print their Didier-Stevens version lines; `xlmdeobfuscator` prints its help header. Any "command not found" means the tool is missing. (Note: `olevba` accepts both `-V`/`--version`; if `--version` is unavailable on an older build, `olevba -h` still prints the banner with the version — see the olevba docs: https://github.com/decalage2/oletools/wiki/olevba.)

## Guided walkthrough
1. `oleid` — quick triage flagging macros, encryption, and other risk indicators. Run this **first** because it is the cheapest signal: it tells you in one pass whether the file is an OLE2/OOXML Office file, whether it has VBA macros, whether it is encrypted, and whether it carries Flash/other embedded objects — before you commit to deeper extraction. `oleid` reads structure only and never executes macro code (https://github.com/decalage2/oletools/wiki/oleid).
```bash
oleid exercise/sample.doc
```
Expected: a table of indicators; the `VBA Macros` row shows `Yes` with a risk flag if macros are present. Nuance: a `Yes` here is not proof of malice — many legitimate documents contain macros — so treat it as a trigger to pull the actual VBA next, not a verdict. `oleid` also reports the OLE/OOXML file type and an `Encrypted` indicator; an encrypted-but-macro-bearing document is a common evasion (an attacker password-protects the file so most scanners cannot read the VBA), so an `Encrypted = Yes` result should raise, not lower, suspicion.

2. `olevba` — extract and display the VBA source and an auto-analysis of suspicious keywords. This is the core step: `olevba` decompresses the VBA from the macro streams and runs a heuristic keyword/IOC scan, so you read the attacker's actual code rather than guessing from metadata (https://github.com/decalage2/oletools/wiki/olevba).
```bash
olevba --decode exercise/sample.doc
```
Expected: prints the VBA modules and an "ANALYSIS" table listing items such as `AutoExec` triggers (e.g. `AutoOpen`), `Suspicious` keywords (e.g. `Shell`), and any `IOC`/decoded strings. Nuance: the `--decode` flag additionally displays the results of olevba's built-in deobfuscation of hex/base64/Dridex-style string encodings, so you see decoded URLs/commands inline; the ANALYSIS table categorizes findings as `AutoExec`, `Suspicious`, `IOC`, `Hex String`, `Base64 String`, etc. Watch specifically for the `Suspicious` rows naming `Shell`, `CreateObject`, `WScript.Shell`, `Environ`, or `URLDownloadToFile` — these are the API calls a downloader/dropper needs and map directly to the T1059 execution and ingress-download behavior discussed later.

3. `oledump.py` — list OLE streams, then dump the macro-bearing stream by index. Use this when you want to work at the raw OLE2 container level — to confirm exactly which stream holds the macro, to extract streams olevba may not surface, or to carve non-VBA embedded content (https://blog.didierstevens.com/programs/oledump-py/).
```bash
oledump.py exercise/sample.doc
oledump.py -s 3 -v exercise/sample.doc
```
Expected: the first command lists numbered streams; a stream containing VBA macro code is marked with a capital `M` (a lowercase `m` marks a stream with a macro/attribute but no substantial code). `-s 3` selects stream index 3 and `-v` decompresses the VBA and prints the source. Nuance: the exact index (`3` here) is document-specific — always read it off the listing first, since it varies between files. Watch too for an `O` marker, which flags a stream that contains an embedded OLE object (e.g. a packaged executable dropped via object-linking) — a distinct abuse path from VBA that you would carve and hash separately.

4. `pdfid.py` then `pdf-parser.py` — score a PDF, then extract the flagged object. `pdfid.py` is a fast keyword counter (it does NOT parse or execute the PDF) that tells you which risky elements are present; `pdf-parser.py` then does the real object-graph walk to pull the flagged content (https://blog.didierstevens.com/programs/pdf-tools/).
```bash
pdfid.py exercise/sample.pdf
pdf-parser.py --search JavaScript exercise/sample.pdf
```
Expected: `pdfid.py` shows nonzero counts for names such as `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, or `/EmbeddedFile`; `pdf-parser.py --search JavaScript` returns the matching object(s) so you can follow references to the JS stream. Nuance: `/OpenAction` combined with `/JavaScript` means script runs automatically on open — the classic auto-execute pattern; `/AA` (additional actions) is a stealthier variant that fires on events like page-open. To then decode a specific object's stream, use `pdf-parser.py -o <obj> -f -d out.bin` (`-f` applies stream filters, `-d` dumps).

5. `xlmdeobfuscator` — emulate Excel 4.0 macros to recover final commands. Legacy XLM (Excel 4.0) macros live in macro sheets, not VBA, so olevba's VBA path won't decode them; XLMMacroDeobfuscator interprets/emulates the cell formulas to reveal the real logic (https://github.com/DissectMalware/XLMMacroDeobfuscator).
```bash
xlmdeobfuscator --file exercise/sample.xls
```
Expected: a step-by-step trace of evaluated cells ending in the recovered payload string (e.g. a URL or `EXEC`/`Shell` call). Nuance: because it emulates rather than statically greps, it defeats cell-splitting and formula-based obfuscation that fool simple string searches; supported inputs include `.xls`, `.xlsm`, and `.xlsb` (see the project README). Recovered `EXEC(...)` cells frequently invoke `mshta`, `regsvr32`, or a WMI/`Shell` call — those tokens are your handoff into host-side detection (T1059) and the signed-binary-proxy behaviors an analyst should hunt.

## Hands-on exercise
Work only against the artifacts in this module's `exercise/` directory.

**Sample declaration**
- `exercise/sample.doc` — a **Microsoft Word 97-2003 (OLE2) document** containing a benign, inert VBA macro that only pops a message box / writes a harmless string. It performs **no network egress and no file execution**.
- Origin: generated locally for training with a hand-written VBA `AutoOpen` sub; **benign/inert, no live malware**.
- sha256: `c8d6b1b7db3374b5e29ff0e9417501b18194b21af9bfe698f4376126899f3c37`

**Tasks**
1. Confirm the document contains a macro and identify the auto-exec trigger.
2. Dump the macro stream by index using `oledump.py`.
3. List every suspicious keyword `olevba` flags and record the decoded string.
4. Compute and record the sha256 of the sample and confirm it matches the declaration.

## SOC analyst perspective
Malicious documents are a leading phishing payload, so defenders must rapidly decide whether an attachment is weaponized. Running `oleid`/`olevba` on a quarantined attachment surfaces auto-exec macros (`AutoOpen`, `Document_Open`, `Workbook_Open`) and decoded URLs/commands that become detection IOCs (olevba's ANALYSIS table explicitly labels `AutoExec`, `Suspicious`, and `IOC` rows — https://github.com/decalage2/oletools/wiki/olevba).

**Concrete detection logic and pivots (Security Onion):**
- **Extract IOCs, then pivot in Zeek.** Take any URL/domain olevba decodes and search Zeek `http.log` (fields `host` and `uri`) and `dns.log` (field `query`) in Kibana to find which internal hosts resolved/fetched the second stage. Zeek `files.log` (with the file-extraction framework enabled) gives you the `sha256` and `mime_type` fields of downloaded objects to correlate against your extracted hash. A high-value hunt: a `dns.log` `query` for a newly-registered/low-reputation domain that immediately precedes an `http.log` `GET` to the same `host` for a `.hta`, `.ps1`, or `.exe` `uri` — the download-cradle signature of a macro-launched stager. See Security Onion docs: https://docs.securityonion.net/en/2.4/zeek.html.
- **Suricata alerts.** Correlate the timeframe with Suricata signatures for document-borne downloaders in the Alerts dashboard; Suricata is the IDS/NSM alerting engine in Security Onion (https://docs.securityonion.net/en/2.4/suricata.html). Pivot on the alert's `http.user_agent` — macro downloaders using `URLDownloadToFile` or PowerShell's `WebClient` frequently present a default/anomalous user-agent that stands out against browser baselines, and Suricata surfaces it as an alert flow you can pin the source host from.
- **Host telemetry pattern to hunt.** The highest-fidelity behavioral tell is an Office process spawning a scripting host — e.g. `winword.exe`/`excel.exe` → `powershell.exe`/`cmd.exe`/`wscript.exe`/`mshta.exe` (Sysmon Event ID 1, process create, using the `ParentImage`→`Image` and `CommandLine` fields — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Two further host-side detections extend coverage: (1) **PowerShell script-block logging, Microsoft-Windows-PowerShell/Operational Event ID 4104**, captures the decoded/deobfuscated script text even when the macro passes an encoded `-EncodedCommand`, directly countering T1027 obfuscation (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows); and (2) signed-binary-proxy execution launched from the document — `mshta.exe`, `regsvr32.exe`, `rundll32.exe` spawned by an Office parent — maps to **T1218 (System Binary Proxy Execution)** and its sub-techniques **T1218.005 (Mshta)** and **T1218.010 (Regsvr32)** (https://attack.mitre.org/techniques/T1218/), which are visible in the same Sysmon Event ID 1 `ParentImage`/`Image` chain. Turn decoded strings into hunt queries and detection content.
- **Threat-hunting pivots.** From a confirmed malicious attachment: (a) hash-pivot the extracted stager SHA256 across Zeek `files.log` and endpoint EDR to find every host that received it; (b) hunt Office child-process anomalies fleet-wide over the mail-delivery window to catch users who opened the same lure; (c) pivot the decoded C2 domain through `dns.log` `query` to enumerate additional beaconing hosts.

**MITRE ATT&CK mapping used for scoping:** T1566.001 (Spearphishing Attachment), T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell) / T1059.003 (Windows Command Shell), T1027 (Obfuscated Files or Information), T1218.005 (Mshta) / T1218.010 (Regsvr32), and T1105 (Ingress Tool Transfer, for the second-stage download). These let the IR team scope the intrusion and write detection coverage. (Technique pages linked in Sources.)

## Attacker perspective
Attackers embed VBA or Excel 4.0 (XLM) macros that trigger on open (`AutoOpen`, `Document_Open`, `Workbook_Open`) to run a downloader or spawn PowerShell/`cmd` (this user-triggered execution is T1204.002 — https://attack.mitre.org/techniques/T1204/002/, delivered via T1566.001 — https://attack.mitre.org/techniques/T1566/001/). They obfuscate strings (char-code math, base64, string concatenation, XLM cell-splitting) to evade AV signatures, which maps to T1027, Obfuscated Files or Information (https://attack.mitre.org/techniques/T1027/). Once running, the macro's job is usually to pull a second stage over HTTP(S) — Ingress Tool Transfer, **T1105** (https://attack.mitre.org/techniques/T1105/) — via `URLDownloadToFile`, `MSXML2.XMLHTTP`, or a PowerShell `WebClient`/`Invoke-WebRequest` cradle. PDFs are abused with `/OpenAction` + `/JavaScript` or embedded `/Launch` actions so that opening the file auto-executes script.

**Concrete TTPs and the artifacts they leave behind:**
- The OLE2/OOXML document itself carries macro streams and metadata recoverable with `oleid`, `olemeta`, and `oledump.py` (macro streams flagged `M`; embedded OLE objects flagged `O`). `olemeta` timestamps and author/company fields can tie a lure to a builder kit or campaign.
- Rather than run the interpreter directly, mature actors proxy execution through trusted signed binaries — `mshta.exe` fetching a remote `.hta`, or `regsvr32.exe` with the "Squiblydoo" scriptlet technique (`regsvr32 /s /n /u /i:http://...`) — which is System Binary Proxy Execution, **T1218.005 (Mshta)** and **T1218.010 (Regsvr32)** (https://attack.mitre.org/techniques/T1218/005/, https://attack.mitre.org/techniques/T1218/010/). The artifact is an Office→signed-LOLBin parent/child chain in Sysmon Event ID 1 and the outbound fetch in Zeek `http.log`.
- Behaviorally, Office spawning a scripting interpreter is visible as a parent→child process chain in EDR/Sysmon (Event ID 1 — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), mapping to T1059.001/T1059.003 (https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1059/003/). PowerShell's decoded command still lands in Event ID 4104 script-block logs even when passed as `-EncodedCommand`.
- Downloaded stagers commonly land in `%TEMP%` / `%APPDATA%` / user profile paths, and the fetch is observable in network telemetry (Zeek `http.log` `host`/`uri`, `dns.log` `query`, `files.log` `sha256`).

**Evasion:** decoded strings and the file hash are still evidence a defender can pivot on, but attackers reduce that signal by encrypting the document (password-protected OLE, which `oleid` flags as `Encrypted`, so the VBA is unreadable until the mailed password is applied), by using benign-looking remote template injection (**T1221, Template Injection** — https://attack.mitre.org/techniques/T1221/, where the .docx references a remote `.dotm` so the malicious macro is not in the delivered file at all), and by heavy formula/string obfuscation (T1027) that static grep misses — which is exactly why emulation-based tooling (XLMMacroDeobfuscator) and olevba's `--decode` deobfuscation exist. Remote-template loads still leave an artifact: the initial HTTP(S) `GET` for the `.dotm` in Zeek `http.log` at document-open time, which is itself a detection opportunity.

## Answer key
- Sample sha256: `c8d6b1b7db3374b5e29ff0e9417501b18194b21af9bfe698f4376126899f3c37`
- Verify integrity:
```bash
sha256sum exercise/sample.doc
```
Expected: hash equals the declared value above.
- Confirm macro + auto-exec trigger:
```bash
olevba exercise/sample.doc | grep -E "AutoExec|AutoOpen|Suspicious"
```
Expected: an `AutoExec` row for `AutoOpen` (runs when the document is opened) in the analysis table. (olevba labels auto-execution triggers as `AutoExec` — https://github.com/decalage2/oletools/wiki/olevba.)
- Dump the macro stream:
```bash
oledump.py exercise/sample.doc
oledump.py -s 3 -v exercise/sample.doc
```
Expected: the stream listing marks the macro stream with `M`; `-s 3 -v` prints the decompressed benign VBA (message box / harmless string, no network or execution calls). (Stream markers and `-s`/`-v` behavior per https://blog.didierstevens.com/programs/oledump-py/.)

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (initial access). https://attack.mitre.org/techniques/T1566/001/
- **T1204.002** — User Execution: Malicious File. https://attack.mitre.org/techniques/T1204/002/
- **T1059.001 / T1059.003** — Command and Scripting Interpreter (PowerShell / Windows Command Shell) commonly launched by macros. https://attack.mitre.org/techniques/T1059/001/ , https://attack.mitre.org/techniques/T1059/003/
- **T1027** — Obfuscated Files or Information (macro/XLM obfuscation). https://attack.mitre.org/techniques/T1027/
- **T1105** — Ingress Tool Transfer (macro pulls a second-stage payload). https://attack.mitre.org/techniques/T1105/
- **T1218.005 / T1218.010** — System Binary Proxy Execution: Mshta / Regsvr32 (signed-LOLBin execution launched from the document). https://attack.mitre.org/techniques/T1218/005/ , https://attack.mitre.org/techniques/T1218/010/
- **T1221** — Template Injection (remote `.dotm` load to keep the macro out of the delivered file). https://attack.mitre.org/techniques/T1221/
- **DFIR phase:** Identification and Examination (triage of a suspicious attachment and static extraction of IOCs).

## Sources
Claim → source mapping (all URLs are official tool docs/repos, MITRE ATT&CK, Microsoft Learn, SANS, or recognized project docs):

- REMnux tool availability and invocation (`oledump.py`, `pdfid.py`, `pdf-parser.py`, oletools) — REMnux documents-analysis reference: https://docs.remnux.org/discover-the-tools/analyze+documents
- oletools suite overview and install (PyPI/GitHub) — https://github.com/decalage2/oletools/wiki
- oletools release/version line (0.60.x) — https://github.com/decalage2/oletools/releases
- `oleid` behavior (structure-only triage, VBA/encryption/embedded-object flags) — https://github.com/decalage2/oletools/wiki/oleid
- `olevba` behavior (VBA extraction, `--decode`, ANALYSIS categories `AutoExec`/`Suspicious`/`IOC`, suspicious API keywords) — https://github.com/decalage2/oletools/wiki/olevba
- `oledump.py` behavior (stream listing, `M`/`m`/`O` markers, `-s`/`-v` flags) — https://blog.didierstevens.com/programs/oledump-py/
- `pdfid.py` / `pdf-parser.py` behavior (keyword counting vs object walking, `/OpenAction`/`/AA`, `--search`, `-o/-f/-d`) — https://blog.didierstevens.com/programs/pdf-tools/
- XLMMacroDeobfuscator (XLM emulation, supported formats, `--file`) — https://github.com/DissectMalware/XLMMacroDeobfuscator
- Sysmon Event ID 1 (process create; `ParentImage`/`Image`/`CommandLine` fields) for Office→scripting-host detection — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- PowerShell script-block logging (Event ID 4104) for decoded script text — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Security Onion — Zeek (`http.log` `host`/`uri`, `dns.log` `query`, `files.log` `sha256`/`mime_type` pivots) — https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion — Suricata (IDS/NSM alerting, `http.user_agent`) — https://docs.securityonion.net/en/2.4/suricata.html
- SANS FOR610 (Reverse-Engineering Malware) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1566.001 — https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1204.002 — https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1059.001 — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1059.003 — https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK T1027 — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1105 (Ingress Tool Transfer) — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1218 / T1218.005 / T1218.010 (System Binary Proxy Execution, Mshta, Regsvr32) — https://attack.mitre.org/techniques/T1218/ , https://attack.mitre.org/techniques/T1218/005/ , https://attack.mitre.org/techniques/T1218/010/
- MITRE ATT&CK T1221 (Template Injection) — https://attack.mitre.org/techniques/T1221/

## Related modules
- [oletools macro analysis deep-dive](../36-oletools-deep/README.md) -- shares oledump/olevba for deeper VBA extraction.
- [PDF analysis (pdfid / pdf-parser)](../37-pdf-analysis/README.md) -- shares pdf-parser for full PDF object-graph work.
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- shares oletools in an end-to-end case.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations).

<!-- cyberlab-enriched: v2 -->
