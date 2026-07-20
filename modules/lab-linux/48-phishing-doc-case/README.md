# 48 * Scenario: phishing document investigation -- LAB-LINUX

## Overview (plain language)
Attackers love sending everyday-looking files — a Word invoice, a PDF resume, an Excel spreadsheet — that secretly contain instructions to download and run malware. This module teaches you to safely pull apart those suspicious documents on an offline analysis machine, without ever opening them in the real Office or Adobe apps. You will use **oletools** to peek inside Office documents and read hidden macros, **pdf-parser** to inspect the guts of a PDF and find suspicious actions or embedded JavaScript, and **CyberChef** to decode the scrambled (obfuscated) text those documents use to hide the real web address or command. Think of it as carefully unwrapping a booby-trapped package with tongs behind glass, so you can see how it works and where it phones home — all without letting it hurt anything.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| oletools | apt install oletools | Analyze OLE/Office documents; extract and triage VBA macros (olevba, oleid, oledump) |
| pdf-parser | apt install pdf-parser | Parse PDF objects, streams, and actions; surface JavaScript, OpenAction, and embedded files |
| CyberChef | (bundled on REMnux; run in browser) | Decode/deobfuscate strings (Base64, XOR, URL, gunzip) extracted from documents |

> Source notes: oletools is a Python package maintained by Philippe Lagadec (decalage2); `olevba`, `oleid`, and `oledump` are all part of its documented tool set (oletools wiki, https://github.com/decalage2/oletools/wiki). `pdf-parser.py` is one of Didier Stevens' PDF Tools (https://blog.didierstevens.com/programs/pdf-tools/) and ships preinstalled on REMnux (https://docs.remnux.org/discover-the-tools/analyze+documents/pdf). CyberChef is GCHQ's open-source data-manipulation tool (https://github.com/gchq/CyberChef) and is preinstalled on REMnux (https://docs.remnux.org/discover-the-tools/browse+the+web).

## Learning objectives
- Triage an Office document with `oleid` and `olevba` to identify auto-execution macros and suspicious keywords.
- Enumerate PDF objects with `pdf-parser` to locate `/OpenAction`, `/JavaScript`, and `/URI` entries.
- Extract obfuscated payload strings from a macro/PDF and decode them using a repeatable CyberChef recipe.
- Produce a concise IOC list (URLs, dropped filenames) suitable for a SOC ticket.

## Environment check
```bash
# Prove the Office/PDF static-analysis tools are installed on LAB-LINUX
olevba --version
oleid --version
pdf-parser.py --version
echo "CyberChef is available on REMnux at file:///opt/cyberchef/CyberChef.html"
```
Expected output: `olevba` prints its oletools version banner (oletools documents `-h`/`--version` output and a version string of the form `olevba 0.60.x on Python 3.x`; see the olevba wiki, https://github.com/decalage2/oletools/wiki/olevba). `oleid` likewise reports the oletools version (https://github.com/decalage2/oletools/wiki/oleid). `pdf-parser.py --version` prints its version banner (Didier Stevens' PDF Tools, https://blog.didierstevens.com/programs/pdf-tools/). The echo confirms the local CyberChef path; the canonical REMnux launcher path is documented at https://docs.remnux.org/discover-the-tools/browse+the+web — confirm the exact path on your build with `ls /opt/cyberchef` if the file: URL does not resolve.

## Guided walkthrough
1. `oleid` — a quick indicator scan. Run it FIRST because it is fast and non-destructive: it reads the OLE structure and reports risk indicators (VBA macros, XLM/Excel 4.0 macros, encryption, Flash objects, external relationships) without dumping code, so you know whether deeper macro analysis is warranted before spending time on it.
```bash
oleid exercise/invoice_sample.doc
```
Expected: a table of indicators; the "VBA Macros" row shows a value such as `Yes` when macros are present. `oleid`'s indicator set (VBA/XLM macros, encryption, Flash, etc.) is documented in the oletools wiki (https://github.com/decalage2/oletools/wiki/oleid). Note that a `Yes` on "VBA Macros" is a *presence* flag, not proof of malice — legitimate documents also carry macros; the next step decides intent.

2. `olevba` — dump and triage VBA macro source. This is where you read the actual code and see olevba's heuristic summary. The `--decode` flag additionally attempts to decode strings the macro obfuscates (Base64, Dridex-style, hex, etc.), which is why it surfaces the hidden payload string rather than just the raw source.
```bash
olevba --decode exercise/invoice_sample.doc
```
Expected: the macro source prints, followed by olevba's "ANALYSIS" summary table that flags keywords by category — `AutoExec` items such as `AutoOpen`/`Document_Open`, `Suspicious` items such as `Shell`, and any `Base64 String` / `Hex String` the decoder recovered. The keyword categories and decoding behavior are documented in the olevba wiki (https://github.com/decalage2/oletools/wiki/olevba). Nuance: the summary marks *why* a keyword is interesting (e.g., "May run an executable file or a system command"); treat the AutoExec + Suspicious combination as the strongest signal of a weaponized macro.

3. `pdf-parser.py` — search the PDF for auto-triggered actions and scripts. `--search` matches a string in object contents (finding the object that references `/OpenAction`), while `--type` filters objects by their `/Type` or dictionary name so you can isolate the `/JavaScript` action object itself. Running both gives you the trigger and the code it points to.
```bash
pdf-parser.py --search OpenAction exercise/resume_sample.pdf
pdf-parser.py --type /JavaScript exercise/resume_sample.pdf
```
Expected: object numbers referencing `/OpenAction` and the `/JavaScript` action object, revealing the code that runs on open. `pdf-parser.py`'s `--search` and `--type` options are documented in Didier Stevens' PDF Tools (https://blog.didierstevens.com/programs/pdf-tools/). Nuance: `/OpenAction` in the document catalog is what makes JavaScript run automatically when the file opens — an `/OpenAction` pointing at a `/JavaScript` action is a classic malicious-PDF pattern (see the PDF analysis workflow on REMnux, https://docs.remnux.org/discover-the-tools/analyze+documents/pdf).

4. Decode the recovered string with CyberChef using a repeatable recipe (From Base64 → optionally URL Decode). To verify from the command line first:
```bash
echo 'aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl' | base64 -d; echo
```
Expected: `http://203.0.113.10/pay.exe` — the same result you would obtain by pasting the string into CyberChef's "From Base64" operation (CyberChef, https://gchq.github.io/CyberChef/). The `203.0.113.0/24` block is a reserved documentation range (RFC 5737), so this "URL" is safe to use as a non-routable example IOC.

## Hands-on exercise
Analyze the two benign samples in this module's `exercise/` directory and extract the hidden C2 URL.

**Sample declaration**
- `exercise/invoice_sample.doc` — a benign, inert OLE Word document containing a harmless `AutoOpen` VBA macro that only stores (never executes) a Base64 string. No live malware, no network egress.
- `exercise/resume_sample.pdf` — a benign PDF with an `/OpenAction`/`/JavaScript` object that contains only a Base64-encoded URL string (no exploit, no shellcode).

Both samples are **generated locally** by the reproducible commands in the Answer key, so no live malicious binary is ever downloaded. Run analysis in an isolated VM with networking disabled.

**Task:** Identify the auto-exec trigger in the DOC, locate the JavaScript object in the PDF, extract the Base64 blob from each, decode it, and report the resulting URL(s) and dropped filename as IOCs.

## SOC analyst perspective
A defender treats a reported phishing attachment as the "identification" trigger of an incident. Using oletools and pdf-parser on an isolated host lets an analyst confirm whether a macro auto-executes (`AutoOpen`, `Document_Open`) or a PDF fires an `/OpenAction`, then extract the C2 URL and dropped filename as IOCs.

**Concrete detection logic and pivots:**
- **Extraction → hunting.** olevba's `AutoExec` keyword category is how you confirm `AutoOpen`/`Document_Open` auto-execution (https://github.com/decalage2/oletools/wiki/olevba); its `Suspicious` category surfaces `Shell`/`powershell` invocations that map to **T1059.001** (PowerShell) and **T1059.005** (Visual Basic).
- **Security Onion / Zeek.** Pivot on the extracted host `203.0.113.10` and URL path `/pay.exe` in Zeek `http.log` (fields `host`, `uri`, `user_agent`) and on any lookup of the C2 domain in Zeek `dns.log` (`query`) — Zeek log reference: https://docs.zeek.org/en/master/logs/index.html. Security Onion exposes these logs in its Zeek/Elastic hunt interfaces (https://docs.securityonion.net/en/2.4/zeek.html).
- **Security Onion / Suricata.** Write or tune a Suricata rule to alert on outbound HTTP GET for `/pay.exe` or the staging IP; Suricata alerts surface in Security Onion's Alerts view (Suricata rule docs: https://docs.suricata.io/en/latest/rules/index.html; Security Onion Suricata docs: https://docs.securityonion.net/en/2.4/suricata.html).
- **Endpoint.** Hunt the dropped filename `pay.exe` and Office-spawns-interpreter chains (e.g., `WINWORD.EXE` → `powershell.exe`) in Sysmon **Event ID 1** (Process Create) — Sysmon docs: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon.

This maps to MITRE ATT&CK **T1566.001** (Spearphishing Attachment, https://attack.mitre.org/techniques/T1566/001/) and **T1204.002** (User Execution: Malicious File, https://attack.mitre.org/techniques/T1204/002/), letting the SOC scope who else received or opened the lure and block the infrastructure before the second-stage payload lands.

## Attacker perspective
Adversaries weaponize documents because they arrive through trusted email flows and rely on the victim to click "Enable Content."

**Concrete TTPs:**
- A VBA macro uses `AutoOpen`/`Document_Open` to run on open — MITRE tracks Office-triggered auto-execution under **T1137** (Office Application Startup, https://attack.mitre.org/techniques/T1137/) and the user-open requirement under **T1204.002** (https://attack.mitre.org/techniques/T1204/002/). The macro typically calls `Shell`, `WScript.Shell`, or `powershell -enc`, mapping to **T1059.001** (https://attack.mitre.org/techniques/T1059/001/) and **T1059.005** (https://attack.mitre.org/techniques/T1059/005/).
- The real URL is hidden via Base64, XOR, hex, or string concatenation to evade static scanners — **T1027** Obfuscated Files or Information (https://attack.mitre.org/techniques/T1027/). PowerShell `-EncodedCommand` payloads are Base64-encoded UTF-16LE (PowerShell docs: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh).
- PDFs abuse `/OpenAction` plus a `/JavaScript` action to trigger execution/downloads on open (PDF analysis workflow, https://docs.remnux.org/discover-the-tools/analyze+documents/pdf).

**Artifacts left behind:** VBA project streams inside the OLE container (recoverable with `oledump`/`olevba`, https://github.com/decalage2/oletools/wiki), `/OpenAction` and `/JS` keys visible via `pdf-parser.py` (https://blog.didierstevens.com/programs/pdf-tools/), embedded encoded strings, and — once detonated — child-process trees under the Office app (Sysmon Event ID 1, https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), temp-folder drops, and outbound HTTP recorded in Zeek `http.log` (https://docs.zeek.org/en/master/logs/index.html).

**Evasion:** macros may stall/`Sleep` or check for analysis artifacts, split strings so `powershell`/URLs never appear as literals, and store payloads in document properties or hex to defeat keyword-only scanners (the reason `olevba --decode` and manual CyberChef decoding matter).

## Answer key
**Generate the benign samples (reproducible, no live malware):**
```bash
mkdir -p exercise
# Benign PDF with OpenAction + JavaScript holding a Base64 URL string
cat > exercise/resume_sample.pdf <<'EOF'
%PDF-1.4
1 0 obj<< /Type /Catalog /OpenAction 2 0 R >>endobj
2 0 obj<< /Type /Action /S /JavaScript /JS (var u="aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl";) >>endobj
trailer<< /Root 1 0 R >>
%%EOF
EOF
# Benign OLE doc stand-in carrying the same encoded URL (inert text)
printf 'Sub AutoOpen()\n b = "aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl"\nEnd Sub\n' > exercise/invoice_sample.doc
sha256sum exercise/resume_sample.pdf exercise/invoice_sample.doc
```

**Expected findings and the commands that produce them:**
```bash
# 1) Auto-exec macro trigger in the DOC
olevba exercise/invoice_sample.doc | grep -i AutoOpen
# -> shows AutoOpen (auto-executes when document is opened)

# 2) PDF auto-action and JavaScript object
pdf-parser.py --search OpenAction exercise/resume_sample.pdf
pdf-parser.py --type /JavaScript exercise/resume_sample.pdf
# -> object 2 with /S /JavaScript and the encoded string

# 3) Decode the extracted Base64 IOC (equivalent to CyberChef "From Base64")
echo 'aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl' | base64 -d; echo
# -> http://203.0.113.10/pay.exe
```
**IOCs:** URL `http://203.0.113.10/pay.exe`; dropped filename `pay.exe`; host `203.0.113.10`.

Record the printed `sha256sum` values from the generator above as the authoritative digests for your copies of `resume_sample.pdf` and `invoice_sample.doc` (they are regenerated deterministically by the commands shown).

> Note on the `.doc` stand-in: the generated `invoice_sample.doc` is plain VBA text, not a true OLE2 container, so it is safe and deterministic for the `grep`/decode steps; `oleid`/`olevba` on a *real* OLE2 sample would additionally parse the compound-file streams (oletools wiki, https://github.com/decalage2/oletools/wiki). This is intentional to keep the lab inert and reproducible offline.

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (initial access vector). https://attack.mitre.org/techniques/T1566/001/
- **T1204.002** — User Execution: Malicious File (macro/PDF requires victim to open). https://attack.mitre.org/techniques/T1204/002/
- **T1137** — Office Application Startup / macro auto-execution. https://attack.mitre.org/techniques/T1137/
- **T1027** — Obfuscated Files or Information (Base64/XOR-encoded URL). https://attack.mitre.org/techniques/T1027/
- **T1059.001 / T1059.005** — Command & Scripting Interpreter (PowerShell / Visual Basic payload staging). https://attack.mitre.org/techniques/T1059/001/ and https://attack.mitre.org/techniques/T1059/005/
- **DFIR phases:** Identification (triage the reported attachment) and Examination/Analysis (static macro/PDF dissection and IOC extraction).

## Sources
Claim → source mapping (all URLs are official tool/project docs, MITRE ATT&CK, Microsoft Learn, or SANS):

- **oletools tools, versions, olevba keyword categories (`AutoExec`/`Suspicious`), `oleid` indicators, `oledump`, `--decode` behavior** — oletools wiki (Philippe Lagadec / decalage2): https://github.com/decalage2/oletools/wiki ; olevba page: https://github.com/decalage2/oletools/wiki/olevba ; oleid page: https://github.com/decalage2/oletools/wiki/oleid
- **pdf-parser.py behavior and `--search` / `--type` / `--version` flags** — Didier Stevens, PDF Tools: https://blog.didierstevens.com/programs/pdf-tools/
- **PDF `/OpenAction` + `/JavaScript` malicious pattern; document analysis workflow; pdf-parser on REMnux** — REMnux docs: https://docs.remnux.org/discover-the-tools/analyze+documents/pdf
- **CyberChef "From Base64" / URL Decode operations** — CyberChef (GCHQ): https://gchq.github.io/CyberChef/ and https://github.com/gchq/CyberChef
- **CyberChef availability/path on REMnux** — REMnux docs: https://docs.remnux.org/discover-the-tools/browse+the+web
- **oletools/document-analysis tradecraft (course context)** — SANS FOR610 (Reverse-Engineering Malware): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- **Zeek `http.log` / `dns.log` fields for network pivots** — Zeek logs reference: https://docs.zeek.org/en/master/logs/index.html
- **Zeek in Security Onion** — https://docs.securityonion.net/en/2.4/zeek.html
- **Suricata rules and alerting** — Suricata docs: https://docs.suricata.io/en/latest/rules/index.html ; Security Onion Suricata: https://docs.securityonion.net/en/2.4/suricata.html
- **Sysmon Event ID 1 (Process Create) for endpoint hunting** — Microsoft Learn / Sysinternals: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **PowerShell `-EncodedCommand` (Base64/UTF-16LE) behavior** — Microsoft Learn: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh
- **MITRE ATT&CK techniques** — T1566.001: https://attack.mitre.org/techniques/T1566/001/ ; T1204.002: https://attack.mitre.org/techniques/T1204/002/ ; T1137: https://attack.mitre.org/techniques/T1137/ ; T1027: https://attack.mitre.org/techniques/T1027/ ; T1059.001: https://attack.mitre.org/techniques/T1059/001/ ; T1059.005: https://attack.mitre.org/techniques/T1059/005/

## Related modules
- [Malicious documents](../10-malicious-documents/README.md) -- shares oletools for Office/macro triage.
- [Deobfuscation](../09-deobfuscation/README.md) -- shares cyberchef for decoding hidden payload strings.
- [CyberChef recipes for malware data](../25-cyberchef-recipes/README.md) -- shares cyberchef and provides reusable decode recipes.
- [oletools macro analysis deep-dive](../36-oletools-deep/README.md) -- shares oletools with a deeper VBA macro focus.

<!-- cyberlab-enriched: v1 -->
