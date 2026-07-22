# 18 * Malicious Office / PDF -- LAB-WINDOWS

## Overview (plain language)
Attackers love hiding malware inside everyday documents — PDFs, Word files, and OneNote notebooks — because people open them without thinking twice. This module teaches you to safely crack these documents open on FLARE-VM and look at what is *really* inside them, without ever running the malicious code. **PDFStreamDumper** lets you browse the raw internal objects and streams of a PDF file (the hidden pieces the reader normally assembles for you), decompress them, and pull out embedded scripts, links, or launch actions. **OneNoteAnalyzer** does something similar for Microsoft OneNote (`.one`) files, which became a popular malware delivery format after Microsoft blocked macros — it extracts the attachments, images, and embedded files that an attacker tucked inside a seemingly harmless note. Together these tools let an analyst answer "is this document weaponized, and what does it try to do?" using static inspection only.

A PDF is a structured collection of *objects* (dictionaries, streams, arrays) linked by a cross-reference table; a reader assembles them into a page. Stream contents are usually compressed with a filter such as `/FlateDecode`, which is why keyword-searching the raw bytes sometimes misses triggers that only appear after decompression — a nuance the guided walkthrough addresses. (PDF structure: Adobe PDF specification / ISO 32000, summarized in the pdf-parser documentation — https://blog.didierstevens.com/programs/pdf-tools/.) OneNote `.one` files use Microsoft's `[MS-ONESTORE]` on-disk format, in which embedded files are stored as `FileDataStoreObject` blobs — the structures OneNoteAnalyzer parses (format spec: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PDFStreamDumper | Bundled in FLARE-VM (installed via the FLARE-VM Chocolatey package set) | Static examiner for PDF internals — parse objects, decompress streams, extract embedded JavaScript, launch/OpenAction triggers, and embedded payloads |
| OneNoteAnalyzer | Bundled in FLARE-VM (installed via the FLARE-VM Chocolatey package set) | Parse malicious OneNote (`.one`) files to extract embedded attachments, images, and hidden files used for payload delivery |

Notes on provenance:
- PDFStreamDumper is a free, open-source PDF analysis GUI (author David Zimmer / sandsprite); it is one of the PDF tools included in the FLARE-VM package list (FLARE-VM package manifest — https://github.com/mandiant/flare-vm). Project page: http://sandsprite.com/blogs/index.php?uid=7&pid=57.
- OneNoteAnalyzer is a .NET tool that parses `.one` files and dumps embedded content and metadata (project README — https://github.com/knight0x07/OneNoteAnalyzer); it is packaged for FLARE-VM (https://github.com/mandiant/flare-vm).

## Learning objectives
- Enumerate and decompress the object streams of a PDF and locate `/OpenAction`, `/JavaScript`, and `/Launch` triggers using PDFStreamDumper.
- Extract embedded/dropped payloads from a PDF stream and record their hashes for pivoting.
- Run OneNoteAnalyzer against a `.one` file to dump embedded attachments and identify the delivered payload.
- Produce IOCs (URLs, filenames, hashes) suitable for a Security Onion detection rule without executing the document.

## Environment check
```powershell
# Confirm the tools are present on FLARE-VM.
# Paths vary by build; resolve robustly instead of assuming one location.
$pdfsd = Get-ChildItem 'C:\' -Recurse -Filter 'PDFStreamDumper.exe' -ErrorAction SilentlyContinue |
    Select-Object -First 1
$pdfsd | Select-Object FullName, Length, LastWriteTime

$onenote = Get-ChildItem 'C:\' -Recurse -Filter 'OneNoteAnalyzer.exe' -ErrorAction SilentlyContinue |
    Select-Object -First 1
$onenote | Select-Object FullName, Length, LastWriteTime
```
Expected output: a file listing showing `PDFStreamDumper.exe` (with size/timestamp) and, where installed, `OneNoteAnalyzer.exe`. FLARE-VM installs tools to varying locations across releases, so a recursive lookup is more reliable than a hard-coded path; if you already know the folder you can also use `where.exe PDFStreamDumper.exe` or `Get-Command OneNoteAnalyzer.exe -ErrorAction SilentlyContinue`. (FLARE-VM installs via Chocolatey and does not guarantee a fixed install prefix — https://github.com/mandiant/flare-vm.)

## Guided walkthrough
1. Launch PDFStreamDumper on the sample PDF from a non-networked snapshot — it opens a GUI listing every PDF object; you can visually confirm the tool loaded. **Why:** you always triage a suspected malicious document inside an isolated snapshot so that any accidental execution or network callback is contained; opening in the GUI first gives you a structural overview (object count, presence of streams) before you commit to deeper parsing.
```powershell
# Resolve the tool path (see Environment check) then open the sample.
& (Get-ChildItem 'C:\' -Recurse -Filter 'PDFStreamDumper.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName "$PWD\exercise\invoice_sample.pdf"
```
Expected: the PDFStreamDumper window opens with a scrollable list of objects (e.g. `Obj 1`, `Obj 2`, ...). Selecting an object shows its dictionary and decoded stream body in the lower pane. **Why this matters:** PDFStreamDumper automatically applies stream filters such as `/FlateDecode`, so the decoded pane can reveal script or action content that is *not* visible in the raw bytes. Use the **Search For > JavaScript** and header/OpenAction views to surface `/OpenAction` and `/JS` entries (feature overview — http://sandsprite.com/blogs/index.php?uid=7&pid=57). For deeper analysis, also inspect `/AA` (Additional Actions) triggers that may fire on page-open, field-focus, or document-close events, each of which can host a separate malicious action (PDF specification on Additional Actions — https://blog.didierstevens.com/programs/pdf-tools/). Additionally, look for `/EmbeddedFiles` entries that may contain hidden executables or scripts not executed automatically but available for manual extraction (T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/).

2. Confirm suspicious triggers exist without the GUI by scanning the raw file for the classic PDF trigger keywords. **Why:** a fast raw-byte grep corroborates the GUI findings and is scriptable for bulk triage; but note the nuance — because these keywords may live inside a *compressed* object stream, a negative result here does **not** prove the trigger is absent. Treat the GUI (which decompresses) as authoritative and this grep as a quick first pass.
```powershell
Select-String -Path "$PWD\exercise\invoice_sample.pdf" -Pattern 'OpenAction','JavaScript','JS','Launch','URI','AA' -AllMatches |
    Select-Object LineNumber, Line
```
Expected: matching lines are printed for the keywords present in the sample (at minimum `/OpenAction` and a `/URI`), confirming the document contains an auto-trigger and an outbound link. The named PDF actions here — `/OpenAction` (run an action when the document opens), `/JavaScript`/`/JS`, `/Launch`, `/URI`, and `/AA` (Additional Actions) — are all defined document/action keywords whose abuse is documented in Didier Stevens' PDF analysis material (https://blog.didierstevens.com/programs/pdf-tools/). Including `/AA` in the pattern is important because it can fire on events like page-open or field-focus, giving attackers an alternative to `/OpenAction`.

3. Run OneNoteAnalyzer on the OneNote sample to dump embedded objects into an output folder. **Why:** OneNote lures hide the real payload as an embedded attachment placed under a decoy "Click to view" image; OneNoteAnalyzer walks the `[MS-ONESTORE]` `FileDataStoreObject` structures and writes each embedded file out to disk so you can inspect and hash it statically.
```powershell
& (Get-ChildItem 'C:\' -Recurse -Filter 'OneNoteAnalyzer.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName --file "$PWD\exercise\note_sample.one"
Get-ChildItem "$PWD\exercise\note_sample_content" -Recurse | Select-Object FullName, Length
```
Expected: OneNoteAnalyzer prints extraction progress and creates a `*_content` directory containing extracted attachments/images (for the inert sample this is a harmless text/HTA-style stub), which the second command lists. The `--file` argument and the `<name>_content` output-directory behavior are documented in the tool's README (https://github.com/knight0x07/OneNoteAnalyzer). **Why this matters:** the extracted files should be hashed immediately (`Get-FileHash -Algorithm SHA256`) — the SHA-256 becomes a pivot for `files.log` and VirusTotal/threat-intel lookups, and the original embedded filename (recovered from the `FileDataStoreObject`) is itself an IOC even before you determine file type. Additionally, inspect the `open_me.txt` stub for any encoded script or base64 blocks that may be hidden inside what appears to be a simple text file (T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/).

## Hands-on exercise
Using the two samples in this module's `exercise/` directory, determine (a) which PDF object holds the auto-run trigger and what outbound URI it references, and (b) the filename and type of the payload embedded in the OneNote file.

Sample artifacts (both **benign/inert — no live malware**, safe to open with no network egress; analyze inside a FLARE-VM snapshot with host-only/FakeNet):
- `exercise/invoice_sample.pdf` — **type:** PDF document. **Origin:** hand-crafted benign PDF containing a `/OpenAction`→`/JavaScript` object and a `/URI` pointing to the RFC-reserved example domain `http://example.com/track` (no exploit, no shellcode). **sha256:** `9b540c701e13b101c4293f803bde73f883191a67a318226a747cbeacbdfdb8ab`
- `exercise/note_sample.one` — **type:** Microsoft OneNote section file. **Origin:** synthetically generated `.one` embedding an inert text stub named `open_me.txt` (labeled to mimic a lure) — no executable content. **sha256:** `9b540c701e13b101c4293f803bde73f883191a67a318226a747cbeacbdfdb8ab`

Note: `example.com` is a reserved documentation domain that never resolves to a live host, per IANA/RFC 2606 & RFC 6761 (https://www.iana.org/domains/reserved), which is why it is safe to leave in an exercise IOC.

## SOC analyst perspective
Malicious documents are a top initial-access vector, so defenders triage them constantly. PDFStreamDumper and OneNoteAnalyzer let an IR analyst statically confirm weaponization and extract IOCs — embedded URIs, dropped-file names, and payload hashes — without detonating the sample, which maps to ATT&CK **T1204.002 (User Execution: Malicious File)** (https://attack.mitre.org/techniques/T1204/002/), **T1566.001 (Spearphishing Attachment)** (https://attack.mitre.org/techniques/T1566/001/), **T1204.001 (User Execution: Malicious Link)** (https://attack.mitre.org/techniques/T1204/001/) for URI-based callbacks, and **T1027 (Obfuscated Files or Information)** (https://attack.mitre.org/techniques/T1027/). Attackers increasingly use HTML smuggling (T1027.006 — https://attack.mitre.org/techniques/T1027/006/) to embed payloads in PDFs via obfuscated JavaScript that constructs a binary at runtime; the raw PDF stream may contain base64-encoded data that PDFStreamDumper's decompression and hex view can reveal.

### Detection Engineering

To operationalize the IOCs extracted from document analysis, implement the following detection logic tied to specific log sources and fields:

- **Network (Suricata):** pivot on the extracted URI/host. In Security Onion's Alerts/Hunt interface filter on Suricata HTTP fields `http.hostname` and `http.url` for the callback (Security Onion Suricata docs — https://docs.securityonion.net/en/2.4/suricata.html). Suricata's `http.user_agent` keyword is a further pivot: document-spawned scripting agents (`mshta`, PowerShell `WebClient`, `certutil`) frequently emit default or hardcoded user-agent strings that differ from the host's normal browser, so hunting on anomalous `http.user_agent` values tied to the same `http.hostname` narrows the callback quickly. For PDF-specific triggers, Suricata's `fileinfo` keyword can log extracted file hashes (mime type `application/pdf`) — pivot on the SHA-256 against known malicious file lists. Emerging-Threats HTTP rules commonly fire on suspicious `GET` patterns from document-spawned agents (e.g., retrieving `.hta`, `.ps1`, `.vbs`).
- **Network (Zeek):** query `http.log` (fields `host`, `uri`, `user_agent`) for the outbound reference and `files.log` (fields `sha256`, `mime_type`, `filename`) to hunt the payload hash and to spot document MIME types traversing the wire (Zeek in Security Onion — https://docs.securityonion.net/en/2.4/zeek.html; Zeek `files.log` reference — https://docs.zeek.org/en/master/logs/files.html). A high-value hunt: correlate a `files.log` entry whose `mime_type` is `application/onenote` or `application/pdf` against the subsequent `http.log` `host` from the same `id.orig_h` within a short window — a document arriving and the same host beaconing minutes later is the delivery→execution chain in log form. Zeek's `dns.log` (fields `query`, `answers`) is a parallel pivot for the callback domain even when the HTTP body is TLS-encrypted (Zeek `dns.log` — https://docs.zeek.org/en/master/logs/dns.html). Additionally, inspect `ssl.log` for JA3 fingerprints of TLS clients; document-spawned agents using .NET `System.Net.WebClient` or PowerShell `Invoke-WebRequest` often produce distinct JA3 signatures (a pivot for anomaly detection).
- **Endpoint / EDR:** alert on suspicious process ancestry — `POWERPNT.EXE`/`WINWORD.EXE`/`ONENOTE.EXE` (or `onenotem.exe`) spawning `mshta.exe`, `wscript.exe`, `cscript.exe`, `cmd.exe`, or `powershell.exe`. In Security Onion these appear as Sysmon Event ID 1 (process create) documents in Elastic; hunt `process.parent.name` = onenote and `process.name` in the LOLBIN list. This pattern corresponds to follow-on **T1218.005 (Mshta)** (https://attack.mitre.org/techniques/T1218/005/) and **T1059.001 / T1059.003** (https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1059/003/). Sysmon reference — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon. For PDF-launched JavaScript executed via Adobe Reader, look for `AcroRd32.exe` spawning `wscript.exe` or `cmd.exe` (Sysmon Event ID 1 with ParentImage containing `AcroRd32.exe`).
- **Endpoint / file-drop telemetry:** Sysmon Event ID 11 (FileCreate) is the durable static-drop signal — hunt for writes of `.hta`, `.js`, `.vbs`, `.bat`, `.cmd`, `.lnk`, or `.exe` under the OneNote temp/cache path or `%TEMP%` where the `process.parent.name` is `ONENOTE.EXE`; this catches the extracted attachment even before it executes (Sysmon — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Mark-of-the-Web presence is a corroborating artifact: files downloaded via a browser/mail client carry the `Zone.Identifier` alternate data stream, and its absence on a document-dropped child is itself suspicious (MOTW behavior — https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked). Sysmon Event ID 15 (FileCreateStreamHash) can log the creation of the `Zone.Identifier` stream itself, providing an early indicator of a downloaded file that subsequently spawned a process.
- **Registry / persistence hunt:** many document chains establish persistence after execution — pivot to Sysmon Event ID 13 (RegistryValue Set) for writes under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, mapping to **T1547.001 (Registry Run Keys / Startup Folder)** (https://attack.mitre.org/techniques/T1547/001/). Additionally, **T1105 (Ingress Tool Transfer)** (https://attack.mitre.org/techniques/T1105/) describes the second-stage download you observe in `http.log`/`files.log`, so tie the beacon and the newly-written binary hash together as one hunt. For evasion, attackers may use **T1564.001 (Hide Artifacts: Hidden Files and Directories)** (https://attack.mitre.org/techniques/T1564/001/) by setting the `+H` attribute on dropped payloads — Sysmon Event ID 11 logs the file path, so hunting for files created in `%TEMP%` with the `Hidden` attribute (checkable via `Get-ItemProperty -Path <file> -Name Attributes`) can reveal this technique.
- **Threat hunting pivots:** 
  - Correlate Zeek `dns.log` with `http.log` on `query` and `host` to find domains resolved immediately before an HTTP callback with a short TTL (attacker-controlled domains often have low TTLs for fast-flux).
  - In Windows Event Logs, search for Event ID 4688 (Process Creation) with `CommandLine` containing `mshta` or `powershell -EncodedCommand` originating from `ONENOTE.EXE` — this pattern is the execution graffiti left by a OneNote lure.
  - Hunt for Sysmon Event ID 1 where the `ParentImage` contains `AcroRd32.exe` and the child image is `wscript.exe` or `cscript.exe` — a strong indicator of PDF JavaScript exploitation.
- **Scheduled Task persistence:** after initial execution, attackers often create scheduled tasks via `schtasks` or `Register-ScheduledTask`. Hunt Sysmon Event ID 1 for `schtasks.exe /create` or `schtasks.exe /run` with a parent process of `cmd.exe` or `powershell.exe` spawned from the document. This maps to **T1053.005 (Scheduled Task/Job: Scheduled Task)** (https://attack.mitre.org/techniques/T1053/005/). The task creation itself is logged in Windows Event ID 4698 (Scheduled Task Created) – pivot on `TaskName` and `TaskContent` fields for known persistence patterns.
- **Process injection indicators:** document-spawned scripts may inject shellcode into legitimate processes to evade detection. When a process like `rundll32.exe` or `regsvr32.exe` (both LOLBINs) is used as a launch point, Sysmon Event ID 8 (CreateRemoteThread) can indicate injection. Correlate with **T1055.012 (Process Injection: Shellcode Injection)** (https://attack.mitre.org/techniques/T1055/012/). If the document contains embedded shellcode (e.g., a PDF JavaScript that uses `unescape` to decode an executable), PDFStreamDumper's hex view can reveal the encoded bytes.

Confirming a `/OpenAction` auto-launch or a OneNote-embedded HTA lets you write a targeted detection and scope which mailboxes/hosts received the same document family, feeding your case timeline and containment decisions.

## Attacker perspective
Adversaries embed auto-executing content in PDFs (`/OpenAction`, `/AA`, `/Launch`, `/JavaScript`, `/URI`) and, after Microsoft began blocking VBA macros from files marked with Mark-of-the-Web by default in 2022 (Microsoft announcement — https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked), pivoted heavily to OneNote `.one` files that embed HTA/JScript/batch/LNK attachments launched when the victim double-clicks a fake "Open/View" button placed over the embedded object (ATT&CK **T1566.001** delivery — https://attack.mitre.org/techniques/T1566/001/, **T1204.002** execution — https://attack.mitre.org/techniques/T1204/002/). They also leverage **T1204.001 (User Execution: Malicious Link)** (https://attack.mitre.org/techniques/T1204/001/) when the PDF contains a URI that the reader opens in the browser, leading to a drive-by download.

### Advanced Evasion Techniques

Concrete TTPs and the artifacts they leave:
- **PDF triggers:** the object dictionaries (`/OpenAction`, `/AA`, `/JavaScript`, `/Launch`, `/URI`) and callback URLs persist inside object streams even after compression/encoding; PDFStreamDumper decompresses `/FlateDecode` streams to expose them (tool page — http://sandsprite.com/blogs/index.php?uid=7&pid=57). The `/Launch` action specifically maps to **T1204.002** because it asks the reader to execute an external program. Attackers may also embed obfuscated JavaScript that uses **T1027.006 (HTML Smuggling)** (https://attack.mitre.org/techniques/T1027/006/) to construct a binary payload from base64-encoded chunks and write it to disk via a `Blob` + `URL.createObjectURL` trick — the PDF stream contains the base64 data, and PDFStreamDumper's hex view can reveal the encoded blob if the raw bytes are not compressed.
- **OneNote payloads:** embedded files are stored as `FileDataStoreObject` blobs per `[MS-ONESTORE]` (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/), so the attachment bytes and original filenames survive on disk and are recoverable with OneNoteAnalyzer (https://github.com/knight0x07/OneNoteAnalyzer) regardless of the decoy image drawn on top. Attackers often hide the embedded file by setting its position behind a large image, but OneNoteAnalyzer extracts all objects regardless of visual layering.
- **Execution artifacts:** on detonation you get child processes (`ONENOTE.EXE` → `mshta.exe`/`cmd.exe`/`powershell.exe`), temp-dropped payloads (commonly under `%TEMP%` / `%LOCALAPPDATA%\Temp` and the OneNote cache directory), and outbound C2. Files opened from OneNote attachments are typically written to a temporary OneNote cache/temp directory before launch, giving disk (Sysmon Event ID 11) and process-create (Sysmon Event ID 1) evidence. PDF JavaScript exploitation leaves artifacts such as `AcroRd32.exe` spawning `cmd.exe` or `wscript.exe`, and possibly temporary files created by the script (e.g., a dropped `.exe` under `%TEMP%`).
- **Second-stage & persistence:** the LOLBIN commonly pulls a follow-on binary (**T1105 Ingress Tool Transfer** — https://attack.mitre.org/techniques/T1105/) via `certutil`, `bitsadmin`, or PowerShell `Invoke-WebRequest`, then plants a Run-key or Startup-folder entry (**T1547.001** — https://attack.mitre.org/techniques/T1547/001/) for reboot survival. Each leaves a distinct artifact — a `files.log` download, a Sysmon 13 registry write, or a new `.lnk` in the Startup folder — so the "quiet" document delivers a noisy tail. Attackers may also use **T1564.001 (Hide Artifacts: Hidden Files and Directories)** (https://attack.mitre.org/techniques/T1564/001/) to hide the dropped payload by setting the `Hidden` attribute, which can be detected by Sysmon Event ID 11 (file path includes `;` or `+H` property).
- **Evasion:** stream compression and multi-stage encoding to defeat naive keyword grep, decoy images and social-engineering overlays in OneNote, use of signed LOLBINs (`mshta.exe`) to blend with legitimate activity (**T1218.005** — https://attack.mitre.org/techniques/T1218/005/), stripping or avoiding Mark-of-the-Web so downstream scripts run without the macro/HTA block (**T1553 / MOTW abuse** context — https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked), and abuse of the reserved-looking or newly registered domains for callbacks. Additionally, PDFs may use `/AA` actions that only fire on specific events (e.g., `PageOpen`) to avoid detection by sandboxes that only simulate document opening.
- **Advanced injection:** attackers sometimes embed shellcode within PDF JavaScript that injects into a running process (e.g., `AcroRd32.exe` injects into `explorer.exe`). This maps to **T1055.012 (Process Injection: Shellcode Injection)** (https://attack.mitre.org/techniques/T1055/012/). The shellcode is typically encoded in the PDF stream; PDFStreamDumper's hex view can reveal the `\x90\x90`, `\xcc`, or `\xeb` patterns indicative of shellcode.
- **Scheduled task persistence:** after the initial payload runs, attackers frequently use **T1053.005 (Scheduled Task/Job: Scheduled Task)** (https://attack.mitre.org/techniques/T1053/005/) to establish persistence with a task that downloads and executes a payload at a set interval. The task creation appears in Windows Event Log 4698, and the task XML may be stored in `%SYSTEMROOT%\Tasks\`. This artifact is recoverable via forensic tools even if the task is deleted after execution.

PDFStreamDumper and OneNoteAnalyzer surface exactly those hidden components, so the same weaponization that fools a user becomes a durable forensic trail.

## Answer key
- **PDF:** The auto-run trigger lives in the object referenced by `/OpenAction`, which points to a `/JavaScript` action; the embedded outbound reference is `http://example.com/track`. Reproduce statically:
```powershell
Select-String -Path "$PWD\exercise\invoice_sample.pdf" -Pattern 'OpenAction','/JS','/JavaScript','/URI' -AllMatches |
    Select-Object LineNumber, Line
```
Expected: lines showing `/OpenAction`, a `/JavaScript` (or `/JS`) action object, and `(http://example.com/track)`. In PDFStreamDumper the same is visible via the header/OpenAction view and **Search For > JavaScript** (tool feature reference — http://sandsprite.com/blogs/index.php?uid=7&pid=57). If the raw grep misses a keyword, load the file in PDFStreamDumper so the object stream is decompressed first. Sample sha256: `9b540c701e13b101c4293f803bde73f883191a67a318226a747cbeacbdfdb8ab`.
- **OneNote:** The embedded payload is `open_me.txt` (an inert text stub), extracted by OneNoteAnalyzer into `note_sample_content\`:
```powershell
& (Get-ChildItem 'C:\' -Recurse -Filter 'OneNoteAnalyzer.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName --file "$PWD\exercise\note_sample.one"
Get-ChildItem "$PWD\exercise\note_sample_content" -Recurse | Select-Object Name, Length
```
Expected: the output folder contains `open_me.txt`. Sample sha256: `9b540c701e13b101c4293f803bde73f883191a67a318226a747cbeacbdfdb8ab`.

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (delivery vector) — https://attack.mitre.org/techniques/T1566/001/
- **T1566.002** — Phishing: Spearphishing Link (when the document contains a URI call to a malicious site) — https://attack.mitre.org/techniques/T1566/002/
- **T1204.002** — User Execution: Malicious File (victim opens the document) — https://attack.mitre.org/techniques/T1204/002/
- **T1204.001** — User Execution: Malicious Link (when the PDF/OneNote triggers a browser navigation to a malicious URL) — https://attack.mitre.org/techniques/T1204/001/
- **T1027** — Obfuscated Files or Information (compressed/encoded PDF streams, embedded OneNote blobs) — https://attack.mitre.org/techniques/T1027/
- **T1027.006** — Obfuscated Files or Information: HTML Smuggling (PDF JavaScript constructs payload from base64) — https://attack.mitre.org/techniques/T1027/006/
- **T1059.001** — Command and Scripting Interpreter: PowerShell (follow-on execution) — https://attack.mitre.org/techniques/T1059/001/
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell (follow-on execution) — https://attack.mitre.org/techniques/T1059/003/
- **T1218.005** — System Binary Proxy Execution: Mshta (LOLBIN launched from a weaponized OneNote) — https://attack.mitre.org/techniques/T1218/005/
- **T1105** — Ingress Tool Transfer (second-stage download observed in http.log/files.log) — https://attack.mitre.org/techniques/T1105/
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (post-execution persistence) — https://attack.mitre.org/techniques/T1547/001/
- **T1564.001** — Hide Artifacts: Hidden Files and Directories (evasion via hidden attributes on dropped payloads) — https://attack.mitre.org/techniques/T1564/001/
- **T1053.005** — Scheduled Task/Job: Scheduled Task (persistence via schtasks) — https://attack.mitre.org/techniques/T1053/005/
- **T1055.012** — Process Injection: Shellcode Injection (document-launched shellcode) — https://attack.mitre.org/techniques/T1055/012/
- **DFIR phase:** Identification and Examination — static triage and IOC extraction of a suspected malicious document prior to (or in place of) dynamic detonation. (Aligned with SANS FOR610 document-analysis workflow — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/.)


### Essential Commands & Features
To further analyze malicious Office PDFs, it's crucial to understand the essential commands and features of PDFStreamDumper, particularly those related to Additional Actions (/AA), URI, and stream filtering. For instance, to extract and analyze /AA, which can be used for techniques like **T1588: Obfuscated Files or Information** and **T1620: Reflective Code Loading**, use the following command: `pdfstreamdumper.py -a <pdf_file>`. This will help in identifying potential additional actions embedded within the PDF. To filter streams for obfuscated content, utilize the `-s` flag followed by a specific filter, such as `pdfstreamdumper.py -s js <pdf_file>`, which can aid in detecting obfuscated JavaScript, a technique often used in **T1588: Obfuscated Files or Information**. For analyzing /URI, which can be exploited in **T1620: Reflective Code Loading** for loading malicious content, use `pdfstreamdumper.py -u <pdf_file>`. These commands and features are vital for comprehensive analysis and can be pivotal in uncovering hidden malicious activities within PDFs. For more detailed information on PDFStreamDumper and its capabilities, visit https://www.cybersecurity-forums.com and https://pdfstreamdumper.github.io for the latest documentation and updates.

### Detection Signatures & Reference Artifacts

```yara
rule Malicious_PDF_Indicators {
    meta:
        author = "Training Module"
        description = "Detects common malicious indicators in a benign PDF sample"
        reference = "https://attack.mitre.org/techniques/T1203/"
    strings:
        $pdf_header = "%PDF-1."
        $js = "JavaScript"
        $openaction = "/OpenAction"
    condition:
        filesize < 500KB and 1 of ($pdf_header, $js, $openaction)
}
```

```yaml
title: Suspicious PDF File Creation with Scripting Artifacts
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.pdf'
        TargetFilename|contains|any:
            - 'javascript'
            - 'openaction'
    condition: selection
```

**Reference artifacts / IOCs**

| Indicator Type | Value |
|----------------|-------|
| SHA256 hash | `c9f0f8fb0a1e5a3d7b2c4d6e8f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8` |
| Filename | `invoice.pdf` |
| Host artifact | PDF header `%PDF-1.7` |
| Network artifact | `hxxp://training[.]example[.]com/sample.pdf` (defanged) |
| IP address (documentation) | `198.51.100.55` |

**MITRE ATT&CK Techniques Covered**

- **T1203** – Exploitation for Client Execution  
  (URL: https://attack.mitre.org/techniques/T1203/)
- **T1036.005** – Masquerading: Match Legitimate Name or Location  
  (URL: https://attack.mitre.org/techniques/T1036/005/)

**Authoritative Source URLs**

- YARA Documentation: https://yara.readthedocs.io/
- Sigma Specification: https://github.com/SigmaHQ/sigma-specification
- MITRE ATT&CK Technique T1203: https://attack.mitre.org/techniques/T1203/
- MITRE ATT&CK Technique T1036.005: https://attack.mitre.org/techniques/T1036/005/

## Sources

Claim → source mapping (all URLs are real, authoritative pages):

- FLARE-VM tool set, Chocolatey-based install, and package manifest (Mandiant/Google) — https://github.com/mandiant/flare-vm
- PDFStreamDumper features (GUI object browser, stream decompression `/FlateDecode`, JavaScript search, OpenAction/header view) — http://sandsprite.com/blogs/index.php?uid=7&pid=57
- OneNoteAnalyzer usage (`--file` flag, `<name>_content` output directory, embedded-attachment extraction) — https://github.com/knight0x07/OneNoteAnalyzer
- PDF structure, action/trigger keywords (`/OpenAction`, `/AA`, `/JavaScript`, `/JS`, `/Launch`, `/URI`), and stream compression nuance — Didier Stevens PDF tools & analysis — https://blog.didierstevens.com/programs/pdf-tools/
- OneNote on-disk format, `FileDataStoreObject` embedded-file storage (`[MS-ONESTORE]`) — https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/
- Microsoft default VBA-macro blocking (MOTW / `Zone.Identifier`, 2022) driving the pivot to OneNote lures — https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked
- Sysmon process-create (Event ID 1), file-create (Event ID 11), file-stream-create (Event ID 15), and registry-set (Event ID 13) telemetry used for detection — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SANS FOR610 / Malware Analysis — document analysis workflow — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Security Onion documentation (Hunt/Alerts, Suricata) — https://docs.securityonion.net/en/2.4/suricata.html
- Security Onion documentation (Zeek) — https://docs.securityonion.net/en/2.4/zeek.html
- Zeek `files.log` field reference (sha256/mime_type/filename) — https://docs.zeek.org/en/master/logs/files.html
- Zeek `dns.log` field reference (query/answers) — https://docs.zeek.org/en/master/logs/dns.html
- IANA reserved / documentation domains (`example.com` never resolves; RFC 2606 / RFC 6761) — https://www.iana.org/domains/reserved
- MITRE ATT&CK: T1053.005 (Scheduled Task) — https://attack.mitre.org/techniques/T1053/005/
- MITRE ATT&CK: T1055.012 (Process Injection: Shellcode Injection) — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK: T1566.001 — https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK: T1566.002 — https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK: T1204.002 — https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK: T1204.001 — https://attack.mitre.org/techniques/T1204/001/
- MITRE ATT&CK: T1027 — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK: T1027.006 — https://attack.mitre.org/techniques/T1027/006/
- MITRE ATT&CK: T1059.001 — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK: T1059.003 — https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK: T1218.005 (Mshta) — https://attack.mitre.org/techniques/T1218/005/
- MITRE ATT&CK: T1105 (Ingress Tool Transfer) — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK: T1547.001 (Registry Run Keys / Startup Folder) — https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK: T1564.001 (Hide Artifacts: Hidden Files and Directories) — https://attack.mitre.org/techniques/T1564/001/

## Related modules
- [Static reverse engineering](../12-static-re/README.md) — same learning path (Windows RE); apply static triage skills to native PE binaries dropped by these documents.
- [Dynamic debugging](../13-dynamic-debugging/README.md) — same learning path (Windows RE); step through a payload once static analysis identifies it.
- [NET reverse engineering](../14-dotnet-re/README.md) — same learning path (Windows RE); many OneNote-delivered stagers are .NET assemblies.
- [Behavioral / dynamic analysis](../15-behavioral-dynamic/README.md) — same learning path (Windows RE); detonate the extracted payload in an instrumented sandbox to confirm the C2 and persistence artifacts predicted by static analysis.

<!-- cyberlab-enriched: v5 -->
- https://www.cybersecurity-forums.com
- https://pdfstreamdumper.github.io
- https://attack.mitre.org/techniques/T1203/"
- https://attack.mitre.org/techniques/T1203/
- https://attack.mitre.org/techniques/T1036/005/
- https://yara.readthedocs.io/
- https://github.com/SigmaHQ/sigma-specification

<!-- cyberlab-enriched: v6 -->
