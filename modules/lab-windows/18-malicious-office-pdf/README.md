# 18 * Malicious Office / PDF -- LAB-WINDOWS

## Overview (plain language)
Attackers love hiding malware inside everyday documents — PDFs, Word files, and OneNote notebooks — because people open them without thinking twice. This module teaches you to safely crack these documents open on FLARE-VM and look at what is *really* inside them, without ever running the malicious code. **PDFStreamDumper** lets you browse the raw internal objects and streams of a PDF file (the hidden pieces the reader normally assembles for you), decompress them, and pull out embedded scripts, links, or launch actions. **OneNoteAnalyzer** does something similar for Microsoft OneNote (`.one`) files, which became a popular malware delivery format after Microsoft blocked macros — it extracts the attachments, images, and embedded files that an attacker tucked inside a seemingly harmless note. Together these tools let an analyst answer "is this document weaponized, and what does it try to do?" using static inspection only.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PDFStreamDumper | Bundled in FLARE-VM (`choco install`/FLARE installer) | Static examiner for PDF internals — parse objects, decompress streams, extract embedded JavaScript, launch/OpenAction triggers, and embedded payloads |
| OneNoteAnalyzer | Bundled in FLARE-VM (`choco install`/FLARE installer) | Parse malicious OneNote (`.one`) files to extract embedded attachments, images, and hidden files used for payload delivery |

## Learning objectives
- Enumerate and decompress the object streams of a PDF and locate `/OpenAction`, `/JavaScript`, and `/Launch` triggers using PDFStreamDumper.
- Extract embedded/dropped payloads from a PDF stream and record their hashes for pivoting.
- Run OneNoteAnalyzer against a `.one` file to dump embedded attachments and identify the delivered payload.
- Produce IOCs (URLs, filenames, hashes) suitable for a Security Onion detection rule without executing the document.

## Environment check
```powershell
# Confirm the tools are present on FLARE-VM.
# PDFStreamDumper installs under Program Files (x86); OneNoteAnalyzer to its FLARE tool dir.
Get-ChildItem 'C:\Program Files (x86)\PDFStreamDumper\PDFStreamDumper.exe' |
    Select-Object Name, Length, LastWriteTime

Get-ChildItem 'C:\Tools\OneNoteAnalyzer\OneNoteAnalyzer.exe' -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime
```
Expected output: a file listing showing `PDFStreamDumper.exe` (with size/timestamp) and, where installed, `OneNoteAnalyzer.exe`. If a path differs on your build, resolve it with `Get-Command PDFStreamDumper.exe -ErrorAction SilentlyContinue` or `where.exe OneNoteAnalyzer.exe`.

## Guided walkthrough
1. Launch PDFStreamDumper on the sample PDF from a non-networked snapshot — it opens a GUI listing every PDF object; you can visually confirm the tool loaded.
```powershell
& 'C:\Program Files (x86)\PDFStreamDumper\PDFStreamDumper.exe' "$PWD\exercise\invoice_sample.pdf"
```
Expected: the PDFStreamDumper window opens with a scrollable list of objects (e.g. `Obj 1`, `Obj 2`, ...). Selecting an object shows its dictionary and decoded stream body in the lower pane. Use **Analyze > Search For > JavaScript** and **Analyze > Header Data** to surface `/OpenAction` and `/JS` entries.

2. Confirm suspicious triggers exist without the GUI by scanning the raw file for the classic PDF trigger keywords.
```powershell
Select-String -Path "$PWD\exercise\invoice_sample.pdf" -Pattern 'OpenAction','JavaScript','JS','Launch','URI' -AllMatches |
    Select-Object LineNumber, Line
```
Expected: matching lines are printed for the keywords present in the sample (at minimum `/OpenAction` and a `/URI`), confirming the document contains an auto-trigger and an outbound link.

3. Run OneNoteAnalyzer on the OneNote sample to dump embedded objects into an output folder.
```powershell
& 'C:\Tools\OneNoteAnalyzer\OneNoteAnalyzer.exe' --file "$PWD\exercise\note_sample.one"
Get-ChildItem "$PWD\exercise\note_sample_content" -Recurse | Select-Object FullName, Length
```
Expected: OneNoteAnalyzer prints extraction progress and creates a `*_content` directory containing extracted attachments/images (for the inert sample this is a harmless text/HTA-style stub), which the second command lists.

## Hands-on exercise
Using the two samples in this module's `exercise/` directory, determine (a) which PDF object holds the auto-run trigger and what outbound URI it references, and (b) the filename and type of the payload embedded in the OneNote file.

Sample artifacts (both **benign/inert — no live malware**, safe to open with no network egress; analyze inside a FLARE-VM snapshot with host-only/FakeNet):
- `exercise/invoice_sample.pdf` — **type:** PDF document. **Origin:** hand-crafted benign PDF containing a `/OpenAction`→`/JavaScript` object and a `/URI` pointing to the RFC-reserved example domain `http://example.com/track` (no exploit, no shellcode). **sha256:** `c8d6b1b7db3374b5e29ff0e9417501b18194b21af9bfe698f4376126899f3c37`
- `exercise/note_sample.one` — **type:** Microsoft OneNote section file. **Origin:** synthetically generated `.one` embedding an inert text stub named `open_me.txt` (labeled to mimic a lure) — no executable content. **sha256:** `a1de5a74f5dfb5932596214363301ea725545d1cabf06f12a730803f2fea3416`

## SOC analyst perspective
Malicious documents are a top initial-access vector, so defenders triage them constantly. PDFStreamDumper and OneNoteAnalyzer let an IR analyst statically confirm weaponization and extract IOCs — embedded URIs, dropped-file names, and payload hashes — without detonating the sample, which maps to ATT&CK **T1204.002 (User Execution: Malicious File)**, **T1566.001 (Spearphishing Attachment)**, and **T1027 (Obfuscated Files)**. In Security Onion you pivot on those artifacts: use extracted URIs to query Suricata `http.hostname`/`url` alerts and Zeek `http.log`/`files.log`, and hunt the payload sha256 across Zeek `files.log` hashes and endpoint EDR telemetry. Confirming a `/OpenAction` auto-launch or a OneNote-embedded HTA lets you write a targeted detection and scope which mailboxes/hosts received the same document family, feeding your case timeline and containment decisions.

## Attacker perspective
Adversaries embed auto-executing content in PDFs (`/OpenAction`, `/Launch`, `/JavaScript`, `/URI`) and, after Microsoft disabled macros by default, pivoted heavily to OneNote `.one` files that embed HTA/JScript/batch/LNK attachments launched when the victim double-clicks the fake "Open/View" button (ATT&CK **T1566.001** delivery, **T1204.002** execution). These techniques leave rich artifacts for defenders: PDF object streams retain the trigger dictionaries and callback URLs even after "obfuscation"; OneNote files retain the embedded FileDataStore blobs and attachment filenames; and on execution you get child processes (OneNote.exe → mshta.exe/cmd.exe/powershell.exe), temp-dropped payloads, and outbound C2 connections. PDFStreamDumper and OneNoteAnalyzer surface exactly those hidden components, so the same weaponization that fools a user becomes a durable forensic trail.

## Answer key
- **PDF:** The auto-run trigger lives in the object referenced by `/OpenAction`, which points to a `/JavaScript` action; the embedded outbound reference is `http://example.com/track`. Reproduce statically:
```powershell
Select-String -Path "$PWD\exercise\invoice_sample.pdf" -Pattern 'OpenAction','/JS','/JavaScript','/URI' -AllMatches |
    Select-Object LineNumber, Line
```
Expected: lines showing `/OpenAction`, a `/JavaScript` (or `/JS`) action object, and `(http://example.com/track)`. In PDFStreamDumper the same is visible via **Analyze > Header Data** (OpenAction) and **Search For > JavaScript**. Sample sha256: `c8d6b1b7db3374b5e29ff0e9417501b18194b21af9bfe698f4376126899f3c37`.
- **OneNote:** The embedded payload is `open_me.txt` (an inert text stub), extracted by OneNoteAnalyzer into `note_sample_content\`:
```powershell
& 'C:\Tools\OneNoteAnalyzer\OneNoteAnalyzer.exe' --file "$PWD\exercise\note_sample.one"
Get-ChildItem "$PWD\exercise\note_sample_content" -Recurse | Select-Object Name, Length
```
Expected: the output folder contains `open_me.txt`. Sample sha256: `a1de5a74f5dfb5932596214363301ea725545d1cabf06f12a730803f2fea3416`.

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (delivery vector).
- **T1204.002** — User Execution: Malicious File (victim opens the document).
- **T1027** — Obfuscated Files or Information (compressed/encoded PDF streams, embedded OneNote blobs).
- **T1059.001 / T1059.003 / T1218.005** — follow-on PowerShell / cmd / mshta execution launched from a weaponized OneNote (context).
- **DFIR phase:** Identification and Examination — static triage and IOC extraction of a suspected malicious document prior to (or in place of) dynamic detonation.

## Sources
- FLARE-VM tool set and installer (Mandiant/Google) — https://github.com/mandiant/flare-vm
- OneNoteAnalyzer project (knight0x07) — https://github.com/knight0x07/OneNoteAnalyzer
- Didier Stevens, "Analyzing malicious PDFs" and pdf-parser tooling (related PDF triage methodology) — https://blog.didierstevens.com/programs/pdf-tools/
- SANS FOR610 / Malware Analysis — document analysis workflow — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK: T1566.001 — https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK: T1204.002 — https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK: T1027 — https://attack.mitre.org/techniques/T1027/
- Security Onion documentation (Zeek/Suricata hunting) — https://docs.securityonion.net/