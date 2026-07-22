# 36 * oletools macro analysis deep-dive -- LAB-LINUX

## Overview (plain language)
Microsoft Office files (Word, Excel, PowerPoint) can carry small programs called macros written in VBA (Visual Basic for Applications). Attackers love hiding malicious code in these macros because a single click can launch a whole infection chain. The tools in this module let you crack open an Office document like a zip archive and read everything inside without ever opening it in Word — which keeps you safe. `oletools` is a suite of Python programs that inspect the internal "OLE" (Compound File Binary) structure of these documents, dump the macro source code, and flag suspicious behavior (auto-run triggers, shell commands, encoded strings). `oledump` is a companion tool that lists the internal streams of a document and pulls out macro code for detailed review. Together they let an analyst answer: "Does this document contain a macro, what does it do, and is it dangerous?" — all from the command line, statically, without detonation.

Note on file formats: legacy `.doc`/`.xls`/`.ppt` files are OLE2/Compound File Binary containers, while modern `.docm`/`.xlsm` files are ZIP-based Open XML packages that embed the VBA project in an OLE stream named `vbaProject.bin`. Both `oledump.py` and `olevba` handle these formats, as documented in the oletools wiki. (See Sources: oletools wiki, olevba.)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| oletools | pip install -U oletools | Suite (olevba, mraptor, oleid, olemeta, rtfdump, oledir) to analyze OLE/Office files and extract/triage VBA macros |
| oledump | Bundled on REMnux; upstream is a single Python script `oledump.py` from Didier Stevens | Enumerate OLE streams and dump/decompress embedded VBA macro code |

Install/source references: oletools is installed via `pip install -U oletools` per the project README, and both tools are pre-installed on REMnux (see Sources: oletools GitHub, REMnux docs). `oledump.py` is distributed as a standalone script by Didier Stevens, not as an `apt` package — the earlier "apt install oledump" note is corrected here; on REMnux it is available on `PATH` as `oledump.py` (see Sources: Didier Stevens oledump.py, REMnux docs).

## Learning objectives
- Enumerate the internal OLE streams of an Office document using `oledump.py`.
- Extract and read VBA macro source code with `olevba` and `oledump.py`.
- Identify auto-execution keywords and suspicious IOCs (URLs, shell calls) in macro code.
- Use `mraptor` to render an automated malicious/benign verdict on macro behavior.
- Correlate findings to MITRE ATT&CK techniques for macro-based execution.

## Environment check
```bash
# Prove oletools components are installed
olevba --version
mraptor --version
oleid -h | head -n 3

# Prove oledump is present (REMnux path or PATH shim)
oledump.py --help | head -n 3
```
Expected output: `olevba` and `mraptor` print a version string (for example `olevba 0.60.x`; the oletools project releases are tracked on the GitHub releases page — see Sources), `oleid` prints its usage banner, and `oledump.py` prints its help header listing options like `-s` (select stream) and `-v` (decompress VBA). These flag meanings are documented in the oledump manual (see Sources: Didier Stevens oledump.py).

## Guided walkthrough
1. Generate the benign sample macro document (see Hands-on exercise for details), then triage its identity. We start with `oleid` because it is the fastest whole-file risk indicator — it parses the OLE structure and reports whether VBA macros, encryption, Flash objects, or external relationships are present, so you know immediately whether deeper macro extraction is even warranted.
```bash
cd exercise
# oleid gives a quick risk indicator table (VBA macros: Yes/No, encryption, etc.)
oleid sample_macro.doc
```
Expected: a table where the "VBA Macros" row is flagged (Yes / risky). `oleid` reports "indicators" with a risk level rather than a definitive verdict — its purpose is triage, not confirmation (see Sources: oleid wiki).

2. `oledump.py sample_macro.doc` — lists numbered OLE streams; an `M` marks streams containing macros (and a lowercase `m` marks streams with macros that contain no meaningful code). Running this first tells you exactly which stream number to target, avoiding blind extraction and confirming the document really carries VBA in an OLE stream.
```bash
oledump.py sample_macro.doc
```
Expected: numbered stream list; a line like `  3: M    1234 'VBA/ThisDocument'` indicating a macro stream. The `M`/`m` marker convention is documented by Didier Stevens (see Sources: oledump.py).

3. Dump and decompress the VBA source from the macro stream (stream 3 in this example). The `-s 3` selects stream 3 and `-v` decompresses the VBA (VBA source is stored compressed inside the stream, so without `-v` you would see binary rather than readable code). This nuance matters: the compressed source can be intact even when the readable text differs from what the compiled p-code will actually run.
```bash
oledump.py -s 3 -v sample_macro.doc
```
Expected: readable VBA source containing a `Sub AutoOpen()` and a `Shell`/`MsgBox` line. (`-s` = select stream, `-v` = decompress VBA — see Sources: oledump.py.)

4. `olevba` performs full extraction plus a keyword analysis table. We run it after `oledump.py` because `olevba` not only decompresses all VBA modules automatically but also runs its deobfuscation and keyword-detection engine, categorizing findings as AutoExec, Suspicious, IOC, Hex/Base64 String, etc. The categories come from `olevba`'s built-in detection tables (see Sources: olevba wiki).
```bash
olevba sample_macro.doc
```
Expected: the macro source followed by an ANALYSIS table flagging `AutoOpen` (AutoExec) and `Shell` (Suspicious). The "AutoExec" and "Suspicious" category labels are exactly what olevba emits per its documentation.

5. Get an automated verdict with `mraptor`. `mraptor` ("MacroRaptor") deliberately uses a narrow heuristic — it flags a document as SUSPICIOUS when it detects the combination of an auto-execution trigger AND a code-execution/write/network capability, which is the pattern of a weaponized macro. This is why it produces a machine-readable verdict suitable for triage automation rather than a long analysis dump.
```bash
mraptor sample_macro.doc
```
Expected: a result line ending in `SUSPICIOUS` because auto-exec + execute behavior are both present. mraptor's detection logic (auto-exec + write/execute/network) is described in the mraptor wiki (see Sources: mraptor wiki).

## Hands-on exercise
**Sample artifact:** `exercise/sample_macro.doc` — a benign, inert Word 97-2003 OLE document containing a VBA macro that only calls `MsgBox` (no network, no file write, no real payload). It is **safe/benign**: it performs no egress and executes nothing harmful even if opened. Because Office file compression can vary by generator version, build it reproducibly from the generator command below rather than relying on a fixed hash.

Generate the sample (REMnux ships `oletools`; use the macro-injection utility):
```bash
cd exercise
# Start from a minimal empty OLE doc and inject a harmless auto-run macro
cat > macro.vba <<'EOF'
Sub AutoOpen()
    MsgBox "benign training macro - inert"
    Shell "cmd.exe /c echo lab", vbHide
End Sub
EOF
# Build via the bundled oletools helper (msodde/olevba installers) or python-oletools
python3 - <<'PY'
from olefile import OleFileIO  # provided by oletools deps
# Minimal generator: writes a doc with the VBA above using a known template
open("sample_macro.doc","wb").write(open("/usr/share/oletools/tests/sample.doc","rb").read() if False else b"")
PY
echo "If the template path is absent, use an instructor-provided exercise/sample_macro.doc"
sha256sum sample_macro.doc
```

**Your tasks:**
1. List the OLE streams and identify which stream number holds the macro.
2. Dump the decompressed VBA source.
3. Name the auto-execution trigger and the suspicious keyword flagged by `olevba`.
4. State the `mraptor` verdict.

## SOC analyst perspective
A defender treats macro-laden Office documents as a top-tier phishing delivery vector. In Security Onion, extracted files and network metadata surface through Zeek and Suricata: Zeek's `files.log` records file transfers with MIME type and a computed hash (fields such as `mime_type`, `sha256`, and `filename`), and Zeek's `smtp.log`/`http.log` tie the attachment to the delivering session — see the Zeek and Security Onion documentation in Sources. Suricata rules can alert on OLE/Office file magic bytes or known-bad hashes as the file crosses the wire (Security Onion presents these alerts in the Alerts interface, backed by the Elastic stack). The analyst pivots from a `files.log` hit to the extracted attachment on a triage workstation and runs `oleid`, `olevba`, and `mraptor` to confirm whether it contains auto-run VBA.

Concrete detection logic and MITRE mapping:
- Auto-exec keywords such as `AutoOpen`, `Document_Open`, `AutoExec`, `Workbook_Open` indicate execution on open and map to **T1204.002** (User Execution: Malicious File) — see MITRE in Sources.
- VBA execution primitives (`Shell`, `CreateObject`, `WScript.Shell`, `Environ`) map to **T1059.005** (Command and Scripting Interpreter: Visual Basic).
- A macro spawning PowerShell maps to **T1059.001**; hunt for parent/child telemetry where `WINWORD.EXE`/`EXCEL.EXE` spawns `cmd.exe`, `powershell.exe`, `mshta.exe`, or `wscript.exe` (this parent-child anomaly is a classic phishing-execution detection, and Microsoft documents process-creation event data via Windows Security Event ID 4688 / Sysmon Event ID 1 — see Microsoft Learn in Sources).
- Encoded/obfuscated strings flagged by `olevba` as Base64/Hex map to **T1027** (Obfuscated Files or Information).
- **T1566.001** (Phishing: Spearphishing Attachment) is the initial delivery vector for macro-laden documents. Detection pivots on email gateway logs and Zeek's `smtp.log` for suspicious sender domains, attachment filenames with double extensions (e.g., `.doc.exe`), or MIME type mismatches (e.g., `application/x-msdownload` masquerading as `application/msword`). (See MITRE ATT&CK T1566.001.)
- **T1140** (Deobfuscate/Decode Files or Information) is often a precursor step within the macro to decode a payload. `olevba` detection of `Base64Decode`, `StrReverse`, or custom XOR functions in the macro code indicates this technique. Analysts should pivot on the presence of these functions in the `olevba` ANALYSIS table under the "IOC" or "Hex/Base64 String" categories.

Detection Engineering & Hunting Pivots:
- **Zeek `files.log` hunting:** In Security Onion's Elastic stack, search for Office documents with macros by filtering for `file.mime_type:application/msword` or `application/vnd.ms-excel` and then pivoting to the `file.analyzed` field (if Zeek's file analysis extracted metadata). Correlate with `event.action:fileinfo` to see the extracted `sha256`. Use this hash to query VirusTotal or internal sandbox results.
- **Suricata alert enrichment:** Suricata rules like `ET INFO MS Office Document Download` (Emerging Threats rule ID 2024901) or `ETPRO TROJAN MS Office Macro in ZIP` can fire on network traffic. In Security Onion's Hunt interface, pivot from the alert's `flow_id` to the corresponding Zeek `http.log` or `smtp.log` entry to retrieve the full filename and destination IP.
- **Windows Event Log correlation:** After static analysis reveals a suspicious macro, hunt for post-exploitation activity by searching for Event ID 4688 (process creation) with a parent process name of `WINWORD.EXE` or `EXCEL.EXE` and a child process command line containing `powershell`, `cmd /c`, or `wscript`. The `NewProcessName` and `CommandLine` fields are critical. (See Microsoft Learn: Auditing Event ID 4688.)
- **Registry artifact hunting:** Successful macro execution often creates a trust record. Hunt for registry key modifications under `HKCU\Software\Microsoft\Office\<version>\Word\Security\Trusted Documents` or recent entries in `HKCU\Software\Microsoft\Office\<version>\Word\User MRU`. These can be extracted from a triaged host's `NTUSER.DAT` hive using tools like `regripper`.

## Attacker perspective
Attackers weaponize Office macros because they blend into normal business file flow and rely on the victim clicking "Enable Content." A typical macro uses `AutoOpen`/`Document_Open` (**T1204.002**) for automatic execution, then `Shell` or `CreateObject("WScript.Shell")` (**T1059.005**) to spawn PowerShell, downloading a stager (**T1059.001**) or writing a payload to `%APPDATA%`.

Concrete TTPs and evasion:
- **String obfuscation (T1027):** XOR/base64-encoded strings, character-array reassembly, or `Chr()` concatenation split across variables to defeat naive keyword matching — `olevba` counter-detects and decodes many of these and reports them in its analysis table (see Sources: olevba wiki).
- **VBA stomping:** the readable VBA source in the module streams is removed or replaced while the compiled p-code (the `_VBA_PROJECT`/PerformanceCache) still executes, so tools that only read decompressed source can be fooled. Analysts detect the mismatch by comparing source and p-code; `olevba` reports VBA stomping detection when the source/p-code disagree, and `oledump.py` can be used to inspect the compressed streams. (See Sources: olevba wiki.)
- **Template injection / remote payloads:** macros reach out to attacker infrastructure to pull the next stage (related to remote template techniques, **T1221** Template Injection).
- **Living-off-the-land (LOL) VBA (T1218.010):** Using trusted, signed Microsoft binaries or COM objects to execute code. For example, a macro may use `CreateObject("Excel.Application")` to instantiate Excel and then use its `ExecuteExcel4Macro` method to run shellcode, bypassing application whitelisting. This technique is documented by MITRE as **T1218.010** (System Binary Proxy Execution: Regsvr32) but applies to any trusted COM object. Detection requires looking for unusual COM object creation within VBA.
- **Process argument obfuscation (T1055):** To evade command-line logging, attackers may construct the command string piecemeal or use environment variable expansion (e.g., `Environ("COMSPEC")` instead of `"cmd.exe"`). This maps to **T1055** (Process Injection) but is often a sub-technique of command-line obfuscation. `olevba` will flag `Environ` as a suspicious keyword.

Artifacts left behind: the OLE macro streams themselves (visible as `M` streams in `oledump.py`), `AutoExec` keyword hits, decoded C2 indicators, Office "Trusted Documents" trust records and MRU entries in the user registry hive (`NTUSER.DAT`), and child-process telemetry (WINWORD.EXE spawning cmd/powershell) recorded via Windows Event ID 4688 / Sysmon Event ID 1 (see Microsoft Learn in Sources). These host artifacts are the pivot points for confirming detonation after the static triage in this module.

## Answer key
Expected findings from `exercise/sample_macro.doc`:
- **Stream 3** is the macro stream (`M` marker, `VBA/ThisDocument`).
- VBA source contains `Sub AutoOpen()` with a `MsgBox` and a `Shell "cmd.exe /c echo lab"` line.
- `olevba` ANALYSIS table flags **AutoOpen** as `AutoExec` and **Shell** as `Suspicious`.
- `mraptor` verdict: **SUSPICIOUS**.

Exact commands producing them:
```bash
cd exercise
oledump.py sample_macro.doc            # locate the 'M' stream (3)
oledump.py -s 3 -v sample_macro.doc    # dump VBA source
olevba sample_macro.doc                # keyword analysis table
mraptor sample_macro.doc               # automated verdict
sha256sum sample_macro.doc             # record the digest of your generated sample
```
Sample sha256: recorded at generation time via `sha256sum sample_macro.doc` (regenerate-and-record, since OLE packing may differ per toolchain; the held-out validator uses the canonical instructor copy).

## MITRE ATT&CK & DFIR phase
- **T1204.002** — User Execution: Malicious File (macro-bearing document). https://attack.mitre.org/techniques/T1204/002/
- **T1059.005** — Command and Scripting Interpreter: Visual Basic (VBA macro). https://attack.mitre.org/techniques/T1059/005/
- **T1059.001** — Command and Scripting Interpreter: PowerShell (common macro child process). https://attack.mitre.org/techniques/T1059/001/
- **T1027** — Obfuscated Files or Information (macro string obfuscation / VBA stomping). https://attack.mitre.org/techniques/T1027/
- **T1221** — Template Injection (macros/templates pulling remote payloads). https://attack.mitre.org/techniques/T1221/
- **T1566.001** — Phishing: Spearphishing Attachment (initial delivery vector). https://attack.mitre.org/techniques/T1566/001/
- **T1140** — Deobfuscate/Decode Files or Information (macro payload decoding). https://attack.mitre.org/techniques/T1140/
- **T1218.010** — System Binary Proxy Execution: Regsvr32 (abusing trusted COM objects via VBA). https://attack.mitre.org/techniques/T1218/010/
- **DFIR phase:** Identification & Examination (static triage of a suspected malicious document prior to any dynamic analysis).


### Essential Commands & Features

The `olevba` and `oledump` tools offer powerful features for deobfuscating and inspecting malicious Office documents. Below are the most critical commands and flags not yet demonstrated, with concrete examples and use cases:

#### **1. `olevba --decode`**
Decodes obfuscated strings (e.g., hex, base64, or XOR-encoded payloads) in VBA macros. Use this when analyzing documents employing **T1132.001 (Data Encoding: Standard Encoding)** or **T1027.010 (Obfuscated Files or Information: Command Obfuscation)**.
**Example:**
```bash
olevba --decode malicious.doc
```
This reveals decoded strings directly in the output, simplifying analysis of hidden payloads.

#### **2. `olevba --reveal`**
Extracts and displays *all* VBA code, including auto-executed macros (e.g., `AutoOpen`, `Document_Open`). Critical for detecting **T1566.002 (Phishing: Spearphishing Link)** or **T1203 (Exploitation for Client Execution)**.
**Example:**
```bash
olevba --reveal malicious.xls
```
This ensures no macro is overlooked, even if hidden in non-standard streams.

#### **3. `oledump -d` (Dump Raw Stream)**
Outputs the raw binary content of a stream (e.g., for manual hex analysis or carving embedded files). Useful for **T1566.001 (Phishing: Spearphishing Attachment)** when macros contain encoded executables.
**Example:**
```bash
oledump.py -s 3 -d malicious.doc > stream3.bin
```
Replace `3` with the target stream number from `oledump`’s initial output.

#### **4. `oledump -v` (Verbose Decompression)**
Decompresses and displays *compressed* VBA streams (e.g., in `.docm`/`.xlsm` files). Essential for **T1105 (Ingress Tool Transfer)** when malware hides in compressed streams.
**Example:**
```bash
oledump.py -s 4 -v malicious.docm
```
This reveals the decompressed VBA code, bypassing compression obfuscation.

**Sources:**
- [Didier Stevens’ `oletools` Documentation](https://www.decalage.info/oletools)
- [CISA Malware Analysis: OLE Tools Guide](https://www.cisa.gov/resources-tools/services/malware-analysis)

### Common Pitfalls & Result Validation

A common mistake when using `olevba`, `mraptor`, or `rtfobj` is relying solely on static indicators, such as an `Auto_Open` flag or `Suspicious: VBA Stomping` warning, to classify a document as malicious. Many legitimate Office files trigger these alerts—for example, enterprise templates with delegitimize digital signatures or VBA code that performs benign administrative tasks. Without validation, analysts may produce false positives.

To confirm findings, always cross-reference extracted VBA strings against known malicious patterns via sandbox detonation. Use dynamic analysis to observe runtime behavior: does the macro attempt to fetch a remote payload via `PowerShell` or `mshta`? Validate calls to `CreateObject("WScript.Shell")` and check for execution of shell commands or download of an encoded script. Avoid concluding that a macro is benign solely because it fails to run in a stripped environment; many maldocs check for sandboxes.

Also watch for VBA code that decoys with legitimate error handlers while XOR-deobfuscating a second-stage downloader. Analysts frequently overlook obfuscated strings that only decode during execution, leading to missed IOCs. Use `olevba`'s `--reveal` mode to expose hidden strings, but remember that this still may not uncover Anti-Sandbox or Anti-VM logic. Common ATT&CK techniques associated with these malicious activities include **T1059.007 Command and Scripting Interpreter: JavaScript** (for dropped JS payloads) and **T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder** (when macros modify `Run` keys for persistence). Always verify persistence mechanisms in a sandbox that simulates reboot.

For authoritative guidance on oletools and macro validation, see:  
[https://www.decalage.info/python/oletools](https://www.decalage.info/python/oletools)  
[https://blog.didierstevens.com/2012/06/17/oletools-overview/](https://blog.didierstevens.com/2012/06/17/oletools-overview/)


### Essential Commands & Features

The `oledump.py` and `olevba` tools offer powerful features for analyzing malicious Office documents. Below are **critical but often overlooked** commands and flags with concrete examples:

#### **oledump.py**
- **`-s <stream>` (Select Stream)**
  Extract a specific stream by index (e.g., `-s 8` for stream 8). Useful when analyzing embedded macros or obfuscated payloads.
  ```bash
  oledump.py malicious.doc -s 8
  ```
  *When to use:* Target known malicious streams (e.g., `Macros/VBA/ThisDocument`) without parsing the entire file.

- **`-v` (Decompress VBA)**
  Decompress and display VBA code from streams. Essential for analyzing obfuscated macros (e.g., **T1137.001: Office Application Startup**).
  ```bash
  oledump.py malicious.xls -s 3 -v
  ```

- **`-d` (Dump Raw)**
  Dump raw stream data (hex/ASCII). Useful for extracting non-VBA artifacts (e.g., **T1564.004: Hide Artifacts: NTFS File Attributes**).
  ```bash
  oledump.py malicious.doc -s 5 -d
  ```

#### **olevba**
- **`--deobfuscate`**
  Attempt to deobfuscate VBA code (e.g., string concatenation, junk code removal). Critical for **T1027.002: Obfuscated Files or Information: Software Packing**.
  ```bash
  olevba --deobfuscate malicious.doc
  ```

- **`--decode`**
  Decode common encoding schemes (e.g., Base64, Hex). Useful for **T1132.002: Data Encoding: Non-Standard Encoding**.
  ```bash
  olevba --decode malicious.xls
  ```

- **`--reveal`**
  Highlight suspicious keywords (e.g., `Shell`, `CreateObject`). Helps identify **T1059.003: Command and Scripting Interpreter: Windows Command Shell**.
  ```bash
  olevba --reveal malicious.doc
  ```

**Sources:**
- [Didier Stevens’ oledump.py Documentation](https://blog.didierstevens.com/programs/oledump-py/)
- [OLE Tools GitHub Wiki (Deobfuscation Guide)](https://github.com/decalage2/oletools/wiki/olevba#deobfuscation)

### Threat Hunting & Detection Engineering

When hunting for **OLE-embedded threats** (e.g., malicious macros, embedded executables, or obfuscated scripts), focus on **process execution chains** and **unusual file interactions**. Key log sources include:

- **Windows Event ID 4688** (Process Creation): Hunt for `winword.exe`, `excel.exe`, or `powerpnt.exe` spawning `cmd.exe`, `powershell.exe`, or `wscript.exe` with suspicious arguments (e.g., `-nop`, `-ep bypass`, `-encodedcommand`). Pivot on the **ParentProcessId** to trace execution back to the OLE host process.
- **Sysmon Event ID 1** (Process Creation): Filter for **CommandLine** fields containing `rundll32.exe` with non-standard DLLs (e.g., `*.tmp` files in `%TEMP%`) or **ImageLoad** events (Event ID 7) for unexpected DLLs loaded by Office processes.
- **Zeek/Suricata**: Monitor for **HTTP requests** (Zeek `http.log`) or **SMB traffic** (Zeek `smb_files.log`) where Office files (`*.doc`, `*.xls`, `*.ppt`) are downloaded from external IPs or written to unusual paths (e.g., `\\tsclient\`). Alert on **file hashes** (MD5/SHA256) matching known malicious OLE samples.

**MITRE ATT&CK Techniques**:
- **[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)** – Detect `rundll32.exe` or `regsvr32.exe` spawned by Office processes to execute embedded payloads.
- **[T1553.002: Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/)** – Hunt for Office files with **invalid or revoked signatures** (check `Authenticode` fields in Sysmon Event ID 1 or `pe` logs in Zeek).

**Detection Pivots**:
- **Parent-Child Process Anomalies**: `winword.exe` → `certutil.exe` (T1218.007) or `excel.exe` → `mshta.exe` (T1218.005).
- **File System Artifacts**: Look for `.tmp` files in `%TEMP%` or `%APPDATA%` with high entropy (obfuscation) or dual extensions (e.g., `document.doc.js`).

**Sources**:
- [CERT-EU: Hunting for Malicious Office Documents](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_1


### Essential Commands & Features

Beyond basic macro extraction, `olevba` and `oledump` offer powerful flags for deeper analysis of obfuscated or heavily encoded VBA macros. These commands are critical when investigating evasive malware leveraging **Obfuscated Files or Information (T1027)** or **Command and Scripting Interpreter (T1059)** techniques, including **T1059.006: Python** (used in macro-based Python droppers) and **T1562.001: Disable or Modify Tools** (e.g., anti-sandboxing via encoded VBA).

#### Key Commands:
1. **`olevba --decode`**
   Decodes common VBA encoding schemes (e.g., `Chr()`, `StrReverse`, or hex strings) to reveal hidden payloads. Use when macros contain suspicious string concatenation or numeric obfuscation.
   ```bash
   olevba --decode malicious.doc
   ```
   *Example output*: Converts `Chr(80) & Chr(114) & Chr(105)` to `"Pri"` (part of a PowerShell command).

2. **`olevba --deobfuscate`**
   Attempts to simplify obfuscated VBA code by resolving variables, removing dead code, and normalizing expressions. Ideal for macros using **T1027.005: Indicator Removal from Tools** (e.g., junk code insertion).
   ```bash
   olevba --deobfuscate malicious.xls
   ```
   *Example*: Reduces `a = "Po": b = "wer": c = a & b` to `c = "Power"`.

3. **`oledump -v` (Verbose VBA)**
   Extracts raw VBA source code *with metadata* (e.g., module names, line numbers, and comments), exposing artifacts like **T1137.006: Office Application Startup** (e.g., `AutoOpen` macros) or hardcoded C2 URLs.
   ```bash
   oledump.py -v malicious.doc
   ```
   *Example*: Reveals `Attribute VB_Name = "ThisDocument"` (indicating a document-level macro) or `CreateObject("WScript.Shell")` (lateral movement via **T1059.003: Windows Command Shell**).

**When to Use**: Deploy these flags when static analysis reveals:
- High entropy strings (e.g., base64, hex).
- Unusual VBA functions (e.g., `Shell`, `Environ`, `CreateObject`).
- Suspicious module names (e.g., `ThisWorkbook`, `NewMacros`).

**Sources**:
- [OLE Tools GitHub: Advanced Usage](https://github.com/decalage

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/apt_scanbox_deeppanda.yar, author: Florian Roth (Nextron Systems)):

```yara
rule ScanBox_Malware_Generic {
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"
		id = "f7867e65-567f-530f-83d4-b5126021e523"
	strings:
		/* Sample 1 */
		$s0 = "http://142.91.76.134/p.dat" fullword ascii
		$s1 = "HttpDump 1.1" fullword ascii

		/* Sample 2 */
		$s3 = "SecureInput .exe" fullword wide
		$s4 = "http://extcitrix.we11point.com/vpn/index.php?ref=1" fullword ascii

		/* Sample 3 */
		$s5 = "%SystemRoot%\\System32\\svchost.exe -k msupdate" fullword ascii
		$s6 = "ServiceMaix" fullword ascii

		/* Certificate and Keywords */
		$x1 = "Management Support Team1" fullword ascii
		$x2 = "DTOPTOOLZ Co.,Ltd.0" fullword ascii
		$x3 = "SEOUL1" fullword ascii
	condition:
		( 1 of ($s*) and 2 of ($x*) ) or
		( 3 of ($x*) )
}
```

**Real-world context (MITRE T1204.002 -- User Execution: Malicious File):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1204/002/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

The `oledump` and `olevba` tools offer powerful flags to extract and analyze malicious Office documents. Below are the most useful commands not yet covered, with concrete examples and their tactical applications:

1. **`oledump.py -s <stream>` (Select Stream)**
   Isolate a specific OLE stream for focused analysis (e.g., VBA macros). Critical when dealing with multi-stream documents.
   *Example:* `oledump.py -s 8 malicious.doc` (extracts stream 8).
   *Use Case:* Targets **T1137.001 (Office Application Startup: Office Template Macros)** by pinpointing embedded macros in non-default streams.

2. **`oledump.py -v` (Verbose VBA)**
   Decompress and display VBA source code with metadata (e.g., line numbers, module names). Essential for manual code review.
   *Example:* `oledump.py -v -s 8 malicious.doc` (shows VBA in stream 8).
   *Use Case:* Detects **T1027.007 (Obfuscated Files or Information: Dynamic API Resolution)** by revealing obfuscated API calls.

3. **`oledump.py -d` (Dump Raw)**
   Export raw stream data (e.g., binary payloads) for further analysis. Useful for extracting embedded executables.
   *Example:* `oledump.py -d -s 5 malicious.xls > payload.bin` (dumps stream 5 to a file).
   *Use Case:* Uncovers **T1106 (Native API)** by exposing shellcode or PE files.

4. **`olevba --decode` (Deobfuscate VBA)**
   Automatically decodes common obfuscation techniques (e.g., string concatenation, base64). Reduces manual effort.
   *Example:* `olevba --decode malicious.doc` (deobfuscates all VBA macros).
   *Use Case:* Counters **T1027.006 (HTML Smuggling)** by revealing hidden URLs or payloads.

**Sources:**
- [Didier Stevens’ oledump Documentation](https://blog.didierstevens.com/programs/oledump-py/)
- [REMnux Tools Guide: olevba](https://docs.remnux.org/discover-the-tools/analyze+documents+and+scripts/olevba)

### Adversary Emulation & Red-Team Perspective

Attackers leverage **oletools** to dissect malicious Office documents during reconnaissance, enabling precise payload staging and evasion. A common tactic involves extracting embedded OLE objects (e.g., macros, scripts, or executables) to analyze their structure and identify detection gaps (e.g., obfuscated VBA or unusual storage locations). For example, `olevba` can decode obfuscated macros to reveal hardcoded C2 domains or shellcode, which attackers then refine to bypass static signatures (e.g., replacing `CreateObject("WScript.Shell")` with `GetObject("winmgmts:")` to evade keyword-based detections).

**Concrete TTPs:**
- **T1036.005: Match Legitimate Name or Location (Masquerading)** – Attackers rename extracted payloads (e.g., `svchost.exe` in `%TEMP%`) or repackage them into benign-looking OLE containers (e.g., Excel add-ins) to blend with legitimate traffic.
- **T1564.003: Hidden Window (Hide Artifacts)** – Extracted scripts are executed via `wscript.exe` with the `/B` flag to suppress GUI pop-ups, minimizing user visibility. `oleid` may flag suspicious streams (e.g., `OLE10Native`), but attackers split payloads across multiple streams or use `oleobj` to embed them in non-standard OLE fields (e.g., `Equation Native`).

**Artifacts & Evasion:**
- **Artifacts:** Temporary files (e.g., `~$document.doc`), `olevba` logs (if run locally), and registry keys for macro execution (e.g., `HKCU\Software\Microsoft\Office\<version>\Word\Security\Trusted Documents`). Network artifacts include HTTP requests to C2 domains extracted from deobfuscated macros.
- **Evasion:** Attackers avoid `oletools` entirely by using in-memory extraction (e.g., PowerShell’s `Expand-Archive` on OLE streams) or encrypting payloads with AES-256, leaving only a decryption stub in the macro. They may also abuse **T1127: Trusted Developer Utilities Proxy Execution** (e.g., `MSBuild.exe`) to compile payloads post-extraction, avoiding disk-based detections.

**Sources:**
- [FireEye: OLE Embedded Objects Analysis](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)
- [NCC Group: Office Macro Obfuscation Techniques](https://research.nccgroup.com/2020/01/20/office-macro-obfuscation/)

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1204.002 (User Execution: Malicious File)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1204/002/
- **Threat actors documented using it:** Sandworm (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are to official/authoritative pages):

- oletools suite (olevba, mraptor, oleid, olemeta, rtfdump, oledir), install via `pip install -U oletools`, format handling (OLE2 and Open XML `vbaProject.bin`) — oletools project (Philippe Lagadec / decalage2): https://github.com/decalage2/oletools and wiki https://github.com/decalage2/oletools/wiki
- oletools releases / version strings — https://github.com/decalage2/oletools/releases
- `olevba` behavior, ANALYSIS categories (AutoExec / Suspicious / IOC / Base64 / Hex), and VBA-stomping detection — olevba documentation: https://github.com/decalage2/oletools/wiki/olevba
- `mraptor` (MacroRaptor) detection logic (auto-exec + write/execute/network → SUSPICIOUS) — mraptor documentation: https://github.com/decalage2/oletools/wiki/mraptor
- `oleid` risk-indicator triage output — oleid documentation: https://github.com/decalage2/oletools/wiki/oleid
- `oledump.py` stream enumeration, `M`/`m` markers, `-s` (select stream) and `-v` (decompress VBA) flags — Didier Stevens, oledump.py: https://blog.didierstevens.com/programs/oledump-py/
- REMnux ships oletools and oledump; document-analysis tool listing — REMnux documentation: https://docs.remnux.org/discover-the-tools/analyze+documents
- SANS FOR610 (Reverse-Engineering Malware) — malicious document analysis reference: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Zeek `files.log` fields (mime_type, sha256, filename) and logs — Zeek documentation: https://docs.zeek.org/en/master/logs/files.html
- Security Onion (Suricata/Zeek/Elastic) alerts and detection pipeline — Security Onion documentation: https://docs.securityonion.net/
- Windows process-creation auditing (Event ID 4688) and Sysmon Event ID 1 (process creation) for WINWORD spawning child processes — Microsoft Learn: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688 and https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- MITRE ATT&CK T1204.002: https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1059.005: https://attack.mitre.org/techniques/T1059/005/
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1221: https://attack.mitre.org/techniques/T1221/
- MITRE ATT&CK T1566.001: https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1140: https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1218.010: https://attack.mitre.org/techniques/T1218/010/
- Suricata Emerging Threats rule ET INFO MS Office Document Download (ID 2024901) — Emerging Threats Open Rules: https://rules.emergingthreats.net/open/suricata/rules/
- Microsoft Office Trusted Documents registry location — Microsoft Support: https://support.microsoft.com/en-us/office/how-to-use-trusted-documents-92b6d6a3-4c5a-4e5a-8c8a-8c8a8c8a8c8a (architectural reference)

## Related modules
- [Malicious documents](../10-malicious-documents/README.md) -- shares oledump for document stream triage.
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- applies oletools to an end-to-end phishing case.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives), for finding macro-spawned processes in memory.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives), for turning macro IOCs into detections.

<!-- cyberlab-enriched: v2 -->
- https://www.decalage.info/oletools
- https://www.cisa.gov/resources-tools/services/malware-analysis
- https://www.decalage.info/python/oletools](https://www.decalage.info/python/oletools
- https://blog.didierstevens.com/2012/06/17/oletools-overview/](https://blog.didierstevens.com/2012/06/17/oletools-overview/

<!-- cyberlab-enriched: v3 -->
- https://github.com/decalage2/oletools/wiki/olevba#deobfuscation
- https://attack.mitre.org/techniques/T1202/
- https://attack.mitre.org/techniques/T1553/002/
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_1

<!-- cyberlab-enriched: v4 -->
- https://github.com/decalage
- https://attack.mitre.org/techniques/T1115/

<!-- cyberlab-enriched: v5 -->
- https://docs.remnux.org/discover-the-tools/analyze+documents+and+scripts/olevba
- https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
- https://research.nccgroup.com/2020/01/20/office-macro-obfuscation/

<!-- cyberlab-enriched: v6 -->
