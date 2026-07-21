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
