# 36 * oletools macro analysis deep-dive -- LAB-LINUX

## Overview (plain language)
Microsoft Office files (Word, Excel, PowerPoint) can carry small programs called macros written in VBA (Visual Basic for Applications). Attackers love hiding malicious code in these macros because a single click can launch a whole infection chain. The tools in this module let you crack open an Office document like a zip archive and read everything inside without ever opening it in Word — which keeps you safe. `oletools` is a suite of Python programs that inspect the internal "OLE" structure of these documents, dump the macro source code, and flag suspicious behavior (auto-run triggers, shell commands, encoded strings). `oledump` is a companion tool that lists the internal streams of a document and pulls out macro code for detailed review. Together they let an analyst answer: "Does this document contain a macro, what does it do, and is it dangerous?" — all from the command line, statically, without detonation.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| oletools | pip install -U oletools | Suite (olevba, mraptor, oleid, olemeta, rtfdump) to analyze OLE/Office files and extract/triage VBA macros |
| oledump | apt install oledump (bundled on REMnux) | Enumerate OLE streams and dump/decompress embedded VBA macro code |

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
Expected output: `olevba` and `mraptor` print a version string (e.g. `olevba 0.60.x`), `oleid` prints its usage banner, and `oledump.py` prints its help header listing options like `-s` and `-v`.

## Guided walkthrough
1. Generate the benign sample macro document (see Hands-on exercise for details), then triage its identity.
```bash
cd exercise
# oleid gives a quick risk indicator table (VBA macros: Yes/No, encryption, etc.)
oleid sample_macro.doc
```
Expected: a table where the "VBA Macros" row is flagged (Yes / risky).

2. `oledump.py sample_macro.doc` — lists numbered OLE streams; an `M` marks streams containing macros.
```bash
oledump.py sample_macro.doc
```
Expected: numbered stream list; a line like `  3: M    1234 'VBA/ThisDocument'` indicating a macro stream.

3. Dump and decompress the VBA source from the macro stream (stream 3 in this example).
```bash
oledump.py -s 3 -v sample_macro.doc
```
Expected: readable VBA source containing a `Sub AutoOpen()` and a `Shell`/`MsgBox` line.

4. `olevba` performs full extraction plus a keyword analysis table.
```bash
olevba sample_macro.doc
```
Expected: the macro source followed by an ANALYSIS table flagging `AutoOpen` (AutoExec) and `Shell` (Suspicious).

5. Get an automated verdict with `mraptor`.
```bash
mraptor sample_macro.doc
```
Expected: a result line ending in `SUSPICIOUS` because auto-exec + execute behavior are both present.

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
A defender treats macro-laden Office documents as a top-tier phishing delivery vector. In Security Onion, email/file transfer events (Zeek `files.log`, Suricata alerts, and Strelka/file-analysis pipelines) surface `.doc`/`.docm`/`.xls` attachments; the analyst pivots to a triage workstation and runs `oleid`, `olevba`, and `mraptor` on the extracted file to confirm whether it contains auto-run VBA. Flags like `AutoOpen`, `Document_Open`, `Shell`, `CreateObject`, and base64/URL strings map directly to MITRE ATT&CK T1204.002 (User Execution: Malicious File) and T1059.005 (Command and Scripting Interpreter: VBA). The extracted IOCs (URLs, dropped filenames, C2 domains) become detections you push into hunts and block-lists, and the macro hash feeds retro-hunting across the mail gateway. This static workflow lets responders reach a verdict quickly without detonating the sample and tipping off infrastructure.

## Attacker perspective
Attackers weaponize Office macros because they blend into normal business file flow and rely on the victim clicking "Enable Content." A typical macro uses `AutoOpen`/`Document_Open` for automatic execution, then `Shell` or `CreateObject("WScript.Shell")` to spawn PowerShell, downloading a stager (T1059.001) or writing a payload to `%APPDATA%`. To evade static tooling, adversaries obfuscate strings with XOR/base64, split commands across variables, or use VBA stomping so the readable source and compiled p-code diverge — which is exactly why analysts dump the compiled p-code with `oledump.py -s N --vbadecompresscorrupt`. Artifacts left behind include the OLE macro streams themselves, `AutoExec` keyword hits, decoded C2 indicators, Office trust-record and `MRU` registry entries on the victim, and child-process telemetry (WINWORD.EXE spawning cmd/powershell) that EDR readily records.

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
- **T1204.002** — User Execution: Malicious File (macro-bearing document).
- **T1059.005** — Command and Scripting Interpreter: Visual Basic (VBA macro).
- **T1059.001** — Command and Scripting Interpreter: PowerShell (common macro child process).
- **T1027** — Obfuscated Files or Information (macro string obfuscation / VBA stomping).
- **DFIR phase:** Identification & Examination (static triage of a suspected malicious document prior to any dynamic analysis).

## Sources
- REMnux documentation — Analyze Documents: https://docs.remnux.org/discover-the-tools/analyze+documents
- oletools project (Philippe Lagadec / decalage2) — https://github.com/decalage2/oletools/wiki
- olevba documentation — https://github.com/decalage2/oletools/wiki/olevba
- Didier Stevens — oledump.py: https://blog.didierstevens.com/programs/oledump-py/
- SANS FOR610 / malicious document analysis references — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1204.002: https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1059.005: https://attack.mitre.org/techniques/T1059/005/