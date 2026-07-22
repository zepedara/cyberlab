# 30 * PE static analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
When you get a suspicious Windows program (an `.exe` or `.dll`), you want to learn as much as you can about it *without running it*. That is called static analysis. Windows programs use a standard layout called the Portable Executable (PE) format, which is like a labeled box: a header at the top describing the contents, then sections holding code, data, and resources. This module teaches three tools that read that box for you. **PE-bear** shows you the structure — headers, sections, and imported functions — in a friendly table so you can spot odd or hollowed-out files. **Detect-It-Easy (DIE)** tells you what compiler or packer built the file and flags suspicious signs like high randomness (entropy) that suggests hidden or compressed code. **FLOSS** pulls readable text out of a file, including strings the malware tried to hide by scrambling them at runtime. Together these give you fast, low-risk clues about what a file is and what it might do.

The PE format's overall layout (DOS header → NT headers → section table → sections) is defined in the Microsoft PE format specification, and every tool below simply parses that same structure (Microsoft Learn, *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| PE-bear | Included in FLARE-VM | GUI PE parser: inspect DOS/NT headers, sections, imports/exports, resources |
| Detect-It-Easy (DIE) | Included in FLARE-VM | Identify compiler/packer/protector, scan entropy, run detection signatures |
| FLOSS | Included in FLARE-VM | Extract static, stack, tight, and decoded (obfuscated) strings from binaries |

Notes on tool behavior (from project docs):
- PE-bear is a multi-platform PE reversing tool that renders the DOS/NT headers, the section table, imports/exports, and resources; it parses only and does not execute the target (hasherezade/pe-bear: https://github.com/hasherezade/pe-bear).
- DIE is a signature-based file-type/packer identifier with an entropy calculator; the console front-end is `diec` (horsicq/Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy and https://github.com/horsicq/DIE-engine/wiki).
- FLOSS ("FLARE Obfuscated String Solver") extracts static strings and additionally uses emulation to recover *stack*, *tight*, and *decoded* strings that ordinary `strings` misses (mandiant/flare-floss: https://github.com/mandiant/flare-floss).
- All three are packaged and installed by FLARE-VM (mandiant/flare-vm: https://github.com/mandiant/flare-vm).

## Learning objectives
- Parse a PE file's headers and sections with PE-bear and identify anomalies (e.g., high section entropy, mismatched raw/virtual sizes).
- Use Detect-It-Easy to identify the compiler/packer and interpret the entropy graph.
- Run FLOSS to recover both plain and obfuscated (stack/decoded) strings and triage indicators.
- Correlate imported API names to likely malware capabilities.
- Produce a defensible static triage note (packer status, suspicious imports, notable strings, sha256).

## Environment check
```powershell
# Confirm the three tools are present on FLARE-VM (adjust to your install paths if needed)
Get-Command floss.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
Get-ChildItem "C:\Tools\PE-bear" -Filter "PE-bear.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
Get-ChildItem "C:\Tools\die_win64_portable" -Filter "diec.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
floss.exe --version
```
Expected output: FLOSS prints its version (e.g., `floss 3.x`), and the `Get-ChildItem` calls print the full paths to `PE-bear.exe` and the DIE console binary `diec.exe`. If FLARE-VM was installed via Chocolatey, tool paths may live under `C:\ProgramData\chocolatey\lib\...` — adjust the search root accordingly. FLARE-VM ships these packages via Chocolatey, so the exact install root can vary between builds (mandiant/flare-vm: https://github.com/mandiant/flare-vm). `floss --version` is a documented flag of the FLOSS CLI (mandiant/flare-floss: https://github.com/mandiant/flare-floss).

## Guided walkthrough
1. Build a benign sample to analyze (see Hands-on exercise) and confirm its hash.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: a 64-character hex SHA256 for the compiled benign sample. `Get-FileHash` is a built-in PowerShell cmdlet that defaults to SHA256; we pin `-Algorithm SHA256` explicitly so the digest is reproducible and comparable across machines (Microsoft Learn, *Get-FileHash*: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash). **Why:** hashing first gives you an immutable reference for your triage note and lets you confirm you analyzed exactly the bytes you think you did.

2. Identify the file type / compiler / packer with Detect-It-Easy console (`diec`).
```powershell
diec.exe .\exercise\sample.exe
```
Expected: DIE reports the file as a PE (e.g., `PE64` / `PE32`), names the compiler/linker (e.g., `Microsoft Visual C/C++`, `MinGW/GCC`), and — for an unpacked benign build — reports no packer. **Why:** DIE matches signature databases against header fields, entry-point code, and section characteristics to fingerprint the toolchain or packer, which tells you at a glance whether you are looking at a straightforward compiled binary or something wrapped for evasion (horsicq/Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy). Note the nuance: a "no packer detected" result is not proof of safety — custom or unknown packers may simply lack a signature, which is why step 3's entropy check is a useful cross-verification.

3. Show the entropy breakdown per section to reason about compression/packing.
```powershell
diec.exe -e .\exercise\sample.exe
```
Expected: a per-section entropy table. Entropy is measured on a 0–8 scale (bits per byte); a section value approaching 8.0 signals compressed or encrypted (often packed) content, while ordinary compiled x86/x64 code typically sits well below that. **Why:** packers and crypters compress or encrypt the real payload, which raises randomness — so the entropy view is an evidence-based check that complements the signature verdict in step 2 (DIE entropy calculator: https://github.com/horsicq/Detect-It-Easy). Do not treat a single high value as conclusive: legitimately compressed resources (e.g., embedded PNGs) can also read high, so combine entropy with import-table size and section names.

4. Recover strings — including obfuscated ones — with FLOSS.
```powershell
floss.exe --no-color .\exercise\sample.exe
```
Expected: FLOSS prints results grouped into static, stack, tight, and decoded string categories. You should see readable static strings (e.g., the benign marker string embedded at build time) and, for real malware, strings FLOSS reconstructs by emulating the sample's own decoding routines. **Why:** ordinary `strings` only recovers contiguous printable runs; FLOSS additionally uses the vivisect emulation engine to recover stack strings (built one character at a time on the stack), "tight" strings (built in tight loops), and decoded strings (produced by deobfuscation functions), which is exactly the text malware authors try to hide (mandiant/flare-floss: https://github.com/mandiant/flare-floss). `--no-color` disables ANSI coloring so output is clean for logs and `Select-String` (FLOSS CLI usage: https://github.com/mandiant/flare-floss/blob/master/doc/usage.md).

5. Open the sample in PE-bear (GUI) and review headers, sections, and imports.
```powershell
Start-Process "C:\Tools\PE-bear\PE-bear.exe" -ArgumentList "$PWD\exercise\sample.exe"
```
Expected: PE-bear launches with the file loaded. Review the **Section Hdrs** tab (compare `Raw size` vs `Virtual size`) and the **Imports** tab (note imported DLLs/APIs). **Why:** a large gap between raw (on-disk) and virtual (in-memory) size can indicate a section that unpacks itself at runtime, and a suspiciously small import table hints that capabilities are resolved dynamically at runtime rather than declared statically (hasherezade/pe-bear: https://github.com/hasherezade/pe-bear; PE section fields defined in Microsoft Learn *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format). PE-bear only parses the file — no window flashes an execution of the sample.

## Hands-on exercise
Analyze the benign sample `exercise\sample.exe` in this module's `exercise/` directory.

**Sample declaration**
- **Type:** A tiny benign Windows console PE that prints a marker string and exits. It is inert — it performs no network, filesystem, registry, or persistence activity. **No live malware is used.**
- **Safe origin / generator (reproducible):** Compile from a one-line source on FLARE-VM using the included VC build tools. This guarantees a benign, no-egress binary you built yourself:
```powershell
# Reproducible benign generator (run from the module folder)
New-Item -ItemType Directory -Force -Path .\exercise | Out-Null
Set-Content -Path .\exercise\sample.c -Encoding ascii -Value '#include <stdio.h>
int main(void){ printf("LAB-WINDOWS-BENIGN-MARKER-30\n"); return 0; }'
cl.exe /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Because compiler/linker versions differ across FLARE-VM builds, the exact SHA256 will vary per machine — record the hash your build produces (see Answer key). The distinguishing invariant is the embedded marker string `LAB-WINDOWS-BENIGN-MARKER-30`. (`cl.exe` flags: `/Fe` names the output executable and `/nologo` suppresses the banner — Microsoft Learn, *MSVC compiler options*: https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file and https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner.)

**Tasks**
1. Use DIE to state the file class (PE32/PE64) and compiler.
2. Use DIE entropy mode to decide whether the sample is packed.
3. Use FLOSS to recover the benign marker string.
4. Use PE-bear to list at least two imported APIs and one section name.

## SOC analyst perspective
Static triage of a captured artifact is the first move in the DFIR examination phase. When an EDR or a Security Onion alert surfaces a suspicious executable, an analyst pulls the file into a sandboxed FLARE-VM and runs DIE + FLOSS + PE-bear before deeper reversing.

Concrete Security Onion pivots:
- **Suricata** may fire a file-download or malware-signature alert; the alert's `flow_id`/`community_id` lets you pivot from `alert` events to the corresponding `flow` records in Kibana/Hunt (Security Onion docs, *Alerts* and *Suricata*: https://docs.securityonion.net/en/2.4/suricata.html).
- **Zeek** logs the carved object in `files.log` (with `md5`/`sha1`/`sha256` when file hashing is enabled) and the transport in `http.log`/`conn.log`; pivot on the file hash and the `tx_hosts`/`rx_hosts` to see who else pulled the same PE (Security Onion docs, *Zeek*: https://docs.securityonion.net/en/2.4/zeek.html; Zeek `files.log` fields: https://docs.zeek.org/en/master/logs/files.html).
- **Elastic/Hunt**: take the FLOSS-decoded IOCs (URLs, mutex names, registry keys, command strings) and the DIE-identified packer name and run fleet-wide queries in the Security Onion Hunt/Dashboards interface (Security Onion docs: https://docs.securityonion.net/).

Detection logic and ATT&CK mapping:
- DIE's packer/entropy verdict maps to **T1027.002 (Software Packing)** (https://attack.mitre.org/techniques/T1027/002/). High entropy (approaching 8.0) plus a small import table plus obfuscated strings is a classic "packed and likely hostile" signal that justifies escalation and detonation.
- FLOSS-recovered obfuscated strings map to **T1027 (Obfuscated Files or Information)** (https://attack.mitre.org/techniques/T1027/) and, where a decode routine is emulated, **T1140 (Deobfuscate/Decode Files or Information)** (https://attack.mitre.org/techniques/T1140/).
- Recovered import tables and strings become IOCs you feed back into Security Onion and hunt across your fleet. Triaging a recovered artifact aligns with the SANS FOR610 static-analysis workflow (SANS FOR610: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).

**Detection Engineering & Threat Hunting:**
- **Detection Logic (EDR/SIEM):** A process creation event (Windows Event ID 4688 or Sysmon Event ID 1) where the `Image` (process path) has a high entropy value (e.g., >7.5) as calculated by a tool like DIE can be a strong indicator of packed malware. This can be correlated with a small number of static imports (e.g., `kernel32.dll` imports count < 10) visible in the PE header, which is a common packer artifact. A Sigma rule could detect this by checking `process_creation|image_entropy` and `pe_imports_count` fields if the EDR enriches process events with PE metadata (Sigma rule concept: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_malware_pe_characteristics.yml).
- **Detection Logic (Network):** A Zeek `files.log` entry where the `mime_type` is `application/x-dosexec` (PE file) and the `analyzers` field includes `PE` and `ENTROPY` with a high value can trigger an alert. The `sha256` from this log is the pivot for all other host-based events (Zeek file analysis: https://docs.zeek.org/en/master/frameworks/file-analysis.html).
- **Threat Hunting Pivot:** From a Suricata alert for a known malicious SHA256 (e.g., `ET MALWARE Win32/Packed Possible UPX`), extract the `community_id` and join with Zeek `conn.log` on `community_id` to find all internal hosts that initiated connections to the external IP during the file transfer, then search those hosts' EDR logs for processes with matching `ParentImage` or `CommandLine` containing the downloaded filename.
- **Additional MITRE ATT&CK Techniques:** Static analysis of import tables can reveal capabilities for **T1059.001 (PowerShell)** (if `powershell.exe` is spawned or `System.Management.Automation` is referenced) and **T1105 (Ingress Tool Transfer)** (if `URLDownloadToFile`, `WinHttp` APIs, or network-related strings are found). Identifying `LoadLibrary` and `GetProcAddress` as primary imports strongly suggests **T1027 (Obfuscated Files or Information)** via dynamic API resolution (MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/; T1059.001: https://attack.mitre.org/techniques/T1059/001/; T1105: https://attack.mitre.org/techniques/T1105/).

## Attacker perspective
Attackers know static analysts read the PE box, so they fight back at build time. Concrete TTPs:
- **Packing/crypting (T1027.002, https://attack.mitre.org/techniques/T1027/002/):** UPX, Themida, or custom crypters compress/encrypt the real payload to raise section entropy and shrink the visible import table. *Artifacts left behind:* high per-section entropy (visible in DIE `-e`), tell-tale section names such as `UPX0`/`UPX1` or `.themida`, and a large gap between raw and virtual section sizes visible in PE-bear (UPX packer: https://github.com/upx/upx; section fields per Microsoft Learn *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format).
- **Dynamic import resolution (T1027, https://attack.mitre.org/techniques/T1027/):** building the import table at runtime via `LoadLibrary`/`GetProcAddress` hides capabilities from the static import view. *Artifact:* a suspiciously thin static import table alongside `LoadLibrary`/`GetProcAddress` in the imports (Microsoft Learn, *GetProcAddress*: https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).
- **String obfuscation (T1140, https://attack.mitre.org/techniques/T1140/):** XOR- or stack-encoding strings so plain `strings` finds nothing — which is exactly why FLOSS's emulation of stack/tight/decoded strings is valuable and, when it runs, surfaces the very strings the attacker tried to conceal (mandiant/flare-floss: https://github.com/mandiant/flare-floss).

**Advanced Evasion & Residual Evidence:**
- **Section Name Spoofing (T1036.005 (Masquerading: Match Legitimate Name or Location)):** Attackers may rename packed sections to mimic legitimate ones (e.g., `.text`, `.data`) to bypass simple name-based detection. The artifact is a mismatch between the section name's expected characteristics and its actual entropy or permissions (e.g., a `.text` section with write permissions `IMAGE_SCN_MEM_WRITE` is anomalous) (MITRE ATT&CK T1036.005: https://attack.mitre.org/techniques/T1036/005/; PE section flags: https://learn.microsoft.com/windows/win32/debug/pe-format#section-flags).
- **Time-stomping (T1070.006 (Indicator Removal: Timestomp)):** Attackers modify the PE header's `TimeDateStamp` field (a 32-bit value representing the linker timestamp) to blend in with legitimate system files. The artifact is a timestamp that is implausibly old (e.g., 1980), in the future, or mismatched with the file's on-disk `CreationTime` in `$STANDARD_INFORMATION` (MITRE ATT&CK T1070.006: https://attack.mitre.org/techniques/T1070/006/; PE `TimeDateStamp` field: https://learn.microsoft.com/windows/win32/debug/pe-format#optional-header-standard-fields-image-only).
- **Overlay Data (T1027.001 (Obfuscated Files or Information: Binary Padding)):** Malware may append extra data (an overlay) after the PE sections, which is not mapped into memory by the loader but can be read by the malware at runtime. This data often contains configuration or secondary payloads. The artifact is a file size larger than the sum of section raw sizes plus headers, visible in PE-bear's "Overlay" field or by comparing `SizeOfImage` with actual file size (MITRE ATT&CK T1027.001: https://attack.mitre.org/techniques/T1027/001/; Overlay detection with PE-bear: https://github.com/hasherezade/pe-bear).

Evasion vs. residual evidence: even sophisticated packing leaves abnormally high entropy, packer signatures DIE recognizes, anomalous section names, and raw/virtual size mismatches — the static-analysis "tells" that drive escalation.

## Answer key
Expected findings and the commands that produce them:

1. **File class & compiler** — DIE identifies a PE (PE32 or PE64 depending on your `cl.exe` target) built by `Microsoft Visual C/C++`:
```powershell
diec.exe .\exercise\sample.exe
```
2. **Packed?** — No. Section entropy is moderate (well below 8.0), and DIE reports no packer:
```powershell
diec.exe -e .\exercise\sample.exe
```
3. **Marker string** — FLOSS recovers the static string `LAB-WINDOWS-BENIGN-MARKER-30`:
```powershell
floss.exe --no-color .\exercise\sample.exe | Select-String "LAB-WINDOWS-BENIGN-MARKER-30"
```
Expected: the line containing `LAB-WINDOWS-BENIGN-MARKER-30` is printed.
4. **Imports/section** — In PE-bear the **Imports** tab shows CRT/`kernel32.dll` APIs (e.g., `GetStdHandle`, `WriteFile`/`__acrt_*`) and the **Section Hdrs** tab lists standard sections such as `.text`, `.rdata`, `.data`. (These are the standard sections emitted by MSVC; section semantics are defined in Microsoft Learn *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format. `GetStdHandle`/`WriteFile` are documented kernel32 console/file APIs: https://learn.microsoft.com/windows/console/getstdhandle and https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile.)

**Sample sha256:** machine-specific (varies with compiler version). Record it with:
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe | Format-List Hash
```
Invariant validation marker string: `LAB-WINDOWS-BENIGN-MARKER-30`.

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (FLOSS surfaces obfuscated/encoded strings) — https://attack.mitre.org/techniques/T1027/
- **T1027.001 — Binary Padding** (Overlay data detection via PE-bear) — https://attack.mitre.org/techniques/T1027/001/
- **T1027.002 — Software Packing** (DIE entropy/packer detection) — https://attack.mitre.org/techniques/T1027/002/
- **T1036.005 — Masquerading: Match Legitimate Name or Location** (Spoofed section names) — https://attack.mitre.org/techniques/T1036/005/
- **T1059.001 — PowerShell** (Detection via import table or string analysis) — https://attack.mitre.org/techniques/T1059/001/
- **T1070.006 — Timestomp** (Anomalous PE header TimeDateStamp) — https://attack.mitre.org/techniques/T1070/006/
- **T1105 — Ingress Tool Transfer** (Network-related imports/strings) — https://attack.mitre.org/techniques/T1105/
- **T1140 — Deobfuscate/Decode Files or Information** (FLOSS emulates decoding routines) — https://attack.mitre.org/techniques/T1140/
- **T1518 — Software Discovery** (build fingerprinting via DIE compiler/linker identification, defensive context) — https://attack.mitre.org/techniques/T1518/
- **DFIR phase:** Identification → Examination (static triage of a recovered artifact prior to dynamic analysis/reversing), consistent with the SANS FOR610 malware-analysis workflow (https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).


### Essential Commands & Features

PE-bear provides advanced static analysis capabilities that go beyond basic PE parsing. Below are **critical but often overlooked commands and features**, each with a concrete example and use case:

1. **Missing Overlay Parsing**
   Use PE-bear’s overlay inspection to detect appended data (e.g., embedded payloads or obfuscated code). Overlays are common in malware leveraging **T1027.009 (Obfuscated Files or Information: Embedded Payloads)**.
   *Example*:
   ```bash
   # Open a sample in PE-bear, navigate to the "Overlay" tab, and check for non-zero data.
   pe-bear suspicious.exe
   ```
   *When to use*: Suspect packed executables or files with unusual entropy.

2. **TLS Callbacks**
   Inspect Thread Local Storage (TLS) callbacks to uncover execution hooks, often abused in **T1480.001 (Execution Guardrails: Environmental Keying)**.
   *Example*:
   ```bash
   # In PE-bear, go to the "TLS" tab to view callback addresses.
   pe-bear malware_with_tls.exe
   ```
   *When to use*: Analyzing samples with anti-debugging or sandbox evasion.

3. **Debug Directory**
   Examine the debug directory for artifacts like PDB paths, which may reveal developer environments or **T1622 (Debugger Evasion)** techniques.
   *Example*:
   ```bash
   # Navigate to the "Debug" tab in PE-bear to extract PDB strings.
   pe-bear sample_with_debug_info.exe
   ```
   *When to use*: Investigating leaked build paths or custom debuggers.

4. **Rich Header Inspection**
   Decode the Rich header to identify compiler signatures, useful for tracking toolchains in **T1587.001 (Develop Capabilities: Malware)**.
   *Example*:
   ```bash
   # In PE-bear, go to the "Rich Header" tab to parse tool IDs and versions.
   pe-bear compiled_with_visual_studio.exe
   ```
   *When to use*: Attribution or detecting custom-compiled malware.

**Authoritative Sources**:
- [PE-bear GitHub Wiki (Overlay/TLS/Debug/Rich Header Docs)](https://github.com/hasherezade/pe-bear/wiki)
- [FireEye PE File Structure Deep Dive (Rich Header Analysis)](https://www.fireeye.com/blog/threat-research/2019/08/definitive-guide-to-detecting-and-preventing-ransomware.html)

### Common Pitfalls & Result Validation

Analysts often overestimate the completeness of static PE analysis, leading to false negatives or positives. A frequent pitfall is trusting unsigned or improperly signed binaries without verifying the certificate chain—attackers may embed stolen or self-signed certificates to evade scrutiny (T1553.002 **Code Signing**). Another mistake is assuming that all imports are legitimate; malware often obfuscates imports by using indirect calls or dynamic API resolution, which static import tables won't reveal. Similarly, omitting checks for environment-sensitive behavior—such as checking for debuggers, sandbox artifacts, or specific registry keys—can cause a sample to appear benign when it actually contains conditional logic triggered only outside analysis environments (T1497.001 **System Checks**). To validate findings, cross-check suspicious static artifacts (e.g., rare section names, high entropy, anomalous certificate relationships) against dynamic execution traces or community sandbox reports. Use reliable hash lookups on public threat databases and test the sample in a controlled sandbox to observe any anti-analysis routines. Avoid false conclusions by confirming that anomalies—like unexpected data in .rsrc or .text sections—are not caused by legitimate obfuscation tools or legitimate packing patterns. Document every indicator and its alternative benign explanation before labeling malware.

Authoritative references:  
https://www.mandiant.com/resources/static-analysis-malware-techniques  
https://www.crowdstrike.com/blog/common-malware-analysis-mistakes/


### Essential Commands & Features

**Overlay Parsing** (`--overlay`)  
Appended data beyond the PE's physical end is commonly used to stash encrypted configs or additional payloads.  
`pebear -f malware.exe --overlay` dumps overlay bytes directly.  
*Use when* scanning for hidden data not visible in standard sections – attack groups often stash C2 configuration here (T1564.001 Hidden Files and Directories).  

**TLS Callbacks** (`--tls-callbacks`)  
TLS (Thread Local Storage) callbacks fire before the entry point, enabling stealthy execution of malicious code.  
`pebear -f sample.exe --tls-callbacks` lists all callback function addresses and their index.  
*Use when* malware avoids the entry point – common in loader trojans (T1204.002 User Execution: Malicious File).  

**Debug Directory** (`--debug-directory`)  
The debug directory may contain embedded CodeView data, linking to original PDB paths that reveal developer or project names.  
`pebear -f unknown.exe --debug-directory` extracts the debug type, timestamp, and path.  
*Use when* pivoting from a binary to developer attribution; also useful to spot tampered debug entries in fileless payloads.  

**Rich Header Analysis** (`--rich-header`)  
The Rich Header holds XOR-obfuscated compiler version info and build counts, helping profile development environments.  
`pebear -f malware.exe --rich-header` decodes and displays the product list and counts.  
*Use when* grouping samples by compiler family or identifying false-flagged benign tools.  

For authoritative references: [Microsoft PE Format – Debug Directory](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) and [SANS – Malicious PE Overlay Analysis](https://www.sans.org/white-papers/2696/).

### Threat Hunting & Detection Engineering

Once a 30+ PE file is unpacked, hunt for **T1055.012 (Process Injection: Process Hollowing)** and **T1574.002 (Hijack Execution Flow: DLL Side-Loading)** by correlating static indicators with runtime telemetry.

**Detection Logic (Windows Event Logs):**
- **Event ID 10 (Process Creation)** – Look for `ParentImage` ending in `explorer.exe` and `Image` paths outside `C:\Program Files\` or `C:\Windows\System32\`. Filter on `CommandLine` containing `svchost.exe -k` without a valid service group (e.g., `netsvcs`).
- **Event ID 8 (CreateRemoteThread)** – Cross-reference `SourceImage` (injected process) with `TargetImage` (hollowed process). Prioritize `TargetImage` values like `svchost.exe`, `dllhost.exe`, or `msiexec.exe` spawned from unusual parents (e.g., `powershell.exe`).
- **Event ID 7 (Image Load)** – Hunt for DLLs loaded from `%TEMP%` or `%APPDATA%` with mismatched signatures (e.g., `version.dll` sideloaded by a non-Microsoft binary).

**Zeek/Suricata Pivots:**
- **Zeek `pe` logs** – Filter for `section_names` containing `.reloc` or `.tls` (common in hollowing) and `import_hash` values linked to known malicious families (e.g., `a52d1314` for QakBot).
- **Suricata `fileinfo`** – Alert on PE files with `entropy > 7.5` and `size > 1MB` transferred over non-standard ports (e.g., `4444/tcp`).

**Hunting Queries:**
- **Splunk:** `index=win_eventlogs EventCode=10 ParentImage="*\\explorer.exe" Image!="C:\\Windows\\*" | stats count by Image, CommandLine`
- **Elastic:** `event.code: 8 and process.parent.name: "powershell.exe" and winlog.event_data.TargetImage: "svchost.exe"`

**Sources:**
- [MITRE ATT&CK: Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [CISA: Detecting DLL Side-Loading (T1574.002)](https://www.cisa.gov/resources-tools/services/detecting-dll-side-loading)


### Essential Commands & Features

PE-bear provides advanced static analysis capabilities beyond basic header inspection. Below are **critical but often overlooked** commands and features, with concrete examples and their investigative use cases:

1. **Missing Overlay Parsing**
   Use the `--overlay` flag to extract and analyze appended data (e.g., embedded payloads or config files). Overlays are common in **T1027.003 Obfuscated Files or Information: Steganography** and **T1553.004 Subvert Trust Controls: Install Root Certificate**.
   ```bash
   pe-bear --file malware.exe --overlay overlay_dump.bin
   ```
   *When to use*: Suspicious file size mismatches or unexpected entropy spikes in the last section.

2. **TLS Callbacks**
   Navigate to `Optional Header > Data Directories > TLS Directory` to inspect Thread Local Storage callbacks, often abused for **T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion**.
   ```bash
   pe-bear --file sample.exe --tls-callbacks
   ```
   *When to use*: Unusual entry point behavior or anti-debugging techniques.

3. **Security Directory (ASLR/DEP/NX)**
   Check `Optional Header > DllCharacteristics` for mitigation flags (e.g., `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` for ASLR). Disabled flags may indicate **T1562.001 Impair Defenses: Disable or Modify Tools**.
   ```bash
   pe-bear --file binary.exe --security-dir
   ```
   *When to use*: Malware targeting legacy systems or bypassing modern protections.

4. **Rich Header Analysis**
   Decode the undocumented "Rich Header" (compiler/linker metadata) via `File Header > Rich Header`. Look for anomalies like mismatched toolchains, linked to **T1587.002 Develop Capabilities: Code Signing Certificates**.
   ```bash
   pe-bear --file suspicious.dll --rich-header
   ```
   *When to use*: Attribution or detecting supply-chain tampering.

**Sources**:
- [PE-bear GitHub Wiki: Advanced Features](https://github.com/hasherezade/pe-bear/wiki/Advanced-Features)
- [NCC Group: Rich Header Analysis](https://research.nccgroup.com/2020/01/20/rich-headers-leveraging-microsofts-undocumented-pe-header/)

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

**Real-world context (MITRE T1027.002 -- Obfuscated Files or Information: Software Packing):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1027/002/ -- real in-the-wild use includes Sandworm, APT29, APT3, APT38, APT39, APT41.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

PE-bear’s advanced static analysis capabilities extend beyond basic header inspection. Below are **critical but often overlooked features**, each demonstrated with a concrete example and use case:

1. **Missing Overlay Parsing**
   Use when: Suspecting appended data (e.g., embedded payloads or config files) not reflected in section headers.
   Example: `pe-bear -f malware.exe --overlay`
   *Flags the overlay offset/size in the "Overlay" tab, enabling extraction via `dd if=malware.exe of=overlay.bin bs=1 skip=$OFFSET`.*
   **MITRE ATT&CK**: [T1027.004 Obfuscated Files or Information: Compile After Delivery](https://attack.mitre.org/techniques/T1027/004/)

2. **TLS Callbacks**
   Use when: Hunting for stealthy execution (e.g., code running before `main()`).
   Example: `pe-bear -f sample.dll --tls`
   *Displays callback addresses in the "TLS" tab. Cross-reference with disassembly to identify suspicious pre-initialization routines.*
   **MITRE ATT&CK**: [T1574.009 Hijack Execution Flow: Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/009/)

3. **Security Directory (Certificate/Manifest)**
   Use when: Analyzing signed binaries or side-loading risks.
   Example: `pe-bear -f signed.exe --security`
   *Reveals certificate thumbprints and manifest entries (e.g., `<requestedExecutionLevel>`). Validate signatures with `signtool verify /v signed.exe`.*
   **Relevant to**: [T1553.003 Subvert Trust Controls: SIP and Trust Provider Hijacking](https://attack.mitre.org/techniques/T1553/003/)

4. **Rich Header Analysis**
   Use when: Attributing compiler/linker versions or detecting tampering.
   Example: `pe-bear -f builder.exe --rich`
   *Decodes the XOR’d header (e.g., `Visual Studio 2019 16.11.31702.278`). Anomalies may indicate [T1588.002 Obtain Capabilities: Tool](https://attack.mitre.org/techniques/T1588/002/).*

**Authoritative Sources**:
- PE-bear GitHub Wiki: [Advanced Features](https://github.com/hasherezade/pe-bear/wiki/Advanced-Features)
- OALabs: [PE-Bear Deep Dive](https://www.youtube.com/watch?v=Wq

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, **30+ PE static deep analysis** is a goldmine for identifying exploitable weaknesses before execution. Attackers leverage static analysis to extract hardcoded credentials (e.g., API keys, passwords), uncover obfuscated payloads, or map out function imports/exports for **Reflective Code Loading (T1620)**—a technique where malicious code is injected into memory without touching disk, evading traditional file-based detection. For example, red teams may parse `.reloc` sections to identify memory regions suitable for **Process Hollowing (T1055.012)**, where legitimate processes are hollowed out and replaced with malicious code, leaving minimal forensic traces beyond anomalous memory artifacts.

Evasion considerations are critical: attackers may split payloads across multiple PE sections, use **indirect jumps (T1622)** to obfuscate control flow, or embed decoy strings to mislead analysts. Static analysis artifacts—such as unusual section names (e.g., `.crt` instead of `.text`), mismatched entry points, or excessive zero-padding—can betray tampering. To evade detection, adversaries may also strip debug symbols, compress sections with UPX, or employ **binary padding (T1027.001)** to inflate file size beyond typical scanner thresholds.

**Key TTPs & Artifacts:**
- **T1620 (Reflective Code Loading):** Static analysis reveals `LoadLibrary`/`GetProcAddress` calls without corresponding DLL imports.
- **T1622 (Debugger Evasion):** Detection of anti-debugging tricks (e.g., `IsDebuggerPresent` checks) or indirect jumps to thwart disassembly.
- **Artifacts:** Unusual section permissions (e.g., `.text` marked as writable), orphaned strings, or mismatched PE headers.

**Sources:**
- [NCC Group: PE File Format Deep Dive](https://research.nccgroup.com/2022/01/20/pe-file-format-deep-dive/)
- [FireEye: Red Team Techniques for Evading Static Analysis](https://www.fireeye.com/blog/threat-research/2021/08/red-team-techniques-for-evading-static-analysis.html)

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1027 (Obfuscated Files or Information)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1027/
- **Threat actors documented using it:** Sandworm (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are official tool docs/repos, Microsoft Learn, MITRE ATT&CK, or Security Onion docs):

- PE file layout, section raw/virtual size fields, section semantics, `TimeDateStamp` field, section flags → Microsoft Learn, *PE Format*: https://learn.microsoft.com/windows/win32/debug/pe-format
- Tool distribution (PE-bear, DIE, FLOSS packaged via Chocolatey) → Mandiant FLARE-VM: https://github.com/mandiant/flare-vm
- FLOSS behavior (static/stack/tight/decoded strings, emulation engine, `--version`, `--no-color`) → mandiant/flare-floss: https://github.com/mandiant/flare-floss and usage doc: https://github.com/mandiant/flare-floss/blob/master/doc/usage.md
- DIE file-type/packer identification, `diec` console, entropy calculator (`-e`) → horsicq/Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy and wiki: https://github.com/horsicq/DIE-engine/wiki
- PE-bear GUI parsing (DOS/NT headers, sections, imports/exports, resources, overlay detection; parse-only) → hasherezade/pe-bear: https://github.com/hasherezade/pe-bear
- `Get-FileHash` (default/`-Algorithm SHA256`) → Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- `cl.exe` flags `/Fe`, `/nologo` → Microsoft Learn MSVC options: https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file and https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner
- Kernel32 APIs `GetStdHandle`, `WriteFile`, `GetProcAddress`, `LoadLibrary` → Microsoft Learn: https://learn.microsoft.com/windows/console/getstdhandle , https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile , https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress , https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
- UPX packer (section names, compression) → https://github.com/upx/upx
- MITRE ATT&CK techniques → T1027: https://attack.mitre.org/techniques/T1027/ ; T1027.001: https://attack.mitre.org/techniques/T1027/001/ ; T1027.002: https://attack.mitre.org/techniques/T1027/002/ ; T1036.005: https://attack.mitre.org/techniques/T1036/005/ ; T1059.001: https://attack.mitre.org/techniques/T1059/001/ ; T1070.006: https://attack.mitre.org/techniques/T1070/006/ ; T1105: https://attack.mitre.org/techniques/T1105/ ; T1140: https://attack.mitre.org/techniques/T1140/ ; T1518: https://attack.mitre.org/techniques/T1518/
- SANS FOR610 Reverse-Engineering Malware course → https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Security Onion pivots (Suricata alerts, Zeek `files.log`) → https://docs.securityonion.net/ ; https://docs.securityonion.net/en/2.4/suricata.html ; https://docs.securityonion.net/en/2.4/zeek.html ; Zeek `files.log` fields: https://docs.zeek.org/en/master/logs/files.html ; Zeek file analysis framework: https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Sigma rule concept for PE characteristics → https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_malware_pe_characteristics.yml

## Related modules
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- shares detect-it-easy (die) for fast file-type/packer verdicts.
- [Static reverse engineering](../12-static-re/README.md) -- shares floss for string-driven capability inference.
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares floss and extends the entropy/packing signals covered here.
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- shares floss and drills into stack/tight/decoded string recovery.

<!-- cyberlab-enriched: v2 -->
- https://github.com/hasherezade/pe-bear/wiki
- https://www.fireeye.com/blog/threat-research/2019/08/definitive-guide-to-detecting-and-preventing-ransomware.html
- https://www.mandiant.com/resources/static-analysis-malware-techniques
- https://www.crowdstrike.com/blog/common-malware-analysis-mistakes/

<!-- cyberlab-enriched: v3 -->
- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- https://www.sans.org/white-papers/2696/
- https://attack.mitre.org/techniques/T1055/012/
- https://www.cisa.gov/resources-tools/services/detecting-dll-side-loading

<!-- cyberlab-enriched: v4 -->
- https://github.com/hasherezade/pe-bear/wiki/Advanced-Features
- https://research.nccgroup.com/2020/01/20/rich-headers-leveraging-microsofts-undocumented-pe-header/
- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format"

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1027/004/
- https://attack.mitre.org/techniques/T1574/009/
- https://attack.mitre.org/techniques/T1553/003/
- https://attack.mitre.org/techniques/T1588/002/
- https://www.youtube.com/watch?v=Wq
- https://research.nccgroup.com/2022/01/20/pe-file-format-deep-dive/
- https://www.fireeye.com/blog/threat-research/2021/08/red-team-techniques-for-evading-static-analysis.html

<!-- cyberlab-enriched: v6 -->
