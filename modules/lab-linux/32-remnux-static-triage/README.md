# 32 * REMnux static triage (DIE/ssdeep/pefile) -- LAB-LINUX

## Overview (plain language)
When a suspicious file lands on an analyst's desk, the first job is "static triage" — learning as much as possible about the file *without running it*. Think of it like inspecting a sealed package: you weigh it, x-ray it, and read the label instead of opening it. These three REMnux tools do exactly that. **Detect-It-Easy (DIE)** looks at a file and guesses what it is: what compiler built it, whether it was packed or compressed, and what protections it uses. **ssdeep** creates a "fuzzy fingerprint" so you can tell whether two files are *similar* (not just identical), which is great for spotting malware families and slightly-modified variants. **pefile** cracks open Windows programs (EXE/DLL) and reads their internal structure — sections, imports, timestamps — so you can spot odd or malicious behavior before any execution.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Detect-It-Easy | (preinstalled on REMnux) `diec --version` | Identify file type, compiler, packer, and protector signatures |
| ssdeep | apt install ssdeep | Compute and compare context-triggered piecewise (fuzzy) hashes for similarity |
| pefile | pip3 install pefile | Python library/CLI to parse the structure of Windows PE (EXE/DLL) files |

Notes on the claims in this table:
- Detect-It-Easy ships preinstalled on REMnux and is documented on the REMnux tool list; `diec` is the console front-end (`diec` = "Detect It Easy Console"). See the Detect-It-Easy repo and REMnux docs in Sources.
- ssdeep implements **context-triggered piecewise hashing (CTPH)**, the fuzzy-hashing algorithm described by Jesse Kornblum; the algorithm and CLI are documented on the ssdeep project site (Sources).
- pefile is a pure-Python module for parsing/working with the Portable Executable (PE) format; the `pefile.PE` class and section/import structures are documented in the erocarrera/pefile repo (Sources).

## Learning objectives
- Use **Detect-It-Easy** to identify a file's type, compiler, and packer status from the command line.
- Generate and compare **ssdeep** fuzzy hashes to quantify similarity between two files.
- Parse a PE file's sections, imports, and compile timestamp with **pefile**.
- Interpret triage findings (packing, suspicious imports, high entropy) to prioritize deeper analysis.

## Environment check
```bash
# Prove each tool is installed on the REMnux side of LAB-LINUX
diec --version
ssdeep -V
python3 -c "import pefile; print('pefile', pefile.__version__)"
```
Expected output: DIE prints a version string (e.g. `Detect It Easy 3.xx`), `ssdeep` prints a version like `ssdeep 2.14.1`, and the Python line prints `pefile 2023.x.x`. If any command errors, install with the commands in the Tools covered table.

Notes: `ssdeep -V` is the documented version flag (ssdeep man page / project docs). `pefile.__version__` is exposed by the module and matches the release tags in the erocarrera/pefile repo. DIE's `--version`/`-v` is documented in the Detect-It-Easy repo. Exact version strings vary by REMnux release; treat the examples above as illustrative, not fixed.

## Guided walkthrough
1. Build a small, benign PE test file so nothing dangerous is used (a plain MinGW-compiled "hello world"). We generate our own sample so the exercise never touches live malware — this is the standard "known-good baseline" approach for practicing triage tooling.
```bash
mkdir -p exercise && cd exercise
cat > hello.c <<'EOF'
#include <stdio.h>
int main(void){ printf("hello lab\n"); return 0; }
EOF
# Cross-compile to a Windows PE (MinGW ships on REMnux/Kali)
x86_64-w64-mingw32-gcc hello.c -o sample.exe
ls -l sample.exe
```
Expected output: a `sample.exe` PE binary is produced (tens of KB). Why cross-compile? `x86_64-w64-mingw32-gcc` is the MinGW-w64 GCC target that emits a Windows PE32+ (PE64) executable from a Linux host, so we get a genuine PE to feed to Windows-format tooling without needing Windows. (MinGW-w64 project; Kali `mingw-w64` package — see Sources.)

2. `diec` — identify what the file is and whether it is packed. This is the fastest way to answer "what am I even looking at?" — DIE reads magic bytes, the PE header, and its signature database to name the format, architecture, linker/compiler, and any packer/protector.
```bash
diec sample.exe
```
Expected output: DIE reports `PE64` (i.e. PE32+), an entrypoint, and a compiler/linker consistent with GCC/MinGW — and importantly it will NOT flag a packer for this clean build. Nuance: for a normal compiler-produced binary, DIE shows only compiler/linker signatures and no packer line; a packer hit (e.g. UPX) on real malware is an early evasion tell. DIE's detection is signature-based, so absence of a packer flag means "no known signature matched," not a guarantee the file is unpacked. (Detect-It-Easy repo — Sources.)

3. `ssdeep` — fingerprint the file, then prove a tiny change produces a *similar* (not identical) hash. This demonstrates CTPH: cryptographic hashes (SHA-256) change completely with a one-byte edit, but fuzzy hashes stay measurably similar, which is what lets analysts cluster variants.
```bash
ssdeep sample.exe > baseline.txt
cp sample.exe sample_mod.exe
printf 'X' >> sample_mod.exe        # append one byte
ssdeep -m baseline.txt sample_mod.exe
```
Expected output: `sample_mod.exe matches baseline.txt:sample.exe (NN)` where NN is a match score (0–100). Nuance: `-m` matches inputs against a saved hash file (documented flag). A single appended byte usually yields a high-but-below-100 score; for a very small file the score may even remain 100 because the change is below ssdeep's block-size sensitivity threshold — this is expected behavior of CTPH and illustrates why ssdeep is best on larger, more complex samples. (ssdeep project docs / man page — Sources.)

4. `pefile` — read the PE structure, sections, and imports. This is the "x-ray": the `TimeDateStamp`, section entropy, and import table are exactly the fields analysts weaponize for hunting and anomaly detection.
```bash
python3 - <<'EOF'
import pefile
pe = pefile.PE("sample.exe")
print("TimeDateStamp:", hex(pe.FILE_HEADER.TimeDateStamp))
for s in pe.sections:
    print(s.Name.decode(errors="ignore").strip("\x00"),
          "entropy=%.2f" % s.get_entropy())
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("DLL:", entry.dll.decode())
EOF
```
Expected output: section names like `.text`, `.data`, `.idata` (or `.rdata`) with entropy values (roughly 4–6 for normal code and data). Nuance: `FILE_HEADER.TimeDateStamp` is the PE COFF header's link-time timestamp — a 32-bit Unix epoch value per the PE/COFF specification; it can be legitimately set, zeroed, or forged, so treat it as an indicator not proof. `get_entropy()` returns Shannon entropy on a 0–8 scale; values approaching 8.0 indicate compression/encryption (a packing signal). MinGW imports typically include `KERNEL32.dll` and the C runtime `msvcrt.dll`. (pefile repo for `PE`, `FILE_HEADER`, `sections`, `get_entropy`, `DIRECTORY_ENTRY_IMPORT`; Microsoft Learn PE/COFF spec for `TimeDateStamp` — Sources.)

## Hands-on exercise
Using the sample in this module's `exercise/` directory, answer:
1. What compiler does **Detect-It-Easy** report for `sample.exe`, and is a packer detected?
2. What is the **ssdeep** similarity score between `sample.exe` and `sample_mod.exe`?
3. Which imported DLLs does **pefile** list for `sample.exe`?

**Sample declaration:**
- **Type:** Windows PE64 executable (`sample.exe`).
- **Safe origin:** Benign and inert. It is generated locally from the `hello.c` source shown above using `x86_64-w64-mingw32-gcc` — it only prints a string and performs NO network or system-modifying activity. NO live malware is used.
- **Reproducible generator:** run the two code blocks in Guided walkthrough steps 1 and 3 inside `exercise/`.

## SOC analyst perspective
Static triage is the front door of the incident-response examination phase. When an EDR alert or a Security Onion detection surfaces an unknown binary, an analyst pulls the extracted file and runs DIE/pefile/ssdeep before ever detonating it.

Concrete Security Onion pivots and detection logic:
- **Zeek `files.log`** records extracted files with their `sha256`/`md5`, `mime_type`, `source`, and `fuid`; use the hash to pivot in Kibana/Elastic and to seed your ssdeep clustering. Zeek's File Analysis Framework (see Zeek docs in Sources) is what produces these fields.
- **Suricata `fileinfo`/file-extraction** events (in Security Onion's Suricata configuration) can carve PE files off the wire; the resulting file hash correlates directly to the same object in `files.log`. (Security Onion docs; Suricata docs — Sources.)
- **PE magic / MIME**: hunt on Zeek `files.log` where `mime_type == "application/x-dosexec"` crossing HTTP or SMB to spot Windows executables being delivered. This maps to MITRE ATT&CK **T1105 Ingress Tool Transfer** when the source is external.
- **Fuzzy clustering**: DIE flags packers/protectors — an early evasion indicator mapping to MITRE ATT&CK **T1027.002 (Software Packing)** and the parent **T1027 (Obfuscated Files or Information)**. pefile exposes suspicious imports (e.g. `VirtualAlloc`/`WriteProcessMemory` combinations tied to process injection tradecraft under **T1055**) and compile timestamps that become pivotable hunt terms. ssdeep clusters the sample against known-bad fuzzy hashes to attribute it to a family and sweep the fleet for near-duplicates.
- **From one alert to a hunt**: correlate the `sha256` from `files.log` with your ssdeep-derived clusters in Elastic, turning a single detection into a fleet-wide retrospective hunt. Detection-in-depth here aligns with the triage-first workflow taught in SANS FOR610 (Sources).
- **Detection Engineering Logic**: Use pefile-derived indicators to build proactive detection rules. For example, a high-entropy section (entropy > 7.0) combined with a suspicious import like `VirtualAllocEx` is a strong signal for **T1055 Process Injection**. In a SIEM, you could create a detection rule that triggers on Windows Event ID 4688 (process creation) where the process image has a high entropy value (calculated via a scripted field) and the command line contains suspicious API calls. Similarly, a PE file with a `TimeDateStamp` of `0x00000000` or a future date is a direct indicator of **T1070.006 Timestomp** and can be hunted via Sysmon Event ID 1 (process creation) with a field for PE compile time.
- **Threat Hunting Pivots**: In Security Onion, start with a Suricata alert for a malicious file download (e.g., ET MALWARE Win32/Dridex). Extract the file hash and query the `files.log` for the `fuid`. Use the `fuid` to pivot to the `http.log` or `smb.log` to identify the source IP and destination. Then, use the file's ssdeep hash to search across all `files.log` entries for similar files (using the `ssdeep` command-line tool against stored hashes in your database). This can uncover lateral movement (**T1570 Lateral Tool Transfer**) or multiple infection stages.

## Attacker perspective
Attackers know analysts will triage statically, so they deliberately defeat these tools using concrete TTPs:

- **Packing/crypting (T1027.002)**: UPX or custom crypters compress/encrypt the real payload behind a stub, raising a section's Shannon entropy toward 8.0 and collapsing the visible import table to a handful of loader APIs. Artifact left behind: one anomalously high-entropy section, an import table dominated by `LoadLibrary`/`GetProcAddress` (dynamic resolution), and an entrypoint that lands outside `.text`. DIE's packer signatures and pefile's `get_entropy()` expose exactly these tells.
- **Timestamp forging / "timestomping" the PE header (T1070.006 style manipulation of time attributes)**: `FILE_HEADER.TimeDateStamp` is trivially zeroed or set to a decoy epoch. Artifact: an implausible or all-zero `TimeDateStamp`, or one that disagrees with Rich header / debug directory timestamps.
- **Obfuscation more broadly (T1027)** and **deobfuscation at runtime (T1140)**: the packed stub decodes the real payload only when executed, which is why static entropy is high but dynamic analysis is still needed.
- **Defeating ssdeep clustering**: authors inject junk/padding bytes, randomize resources, or recompile per-target so fuzzy scores drop. Evasion is imperfect — minor changes still leave residual similarity (a match score well below 100), which is precisely what CTPH is designed to catch.
- **Additional TTPs**: Attackers may also use **T1218.011 (Signed Binary Proxy Execution: Rundll32)** to load malicious DLLs discovered via pefile's import table, or **T1547.001 (Registry Run Keys / Startup Folder)** for persistence, which can be hinted at by imports like `RegSetValueEx`. The presence of `WinExec` or `ShellExecute` imports may indicate **T1059.001 (PowerShell)** or other scripting for execution. Furthermore, to evade signature-based detection, attackers may employ **T1036.005 (Masquerading: Match Legitimate Name or Location)**, naming their binary after a system file but with anomalous PE characteristics.
- **Artifact Evolution**: Modern malware families often use multi-stage loaders. The first stage (discovered via static triage) may have low entropy and benign imports, but it downloads a second stage with high entropy and no imports. This technique, **T1105 (Ingress Tool Transfer)**, leaves network artifacts in Zeek `http.log` or Suricata alerts. The defender's advantage is correlating the static file properties with the network behavior.

Defender-visible artifacts across a campaign: PE header anomalies, packer signatures, mismatched section characteristics (e.g., writable+executable sections), truncated import tables, and consistent fuzzy-hash lineage. (MITRE ATT&CK T1027 / T1027.002 / T1140 / T1055 / T1070.006 / T1105 / T1218.011 / T1547.001 / T1059.001 / T1036.005 pages — Sources.)

## Answer key
Expected findings and the exact commands that produce them:
1. **DIE:** compiler is MinGW / GCC, no packer detected.
```bash
diec exercise/sample.exe | grep -iE "compiler|packer|linker"
```
2. **ssdeep:** the modified copy matches the baseline with a score under 100 (fuzzy match, not identical); for this very small sample the score may be high (possibly 100) because one appended byte is below the CTPH block-size sensitivity — record whatever score you observe.
```bash
ssdeep exercise/sample.exe > exercise/baseline.txt
ssdeep -m exercise/baseline.txt exercise/sample_mod.exe
```
3. **pefile imports:** `KERNEL32.dll` and `msvcrt.dll` (MinGW C runtime).
```bash
python3 -c "import pefile; pe=pefile.PE('exercise/sample.exe'); [print(e.dll.decode()) for e in pe.DIRECTORY_ENTRY_IMPORT]"
```
**Sample sha256:** the `sample.exe` is locally generated, so verify your own build with:
```bash
sha256sum exercise/sample.exe
```
(Record this digest in your notes; it is deterministic per toolchain version but differs across MinGW versions, which is why a reproducible generator command is provided instead of a fixed digest.)

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (detected via DIE/pefile entropy and header analysis). https://attack.mitre.org/techniques/T1027/
- **T1027.002 — Software Packing** (DIE packer signatures; pefile section entropy). https://attack.mitre.org/techniques/T1027/002/
- **T1140 — Deobfuscate/Decode Files or Information** (context for follow-on analysis). https://attack.mitre.org/techniques/T1140/
- **T1055 — Process Injection** (context: suspicious import combinations flagged during pefile triage). https://attack.mitre.org/techniques/T1055/
- **T1070.006 — Indicator Removal: Timestomp** (context: forged/zeroed PE `TimeDateStamp`). https://attack.mitre.org/techniques/T1070/006/
- **T1105 — Ingress Tool Transfer** (context: PE files delivered over network, detected via Zeek/Suricata). https://attack.mitre.org/techniques/T1105/
- **T1218.011 — Signed Binary Proxy Execution: Rundll32** (context: malicious DLLs identified via pefile import analysis). https://attack.mitre.org/techniques/T1218/011/
- **DFIR phase:** Identification and Examination — static triage prioritizes samples before dynamic analysis.


### Essential Commands & Features

REMnux’s static triage tools offer deeper analysis with targeted flags and methods. Below are **undemonstrated but critical** commands for `DIE` and `pefile` to uncover evasion techniques like **T1027.009 (Embedded Payloads)** and **T1564.001 (Hidden Files and Directories)**.

#### **DIE (Detect It Easy)**
- **Deep scan (`-d`)**:
  Uncover obfuscated sections or anomalies missed by default scans. Use when suspecting **packed binaries (T1027.002)** or **steganography (T1027.009)**.
  ```bash
  diec -d suspicious.exe
  ```
- **All info (`-a`)**:
  Extract *every* detectable attribute (compiler, linker, entropy, etc.). Critical for **supply-chain attacks (T1554)**.
  ```bash
  diec -a malware.dll
  ```
- **Entropy flags (`-e`)**:
  Highlight high-entropy sections (e.g., encrypted payloads). Pair with `-d` for **T1027.002 (Software Packing)**.
  ```bash
  diec -e -d packed_sample.bin
  ```

#### **pefile (Python Library)**
- **`dump_dict()`**:
  Export parsed PE headers as a Python dictionary for scripting. Ideal for **automating detection of T1218.010 (Signed Binary Proxy Execution)**.
  ```python
  import pefile
  pe = pefile.PE("signed_proxy.exe")
  pe_dict = pe.dump_dict()
  print(pe_dict["Rich Header"])
  ```
- **Rich Header Parsing**:
  Detect tampered build environments (e.g., **T1553.002 (Code Signing)**). Use `pe.RICH_HEADER` to extract compiler stamps.
  ```python
  if hasattr(pe, "RICH_HEADER"):
      print(f"Rich Header: {pe.RICH_HEADER.values}")
  ```

**Sources**:
- [DIE GitHub: Advanced Usage](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/USAGE.md#command-line)
- [pefile Documentation: Rich Headers](https://github.com/erocarrera/pefile/blob/wiki/PEfileFeatures.md#rich-headers)

### Threat Hunting & Detection Engineering
To enhance threat hunting and detection engineering in the context of 32-bit Remnux static triage, focus on analyzing Windows Event Logs for signs of adversary activity. Specifically, monitor Event ID 4688 (Process Creation) for unusual process executions, and Event ID 4624 (Logon) for suspicious login attempts. These events can indicate techniques like [T1550](https://attack.mitre.org/techniques/T1550) - "Use Alternate Authentication Material" and [T1497](https://attack.mitre.org/techniques/T1497) - "Virtualization/Sandbox Evasion". For network traffic analysis, utilize Zeek's `http` log to inspect HTTP requests for potential command and control (C2) communications. Threat hunters can pivot on fields like `username`, `domain`, and `dst_ip` to identify related events. Additionally, analyzing Suricata's `files` log for suspicious file downloads can reveal potential malware activity. For more information on Windows Event Logs and network traffic analysis, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [NSA Cybersecurity](https://www.nsa.gov/What-We-Do/Cybersecurity/) websites.


### Essential Commands & Features

While basic triage with **DIE** and **pefile** is covered, these advanced commands unlock deeper static analysis capabilities for detecting obfuscation, packing, and malicious PE artifacts.

#### **DIE (Detect It Easy)**
- **Deep Scan (`-d`)** – Recursively unpacks nested layers (e.g., UPX → custom packer). Critical for analyzing samples using **T1027.007 (Dynamic API Resolution)** or **T1562.001 (Disable or Modify Tools)**.
  ```bash
  diec -d suspicious.exe
  ```
- **All Info (`-a`)** – Extracts *all* detectable signatures (compilers, packers, protections) and entropy values. Use when investigating **T1127 (Trusted Developer Utilities Proxy Execution)**.
  ```bash
  diec -a suspicious.dll
  ```
- **Entropy Calculation** – High entropy (>7.5) suggests compression/encryption (e.g., **T1027.003 (Steganography)**). DIE displays this in the `-a` output; cross-reference with `pefile` for section-level granularity.

#### **pefile (Python PE Parser)**
- **Full PE Summary (`dump_info()`)** – Dumps headers, imports, exports, and section details in a structured format. Essential for identifying anomalous sections (e.g., `.crt` masquerading as **T1036.003 (Rename System Utilities)**).
  ```python
  import pefile
  pe = pefile.PE("malware.exe")
  pe.dump_info()  # Outputs to console; redirect to file with > pe_info.txt
  ```

**When to Use**: Combine DIE’s `-d` with `pefile.dump_info()` to validate unpacked samples before dynamic analysis. Prioritize `-a` for samples with anti-forensic techniques (e.g., **T1218.005 (Mshta)**).

**Sources**:
- DIE Deep Scan Docs: [https://github.com/horsicq/Detect-It-Easy/blob/master/docs/CLI.md](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/CLI.md)
- pefile Advanced Usage: [https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md#dump_info](https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md#dump_info)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, static triage tools like those in **REMnux** are both a threat and an opportunity. Attackers leverage similar techniques to analyze their own malware, ensuring it evades detection before deployment. For example, they may use **Obfuscated Files or Information (T1027)** variants not listed (e.g., **T1027.001: Binary Padding**) to inflate file sizes and bypass signature-based detection, leaving behind artifacts like anomalous section headers or unusually large `.rsrc` segments. Another common tactic is **Process Injection (T1055.001: Dynamic-link Library Injection)**, where malicious code is injected into legitimate processes (e.g., `explorer.exe`) to blend in with normal activity. This leaves traces such as unexpected memory allocations or suspicious thread creation events in tools like **Process Hacker**.

Evasion considerations include:
- **Timing-based delays** (e.g., **T1499.003: Application Exhaustion Flood**) to frustrate automated analysis.
- **Environmental keying** (e.g., **T1608.001: Upload Malware**) to ensure payloads only execute in targeted environments, avoiding sandboxed triage tools like REMnux.

**Key Artifacts Left Behind**:
- Unusual import tables (e.g., `VirtualAlloc` + `CreateRemoteThread` chains).
- Modified registry keys (e.g., `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`).

**Sources**:
- [MITRE ATT&CK: T1027.001](https://attack.mitre.org/techniques/T1027/001/)
- [FireEye: Red Team Techniques for Evasion](https://www.fireeye.com/blog/threat-research/2021/03/red-team-techniques-for-evasion.html)

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- REMnux ships DIE/ssdeep/pefile; tool discovery — REMnux docs: https://docs.remnux.org/discover-the-tools
- Detect-It-Easy behavior, `diec` console, `--version`, packer/compiler signature detection — horsicq/Detect-It-Easy repo: https://github.com/horsicq/Detect-It-Easy
- ssdeep context-triggered piecewise (fuzzy) hashing algorithm, CLI flags (`-V`, `-m`), scoring 0–100 — ssdeep project docs: https://ssdeep-project.github.io/ssdeep/
- Kali `ssdeep` package/usage — Kali Tools: https://www.kali.org/tools/ssdeep/
- pefile `PE` class, `sections`, `get_entropy()`, `FILE_HEADER.TimeDateStamp`, `DIRECTORY_ENTRY_IMPORT`, `__version__` — erocarrera/pefile repo: https://github.com/erocarrera/pefile
- PE/COFF `IMAGE_FILE_HEADER.TimeDateStamp` semantics (32-bit epoch link timestamp), PE32+ (PE64) format — Microsoft Learn PE Format spec: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- MinGW-w64 cross-compiler (`x86_64-w64-mingw32-gcc`) producing Windows PE — MinGW-w64 project: https://www.mingw-w64.org/ and Kali `mingw-w64` package: https://www.kali.org/tools/mingw-w64/
- Zeek File Analysis Framework and `files.log` fields (sha256/md5, mime_type, fuid) — Zeek docs: https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Suricata file extraction / `fileinfo` events — Suricata docs: https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
- Security Onion Zeek/Suricata/Elastic integration and pivots — Security Onion docs: https://docs.securityonion.net/
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 Software Packing: https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1070.006 Indicator Removal: Timestomp: https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1218.011 Signed Binary Proxy Execution: Rundll32: https://attack.mitre.org/techniques/T1218/011/
- MITRE ATT&CK T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder: https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1059.001 Command and Scripting Interpreter: PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1036.005 Masquerading: Match Legitimate Name or Location: https://attack.mitre.org/techniques/T1036/005/
- SANS FOR610 Reverse-Engineering Malware (static triage workflow): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Windows Event ID 4688 (process creation) and Sysmon Event ID 1 (process creation) for detection logic — Microsoft Learn: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688 and Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## Related modules
- [Malware static triage](../08-malware-static-triage/README.md) -- shares detect-it-easy for file identification/packing checks.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); pairs static triage with memory analysis.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); turns triage findings into detection rules.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); disk-forensics companion to file triage.

<!-- cyberlab-enriched: v2 -->
- https://github.com/horsicq/Detect-It-Easy/blob/master/docs/USAGE.md#command-line
- https://github.com/erocarrera/pefile/blob/wiki/PEfileFeatures.md#rich-headers
- https://attack.mitre.org/techniques/T1550
- https://attack.mitre.org/techniques/T1497
- https://www.cisa.gov/
- https://www.nsa.gov/What-We-Do/Cybersecurity/

<!-- cyberlab-enriched: v3 -->
- https://github.com/horsicq/Detect-It-Easy/blob/master/docs/CLI.md](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/CLI.md
- https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md#dump_info](https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md#dump_info
- https://attack.mitre.org/techniques/T1027/001/
- https://www.fireeye.com/blog/threat-research/2021/03/red-team-techniques-for-evasion.html

<!-- cyberlab-enriched: v4 -->
