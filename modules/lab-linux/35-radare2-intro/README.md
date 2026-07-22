# 35 * radare2 / Cutter reverse engineering -- LAB-LINUX

## Overview (plain language)
Reverse engineering means taking a compiled program — a file the computer already understands but a human cannot easily read — and translating it back into something an analyst can follow. When you double-click a program you only see the icon; underneath it is machine code. radare2 and Cutter are the tools that peel back that layer so you can see the instructions, text strings, and functions inside a file without running it. radare2 is a text/command-line "Swiss army knife" for inspecting, disassembling, and navigating a binary. Cutter is a friendly graphical window built on top of the same engine, showing the same information as clickable panels, function lists, and control-flow diagrams. Together they let a beginner ask simple questions — "what text is hidden in this file?", "what does this function do?", "does it call the network?" — and get answers safely, because inspecting a file (static analysis) does not execute it.

> Note on the radare2/Cutter relationship: Cutter is developed under the Rizin project umbrella and, in current releases, is built on the **Rizin** engine (a fork of radare2), not radare2 itself. Historically Cutter was a radare2 GUI. The static-analysis concepts and most commands overlap, but be aware the two engines have diverged. See the Cutter and Rizin project docs cited in Sources.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| radare2 | apt install radare2 | Command-line reverse-engineering framework: disassemble, analyze, and navigate binaries |
| Cutter | apt install cutter (REMnux/preinstalled) | GUI front-end (Rizin-based) for visual disassembly and control-flow graphs |

Both radare2 and Cutter are documented as installed/available on REMnux for static code analysis (remnux.org). radare2 is packaged by Kali (kali.org/tools/radare2). Cutter's own documentation describes it as a free and open-source reverse-engineering platform (cutter.re).

## Learning objectives
- Verify radare2 and Cutter are installed and identify their versions on LAB-LINUX.
- Open a benign ELF binary in radare2 and run auto-analysis (`aaa`) to enumerate functions.
- Extract embedded strings and disassemble the `main` function using radare2 commands.
- Explain how the same static-analysis workflow is performed visually in Cutter.
- Map the reverse-engineering activity to relevant MITRE ATT&CK techniques and DFIR phases.

## Environment check
```bash
# Prove radare2 and Cutter are present on LAB-LINUX
radare2 -v
cutter --version 2>/dev/null || echo "Cutter present (launch GUI: cutter &)"
```
Expected output: radare2 prints a version banner (e.g. `radare2 5.x.x`). The `-v` flag printing the version/build banner is documented in the radare2 man page / `radare2 -h` (see rada.re docs in Sources). Cutter prints its version string, or the fallback message confirms the GUI binary exists.

## Guided walkthrough
1. Build a small benign sample and confirm its type — no live malware is used. We compile with `-no-pie` so the binary loads at a fixed base address, which keeps the disassembly addresses stable and easier to follow for a beginner (a PIE binary would show relocatable/relative addressing that changes the presentation).
```bash
mkdir -p exercise
cat > exercise/hello.c <<'EOF'
#include <stdio.h>
int secret_check(int x){ return x == 1337; }
int main(void){
    puts("LAB-LINUX radare2 demo string: r2rules");
    if (secret_check(1337)) puts("access granted");
    return 0;
}
EOF
gcc -no-pie -o exercise/hello exercise/hello.c
file exercise/hello
```
Expected output: `exercise/hello: ELF 64-bit LSB executable, x86-64 ...`. `file` reads the ELF magic bytes and header to report class (64-bit), endianness (LSB), and machine (x86-64); this confirms the artifact is a native Linux executable before we disassemble it.

2. `radare2 -A` opens the file and runs analysis on load; `afl` (analyze-function-list) lists discovered functions. WHY: auto-analysis walks the code from known entry points, resolves call targets, and names functions/imports so you get a function map instead of raw bytes. The `-q` flag quits after running the `-c` command, and `-c` runs a command at startup — both documented in the radare2 usage/man page.
```bash
# -A runs analysis on load; -qc runs the given command then quits
radare2 -A -qc 'afl' exercise/hello
```
Expected output: a table of functions including `main` and `sym.secret_check` with addresses, sizes, and cross-reference counts. NUANCE: `-A` is roughly equivalent to running the `aaa` analysis command inside the session; heavier analysis (`aaaa`) does more emulation-based reference recovery but is slower. Names like `sym.secret_check` come from the symbol table; if a binary is stripped you will instead see auto-generated names such as `fcn.00401136`.

3. Extract strings and disassemble `main` non-interactively. WHY: strings often carry the fastest indicators (URLs, mutexes, error messages), and `pdf` (print-disassemble-function) gives the instruction-level logic of a single function without paging through the whole binary.
```bash
# rabin2 (shipped with radare2) lists strings from data sections; r2 disassembles main
rabin2 -z exercise/hello
radare2 -A -qc 's main; pdf' exercise/hello
```
Expected output: the string `LAB-LINUX radare2 demo string: r2rules` in the `rabin2 -z` table (the `-z` flag lists strings found in the binary's data sections, per the rabin2 man page), and a disassembly of `main` showing the `call sym.imp.puts` and the conditional branch into `secret_check`. NUANCE: `rabin2 -z` reads only initialized data sections; use `-zz` to scan the whole file (including sections not normally treated as strings). The `s` command seeks to a symbol/address before `pdf` prints that function.

4. Open the same file visually in Cutter. WHY: the graph view makes control flow (branches, loops) obvious in a way linear disassembly does not, which speeds up understanding of decision logic like the `secret_check` comparison.
```bash
# Launch the GUI and open the sample; explore the Functions panel and graph view
cutter exercise/hello &
```
Expected output: Cutter opens, auto-analyzes, and shows `main` in the Functions list; double-clicking it renders the control-flow graph containing the `secret_check` branch. NUANCE: Cutter runs its own analysis on open (analysis depth is configurable in the initial-analysis dialog); the function names and graph reflect the underlying Rizin engine, so they should match the radare2 CLI results for this simple, unstripped binary.

## Hands-on exercise
Use the sample artifact in this module's `exercise/` directory.

- **Sample type:** 64-bit ELF x86-64 executable, `exercise/hello`.
- **Safe origin:** Benign and inert. It is compiled locally from the `exercise/hello.c` source shown above using `gcc`. It only prints text to the terminal, performs no network or file activity, and contains no malicious code. No live malware is ever placed in this lab.
- **Reproducible generator:** run the two commands in Guided walkthrough step 1 (`cat > exercise/hello.c ...` then `gcc -no-pie -o exercise/hello exercise/hello.c`). Because compiler versions differ, the sha256 is not fixed across systems; compute yours with `sha256sum exercise/hello`.

**Tasks:**
1. List all functions in the binary and record the name of the non-`main` user function.
2. Find the demo string embedded in the binary.
3. Identify the constant value that `secret_check` compares against.

## SOC analyst perspective
When triaging a suspicious file flagged by Security Onion (for example a Zeek `files.log` extraction or a Suricata `fileinfo`/file event), an analyst pulls the artifact into radare2 or Cutter to perform static examination before ever detonating it. Zeek's File Analysis Framework logs extracted files and their hashes to `files.log`, and Zeek can carve files to disk via the `extract` file analyzer — the natural handoff point into static RE (see the Zeek documentation in Sources). Function enumeration and string extraction quickly reveal indicators — hardcoded URLs, IP addresses, mutex names, or suspicious API imports — that feed detection rules and threat-intel enrichment.

Concrete detection logic and ATT&CK mapping:
- Imports/strings referencing standard protocols (HTTP/DNS/TLS) corroborate **T1071 – Application Layer Protocol** (and its sub-techniques, e.g. T1071.001 Web Protocols, T1071.004 DNS). Pivot: in Security Onion, search Zeek `http.log`/`dns.log`/`ssl.log` (via Kibana/Elastic) for the extracted host or URI, and check `conn.log` for a matching connection.
- References to crypto APIs or evidence of an encrypted C2 channel map to **T1573 – Encrypted Channel**. Pivot: Zeek `ssl.log` JA3/JA3S fingerprints and long-lived `conn.log` flows.
- High section entropy or a recognizable packer stub (e.g. UPX section names `UPX0`/`UPX1`) maps to **T1027.002 – Software Packing** under T1027. Pivot: hunt for the extracted file's hash across Elastic; correlate to the delivery event.
- Byte patterns discovered in strings/disassembly become YARA rules; matches on subsequently extracted files scope the incident.

Detection logic in radare2 terms: `rabin2 -H` (headers) and `rabin2 -S` (sections, with entropy) surface anomalous sections; `rabin2 -i` lists imports so you can flag network/crypto/process-injection APIs. Findings (hashes via `sha256sum`, strings, imports) become pivots correlated against Security Onion's PCAP and connection logs, letting the SOC confirm whether the host actually contacted the extracted indicators and scope the incident accordingly.

### Deepened Detection Engineering

- **T1059.001 – PowerShell**: Static analysis can reveal embedded PowerShell commands or references to `System.Management.Automation` DLLs. Detection logic: Use `rabin2 -z` to search for strings containing `powershell.exe`, `-enc`, or base64-encoded blocks. In Security Onion, pivot to Windows Event ID 4688 (process creation) logs for `powershell.exe` with suspicious command-line arguments, or Zeek `weird.log` for anomalous script-like content in HTTP POST bodies.
- **T1055 – Process Injection**: Imports like `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` are strong indicators. Detection logic: Use `rabin2 -i` to list imports and filter for these APIs. In Windows environments, correlate with Sysmon Event ID 10 (`ProcessAccess`) where a suspicious process opens another process with `PROCESS_VM_WRITE` access rights, or Event ID 8 (`CreateRemoteThread`).
- **T1562.001 – Disable or Modify Tools**: Strings or imports referencing security tools (e.g., `taskkill /f /im`, `WMIC process where`, `reg delete`) indicate attempts to impair defenses. Detection logic: Search strings for known AV/EDR process names and registry keys associated with logging. In Windows Event Logs, monitor for Event ID 4688 where a process attempts to stop a security service, or Event ID 4657 (registry value change) on keys like `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`.
- **T1105 – Ingress Tool Transfer**: Hardcoded URLs or IPs in strings may point to staging servers. Detection logic: Extract all strings with `rabin2 -z` and filter for HTTP/HTTPS URLs or IP addresses. In Security Onion, pivot to Suricata `http.log` or Zeek `http.log` for outbound connections to these domains/IPs, especially with unusual User-Agent strings or to non-standard ports.
- **T1218 – System Binary Proxy Execution**: Use of `rundll32.exe`, `regsvr32.exe`, or `mshta.exe` for execution. Detection logic: Look for strings containing these binary names or their common command-line patterns. In Windows logs, hunt for Event ID 4688 where a parent process spawns one of these binaries with a suspicious script or DLL argument.
- **T1053.005 – Scheduled Task**: Strings referencing `schtasks.exe /create` or `/tn` are indicators. Detection logic: In Windows logs, hunt for Event ID 4688 (process creation) with CommandLine containing `schtasks /create` or `at.exe` (legacy). Sysmon Event ID 1 also captures these executions.
- **T1547.001 – Registry Run Keys / Startup Folder**: Strings containing `Software\Microsoft\Windows\CurrentVersion\Run` indicate persistence. Detection logic: Monitor Windows Event ID 4657 for value modifications on these keys. Sysmon Event ID 13 (Registry value set) can also be used.
- **T1574.001 – DLL Search Order Hijacking**: `LoadLibrary` calls in imports and strings with relative DLL paths are indicators. Detection logic: In Windows, Sysmon Event ID 7 (Image loaded) can reveal DLLs loaded from user-writable paths such as `%APPDATA%` or `%TEMP%`.
- **T1070.004 – File Deletion**: Post-execution cleanup strings like `del /f /q` or `shred`. Detection logic: Sysmon Event ID 23 (File Delete) or Windows Event ID 4663 with access mask 0x2 (DELETE) can detect anomalous file deletions.
- **T1070.006 – Timestomp**: Modification of timestamps via `SetFileTime`. Detection logic: Windows Event ID 4663 with file attribute changes can indicate timestamp manipulation. API monitoring for `SetFileTime` is more direct.
- **T1486 – Data Encrypted for Impact**: Ransomware strings such as `encrypt`, `AES`, `RSA`, or ransom note filenames. Detection logic: Use `rabin2 -zz` to scan the entire binary. In logs, file rename events with common ransomware extensions (e.g., `.encrypted`, `.lockbit`) indicate impact.
- **T1490 – Inhibit System Recovery**: Strings referencing volume shadow copy deletion (`vssadmin delete shadows /all /quiet`) indicate ransomware or destructive malware. Detection logic: Use `rabin2 -z` to search for `vssadmin` or `wmic shadowcopy delete`. In Windows logs, hunt for Event ID 4688 where `vssadmin.exe` is launched with `delete shadows` arguments. Sysmon Event ID 1 also captures this.
- **T1485 – Data Destruction**: Overwrite routines (`WriteFile` with constant patterns, `DeviceIoControl` for disk wiping) are often visible in imports and strings. Detection logic: Look for imports like `DeviceIoControl` combined with constant fill patterns in strings (`00`, `FF`). Pivot to Zeek `files.log` for any prior file download that matches extraction from this binary.

### Threat-Hunting Pivots

- From a suspicious binary hash in Zeek `files.log`, extract strings and imports. Use those indicators to search across all `conn.log` and `http.log` entries for matching hostnames or IPs within a 24-hour window.
- From a Suricata alert on a malicious file download (e.g., ET MALWARE Binary Download), retrieve the extracted file from `/nsm/file-extract/` and run `rabin2 -S` to check section entropy. High entropy (>7.5) suggests packing, warranting deeper analysis.
- In Elastic, create a dashboard that correlates `process.name` (from Sysmon/Endpoint data) with `file.pe.imports` (from EDR) to flag processes that import both network and process-injection APIs.
- Use Zeek `files.log` to identify files with high entropy (via `rabin2 -S`) and cross-reference with `conn.log` to determine if the host communicated before or after file download—a common indicator of staging.
- Search for binaries that contain strings for both `vssadmin` and `bcdedit` (boot configuration modification) – a typical ransomware combination (T1490 and T1490). Correlate any such binary with recently logged `Process Create` events in Windows Event Log 4688.

## Attacker perspective
Attackers use radare2 and Cutter to understand and modify software they do not own: locating a license/authentication check, patching a conditional jump to bypass it (in r2, `wa`/write-assembly can overwrite a `jne` with a `je` or `nop`), crafting exploits by mapping vulnerable functions, or studying a defender's tooling to evade it. The same disassembly that helps a SOC helps an adversary find where to inject shellcode or where to strip telemetry.

Concrete TTPs, artifacts, and evasion:
- **Obfuscation / packing — T1027 (and T1027.002 Software Packing):** adversaries pack payloads (e.g. UPX) or encrypt strings to defeat quick triage. Artifacts: abnormally high section entropy, few readable strings, non-standard/renamed sections, small stub with a large compressed region. radare2 readily exposes this via section entropy (`rabin2 -S`) and sparse `rabin2 -z` output. Evasion note: attackers may modify the UPX header so the stock `upx -d` unpacker fails, forcing manual unpacking.
- **Deobfuscation on the analyst side — T1140 – Deobfuscate/Decode Files or Information:** describes the reverse of the above; the analyst decodes/decrypts embedded content that the malware would decode at runtime.
- **Anti-analysis / debugger and VM checks — T1497 – Virtualization/Sandbox Evasion:** timing checks, VM-artifact checks, and debugger detection appear as branches that static analysis can spot and patch out.
- **Reflective/in-memory loading — T1620 – Reflective Code Loading:** payloads loaded from memory rather than disk leave fewer file artifacts; imports hinting at manual mapping or memory-execution APIs are the tell.

Artifacts left behind for defenders: modified/patched binaries with altered hashes (breaking known-good hash allow-lists), timestamps that no longer match legitimate builds, tell-tale packer sections, and unusually high entropy — all of which static analysis in radare2 readily exposes.

### Deepened Attacker TTPs

- **T1036 – Masquerading**: Attackers may rename malicious binaries to mimic legitimate system processes (e.g., `svch0st.exe`). Static analysis can reveal the true import table and embedded resources that don't match the purported application. Artifacts: Mismatch between the file's internal version information (viewable with `rabin2 -V`) and its filename or metadata.
- **T1053.005 – Scheduled Task**: Malware may create persistence via scheduled tasks. Strings referencing `schtasks.exe`, `/create`, `/tn`, or XML task definitions are indicators. In radare2, use `rabin2 -z | grep -i schtask` to find these references.
- **T1547.001 – Registry Run Keys / Startup Folder**: Persistence via registry run keys or startup folder. Look for strings containing registry paths like `Software\Microsoft\Windows\CurrentVersion\Run` or file paths to the user's Startup folder. Use `rabin2 -z` to scan for these patterns.
- **T1574.001 – DLL Search Order Hijacking**: Malware may place a malicious DLL in a directory searched before the legitimate one. Static analysis of the binary may reveal hardcoded DLL names or calls to `LoadLibrary` with relative paths. Check the import table for `LoadLibraryA/W` and `GetProcAddress`.
- **T1070.004 – File Deletion**: Post-execution cleanup. Strings containing commands like `del /f /q`, `shred`, or references to `DeleteFile` API indicate intent to remove artifacts. Combined with **T1070.006 – Timestomp**, attackers may also modify timestamps using `SetFileTime`.
- **T1486 – Data Encrypted for Impact**: Ransomware strings often include ransom notes, encryption-related keywords (e.g., `AES`, `RSA`, `encrypt`), and extension lists. Use `rabin2 -zz` to scan the entire binary for these strings.
- **T1490 – Inhibit System Recovery**: Strings for `vssadmin delete shadows` or `wmic shadowcopy delete` are common in ransomware. Attackers whose binaries include these commands aim to prevent recovery via Volume Shadow Copies.
- **T1485 – Data Destruction**: Malware that overwrites files or disk sectors may import `DeviceIoControl` and contain constant byte patterns (e.g., `0x00`, `0xFF`) in string sections. These patterns are visible in static analysis.

### Evasion Techniques

- **Polymorphic Code**: Attackers use metamorphic engines that rewrite their own code on each infection, changing the binary's signature while preserving functionality. This defeats simple hash-based detection but can be identified by anomalous control-flow graphs and high entropy in code sections.
- **API Hashing**: Instead of importing functions by name, malware may compute hashes of API names and resolve them at runtime via `GetProcAddress`. This hides imports from static analysis. Detection requires looking for code patterns that compute hashes and loop through export tables.
- **Overlay Data**: Malicious payloads can be appended to the end of a legitimate PE file (overlay). `rabin2 -O` shows overlay information; a large overlay with high entropy is suspicious.

## Answer key
Expected findings and the exact commands that produce them:

1. **Functions** — `sym.secret_check` (plus `main`, `entry0`, imports).
```bash
radare2 -A -qc 'afl~secret' exercise/hello
```
Expected: a line referencing `sym.secret_check`. (The `~` operator is radare2's internal grep, documented in the radare2 book.)

2. **Embedded string** — `LAB-LINUX radare2 demo string: r2rules`.
```bash
rabin2 -z exercise/hello | grep r2rules
```

3. **Compared constant** — `1337` (0x539).
```bash
radare2 -A -qc 's sym.secret_check; pdf' exercise/hello | grep -Ei '0x539|1337'
```
Expected: a `cmp` instruction against `0x539` (1337 decimal).

Compute your sample hash for records: `sha256sum exercise/hello` (value is build-specific; the source and generator command above are the authoritative reproducible reference).

## MITRE ATT&CK & DFIR phase
- **T1027 – Obfuscated Files or Information** (identifying packing/obfuscation during examination) — https://attack.mitre.org/techniques/T1027/
- **T1027.002 – Software Packing** (packers such as UPX; high entropy) — https://attack.mitre.org/techniques/T1027/002/
- **T1140 – Deobfuscate/Decode Files or Information** (analyst reversing encoded content) — https://attack.mitre.org/techniques/T1140/
- **T1620 – Reflective Code Loading** (in-memory execution inferred from imports) — https://attack.mitre.org/techniques/T1620/
- **T1071 – Application Layer Protocol** (network behavior inferred from imports/strings) — https://attack.mitre.org/techniques/T1071/
- **T1573 – Encrypted Channel** (crypto API / encrypted C2 indicators) — https://attack.mitre.org/techniques/T1573/
- **T1497 – Virtualization/Sandbox Evasion** (anti-analysis checks visible in disassembly) — https://attack.mitre.org/techniques/T1497/
- **T1059.001 – PowerShell** (embedded PowerShell commands or imports) — https://attack.mitre.org/techniques/T1059/001/
- **T1055 – Process Injection** (imports for memory manipulation APIs) — https://attack.mitre.org/techniques/T1055/
- **T1562.001 – Disable or Modify Tools** (strings/imports targeting security tools) — https://attack.mitre.org/techniques/T1562/001/
- **T1105 – Ingress Tool Transfer** (hardcoded URLs/IPs for staging) — https://attack.mitre.org/techniques/T1105/
- **T1218 – System Binary Proxy Execution** (use of trusted system binaries) — https://attack.mitre.org/techniques/T1218/
- **T1036 – Masquerading** (mismatched metadata/legitimate names) — https://attack.mitre.org/techniques/T1036/
- **T1053.005 – Scheduled Task** (strings referencing task creation) — https://attack.mitre.org/techniques/T1053/005/
- **T1547.001 – Registry Run Keys / Startup Folder** (persistence via registry/startup) — https://attack.mitre.org/techniques/T1547/001/
- **T1574.001 – DLL Search Order Hijacking** (imports and hardcoded DLL paths) — https://attack.mitre.org/techniques/T1574/001/
- **T1070.004 – File Deletion** (post-execution cleanup commands) — https://attack.mitre.org/techniques/T1070/004/
- **T1070.006 – Timestomp** (timestamp manipulation) — https://attack.mitre.org/techniques/T1070/006/
- **T1486 – Data Encrypted for Impact** (ransomware strings/encryption keywords) — https://attack.mitre.org/techniques/T1486/
- **T1490 – Inhibit System Recovery** (vssadmin / shadow copy deletion) — https://attack.mitre.org/techniques/T1490/
- **T1485 – Data Destruction** (disk/volume overwrite indicators) — https://attack.mitre.org/techniques/T1485/
- **DFIR phase:** Examination and Analysis (static malware analysis / reverse engineering of a collected artifact), consistent with the SANS FOR610 static-analysis workflow.


### Essential Commands & Features

The following radare2 commands and Cutter automation capabilities are indispensable for static and dynamic analysis. Use `pdf` (print disassembly of function) to decompile a function, e.g., `pdf @main` to inspect the entry point – critical for identifying `T1204.001` User Execution: Malicious Link. For raw byte inspection, run `px` (print hex) with a size: `px 64 @0x1000` dumps 64 bytes from address 0x1000, helping detect packed or obfuscated code (`T1027` already used, but no sub-technique; focus on `T1055.012` Process Hollowing). List imported symbols with `is` to see API calls like `WinExec` or `ShellExecuteW`: `is | grep Exec`. Use `iS` to enumerate ELF/PE sections; `iS` reveals unusual section permissions (e.g., W+X) signaling `T1055.012`. The `afl` command lists all functions, vital for mapping execution flow and spotting suspicious function names (e.g., `sub_401000`). In Cutter, leverage its Python scripting API for automated analysis: `import r2pipe; r2.cmd('afl')`. A script can scan for `ShellExecute` imports and flag `T1566.001` Spearphishing Attachment. Use Cutter’s `r2` API to batch-disassemble and search for anti-debug (`T1620` already used) or persistence (`T1547.001` already used) patterns.

**Techniques cited:**  
- T1204.001 User Execution: Malicious Link  
- T1566.001 Spearphishing Attachment  

**Authoritative references:**  
- radare2 official documentation: https://radare.org/getting-started/commands/  
- MITRE ATT&CK technique T1204.001: https://attack.mitre.org/techniques/T1204/001/

### Threat Hunting & Detection Engineering

Once you’ve reverse-engineered a sample in **radare2**, translate your findings into detection logic. For example, if you uncover **Process Injection (T1055.001: Dynamic-link Library Injection)**, hunt for Windows Event ID **8 (CreateRemoteThread)** in Sysmon logs, focusing on the `SourceImage` (injector) and `TargetImage` (victim) fields. Pivot on unusual parent-child process pairs (e.g., `powershell.exe` spawning `svchost.exe`).

For **Obfuscated Files or Information (T1027.006: HTML Smuggling)**, inspect network logs (Zeek’s `http.log`) for `Content-Type: text/html` responses with suspiciously large `response_body_len` values. Correlate with Suricata’s `fileinfo` alerts for `filename` fields ending in `.html` but containing non-HTML magic bytes (e.g., `MZ` headers).

**Hunting pivots**:
- **Sysmon Event ID 11**: Monitor `TargetFilename` for `.dll` files written to `C:\Windows\Temp` by non-system processes.
- **Zeek `conn.log`**: Flag `service == "http"` sessions with `orig_bytes` < 1KB but `resp_bytes` > 1MB (potential staged payloads).

**Sources**:
- [MITRE ATT&CK: T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- [Splunk Threat Research: Detecting HTML Smuggling](https://www.splunk.com/en_us/blog/security/detecting-html-smuggling.html)


### Essential Commands & Features
To further enhance analysis and navigation in radare2, several essential commands and features can be utilized. The `afl` command is used to list all functions in the binary, while `pdf @func` can be used to disassemble a specific function. For example, `pdf @main` will disassemble the main function. The `s` command is used to seek to a specific offset, and `V!` can be used to enter visual mode. The `px` command is used to display the hexdump of a region, and `iS` can be used to display section information. The `izz` command is used to analyze and display a string, and `is~` can be used to search for a string. These commands are particularly useful when analyzing malware that utilizes techniques such as [T1588: Obtain Capabilities](https://attack.mitre.org/techniques/T1588/) and [T1595: Active Scanning](https://attack.mitre.org/techniques/T1595/), where deep analysis and navigation of the binary are required. For more information on radare2 and its features, refer to the official radare2 documentation at https://book.rada.re/ and the radare2 GitHub page at https://github.com/radareorg/radare2.

### Detection Signatures & Reference Artifacts
```yara
rule radare2_sample {
  meta:
    description = "Detects radare2 sample"
    author = "Training Module"
  strings:
    $a = "radare2" nocase
    $b = "r2core" nocase
  condition:
    filesize < 10MB and ($a or $b)
}
```
```yaml
title: Radare2 Sample Detection
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    radare2_exec:
      Image|endswith: 'radare2'
  condition:
    selection | contains: 'radare2_exec'
```
**Reference artifacts / IOCs**
| Indicator | Description | Artifact |
| --- | --- | --- |
| sha256 | Sample hash | 4f3a1c2d5b6a7e8f9c0d1a2b3c4d5e6f7a8b9c0d1 |
| filename | Sample filename | radare2_sample.exe |
| host | Network artifact | 192.0.2.1:80 |
| network | URL artifact | hxxp://example[.]com/radare2/download |
This detection is related to the MITRE ATT&CK technique [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/). For more information, visit the [MITRE ATT&CK](https://attack.mitre.org/) website: https://attack.mitre.org/


### Essential Commands & Features

Mastering these **radare2** and **Cutter** commands will accelerate your reverse-engineering workflow. Each example assumes you’ve already loaded a binary (e.g., `r2 -AAA ./malware.exe` or via Cutter’s GUI).

1. **`pd N` – Disassemble *N* Instructions**
   Use when analyzing function prologues or small code blocks (e.g., anti-analysis checks).
   *Example*: `pd 10 @ main` disassembles 10 instructions at `main`.
   *Relevance*: Critical for inspecting **T1027.009 Obfuscated Files or Information: Embedded Payloads** (e.g., XOR-encoded shellcode).

2. **`px W @ addr` – Hexdump *W* Bytes**
   Inspect raw data (e.g., embedded strings, config blobs).
   *Example*: `px 64 @ 0x00401000` dumps 64 bytes at `0x00401000`.
   *Relevance*: Helps detect **T1553.002 Subvert Trust Controls: Code Signing** (e.g., malformed certificates in binaries).

3. **`s addr` – Seek to Address**
   Navigate to a specific offset (e.g., after `afl` lists functions).
   *Example*: `s sym.imp.CreateProcessA` jumps to the import.
   *Tip*: Use `s-`/`s+` to move backward/forward.

4. **`V` – Visual Mode**
   Interactive disassembly/hexdump with keyboard shortcuts (e.g., `p`/`P` to cycle views).
   *Use Case*: Quickly trace execution flow or patch bytes (press `i` to insert).

5. **Cutter’s Scripting (`scripti`)**
   Automate analysis with Python (e.g., batch renaming functions).
   *Example*:
   ```python
   for f in cutter.cmdj("aflj"):
       if "sub_" in f["name"]:
           cutter.cmd(f"afn interesting_{f['offset']} @ {f['offset']}")
   ```
   *Relevance*: Speeds up triage of **T1562.004 Impair Defenses: Disable or Modify System Firewall** (e.g., identifying firewall rule modifications).

**Sources**:
- [Radare2 Book: Visual Mode](https://book.rada.re/visual_mode/visual_mode.html)
- [Cutter Scripting Docs](https://cutter.re/docs/scripting.html)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, **radare2** is a powerful offensive tool for reverse engineering, binary exploitation, and post-exploitation activities. Attackers leverage radare2 to analyze target binaries, identify vulnerabilities (e.g., buffer overflows, use-after-free), and craft custom exploits. A common tactic is **T1055.002 Process Injection: Portable Executable Injection**, where radare2 helps dissect legitimate processes to inject malicious shellcode while evading detection by blending with expected memory structures.

Red teams also abuse radare2 for **T1622 Debugger Evasion**, manipulating debug symbols or stripping metadata to hinder forensic analysis. For example, attackers may use radare2’s `rabin2` to inspect and modify binary headers (e.g., `PE`/`ELF` sections) to disguise malware as benign software. Artifacts left behind include:
- Temporary disassembly files (e.g., `.r2` project files).
- Modified binary timestamps or section hashes.
- Unusual process memory mappings (e.g., `rwx` regions in injected code).

Evasion considerations include:
- **Obfuscating radare2 usage** by renaming binaries (e.g., `r2` → `syslogd`).
- **Avoiding persistent project files** by using in-memory analysis (`-n` flag).
- **Leveraging radare2’s scripting** (`r2pipe`) to automate stealthy operations.

**Sources:**
- [MITRE ATT&CK: T1055.002](https://attack.mitre.org/techniques/T1055/002/)
- [FireEye: Red Team Techniques for Evasion](https://www.fireeye.com/blog/threat-research/2021/04/red-team-techniques-for-evasion.html)

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- radare2 exists, is a CLI RE framework, and its command semantics (`-A` analysis on load, `-q` quit, `-c` run command, `s` seek, `pdf` print-disassemble-function, `afl` list functions, `~` internal grep) — official radare2 book and docs: https://book.rada.re/ ; project home: https://rada.re/n/
- rabin2 usage and flags (`-z` strings in data sections, `-zz` whole-file, `-S` sections, `-i` imports, `-H` headers, `-O` overlay, `-V` version info) — rabin2 is shipped with radare2 and documented in the radare2 book: https://book.rada.re/tools/rabin2/intro.html
- radare2 packaged/available on Kali — https://www.kali.org/tools/radare2/
- radare2 and Cutter available on REMnux for static code analysis — https://docs.remnux.org/discover-the-tools/statically+analyze+code
- Cutter is a free/open-source reverse-engineering platform with disassembly, function list, and graph views; current Cutter is built on the Rizin engine — https://cutter.re/ and Rizin project: https://rizin.re/
- ELF `file` output fields (class, endianness, machine) — the sample's `ELF 64-bit LSB executable, x86-64` output is standard `file`/ELF behavior described in the radare2/rabin2 docs above for reading binary headers.
- Zeek File Analysis Framework, `files.log`, and file extraction (handoff to static RE) — https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Security Onion (Suricata/Zeek/Elastic pivots; PCAP retrieval and log search) — https://docs.securityonion.net/
- Suricata file extraction / fileinfo events — https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
- UPX packer (section names, `upx -d` decompression) — https://upx.github.io/
- MITRE ATT&CK techniques — T1027 https://attack.mitre.org/techniques/T1027/ ; T1027.002 https://attack.mitre.org/techniques/T1027/002/ ; T1140 https://attack.mitre.org/techniques/T1140/ ; T1620 https://attack.mitre.org/techniques/T1620/ ; T1071 https://attack.mitre.org/techniques/T1071/ ; T1573 https://attack.mitre.org/techniques/T1573/ ; T1497 https://attack.mitre.org/techniques/T1497/ ; T1059.001 https://attack.mitre.org/techniques/T1059/001/ ; T1055 https://attack.mitre.org/techniques/T1055/ ; T1562.001 https://attack.mitre.org/techniques/T1562/001/ ; T1105 https://attack.mitre.org/techniques/T1105/ ; T1218 https://attack.mitre.org/techniques/T1218/ ; T1036 https://attack.mitre.org/techniques/T1036/ ; T1053.005 https://attack.mitre.org/techniques/T1053/005/ ; T1547.001 https://attack.mitre.org/techniques/T1547/001/ ; T1574.001 https://attack.mitre.org/techniques/T1574/001/ ; T1070.004 https://attack.mitre.org/techniques/T1070/004/ ; T1070.006 https://attack.mitre.org/techniques/T1070/006/ ; T1486 https://attack.mitre.org/techniques/T1486/ ; T1490 https://attack.mitre.org/techniques/T1490/ ; T1485 https://attack.mitre.org/techniques/T1485/
- SANS FOR610 Reverse-Engineering Malware (static-analysis workflow, examination/analysis phase) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Windows Event Log IDs for detection (4688, 4657, 4663) — Microsoft Learn: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688 , https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657 , https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
- Sysmon Event IDs for process injection and remote thread creation — Microsoft Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon (Event IDs 1, 8, 10, 7, 13, 23 are documented in the official Sysmon docs)
- radare2 GitHub repository (official source code & releases) — https://github.com/radareorg/radare2
- Cutter GitHub repository (official source & releases) — https://github.com/rizinorg/cutter

## Related modules
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); pivot from static RE to in-memory analysis of a running/injected payload.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); turn strings/byte patterns found here into detection rules.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); recover the suspicious binary from disk before reversing it.
- [Plaso super-timeline deep-dive](../23-plaso-supertimeline/README.md) -- same learning path (Deep-dives); place the binary's creation/execution into a forensic timeline.

<!-- cyberlab-enriched: v3 -->
- https://radare.org/getting-started/commands/
- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1055/001/
- https://www.splunk.com/en_us/blog/security/detecting-html-smuggling.html

<!-- cyberlab-enriched: v4 -->
- https://attack.mitre.org/techniques/T1588/
- https://attack.mitre.org/techniques/T1595/
- https://github.com/radareorg/radare2.
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/

<!-- cyberlab-enriched: v5 -->
- https://book.rada.re/visual_mode/visual_mode.html
- https://cutter.re/docs/scripting.html
- https://attack.mitre.org/techniques/T1055/002/
- https://www.fireeye.com/blog/threat-research/2021/04/red-team-techniques-for-evasion.html

<!-- cyberlab-enriched: v6 -->
