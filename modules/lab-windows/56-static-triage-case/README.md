# 56 * Scenario: rapid static triage -- LAB-WINDOWS

## Overview (plain language)
Rapid static triage means quickly learning what a suspicious file *is* and what it *might do* — without ever running it. Instead of executing the sample (which could infect the machine), you inspect it "at rest" on disk. These four tools each answer a different beginner-friendly question: Detect-It-Easy (DIE) tells you the file type, compiler, and whether it looks packed. PE-bear opens up the internal structure of a Windows program (its headers, sections, and imported functions). FLOSS pulls out readable text, including strings that malware tries to hide. capa reads the compiled code and reports the program's likely *capabilities* in plain English, such as "encrypts data" or "communicates over HTTP." Together they let an analyst form a fast, safe first opinion in minutes.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Detect-It-Easy (DIE) | FLARE-VM (choco/installer) | Identify file type, compiler/packer, and entropy signatures |
| capa | FLARE-VM (`capa.exe`) | Map compiled code to human-readable capabilities via rules |
| FLOSS | FLARE-VM (`floss.exe`) | Extract static, stack, tight, and decoded/obfuscated strings |
| PE-bear | FLARE-VM (installer) | Inspect PE headers, sections, imports/exports interactively |

Notes on tool behavior (sourced):
- DIE ships a console front-end `diec` (also `diec.exe` on Windows) in addition to the GUI; both apply its detection signature database. See the DIE repo README (https://github.com/horsicq/Detect-It-Easy) and the console-mode documentation (https://github.com/horsicq/DIE-engine).
- capa is a rule-based capability detector that maps rules to MITRE ATT&CK and MBC; capability rules live in the community `capa-rules` repo (https://github.com/mandiant/capa-rules), documented in the capa README (https://github.com/mandiant/capa).
- FLOSS statically extracts printable ASCII/UTF-16LE strings and additionally recovers *stack strings*, *tight strings*, and *decoded strings* by emulation (https://github.com/mandiant/flare-floss).
- PE-bear is a GUI PE reversing/inspection tool (headers, sections, imports/exports); it has no scripting CLI, so header confirmation here is done via the GUI plus PowerShell reflection (https://github.com/hasherezade/pe-bear).

## Learning objectives
- Identify a sample's file type, compiler, and packing status using Detect-It-Easy.
- Enumerate a PE's sections, entry point, and imported APIs with PE-bear.
- Recover hidden/obfuscated strings using FLOSS and interpret indicators of compromise.
- Produce a capability report with capa and correlate results to MITRE ATT&CK techniques.
- Assemble a concise triage verdict from all four tools without executing the sample.

## Environment check
```powershell
# Prove each triage tool is available on FLARE-VM
capa.exe --version
floss.exe --version
Get-ChildItem "C:\Tools\die\diec.exe" | Select-Object Name, Length
Get-ChildItem "C:\Tools\PE-bear\PE-bear.exe" | Select-Object Name, Length
```
Expected output: capa prints its version (for example `capa 7.x.x`), FLOSS prints its version banner, and `Get-ChildItem` lists `diec.exe` and `PE-bear.exe` with a nonzero size, confirming the tools are installed. Both capa and FLOSS support `--version`, per their READMEs (https://github.com/mandiant/capa, https://github.com/mandiant/flare-floss). On a FLARE-VM install the exact install paths can vary by package version — if the paths above do not resolve, locate the binaries with `Get-Command capa.exe, floss.exe` and `Get-ChildItem C:\Tools -Recurse -Filter diec.exe`.

## Guided walkthrough
1. Build the benign sample used throughout (see Hands-on exercise) so a real PE exists to triage.
```powershell
# Confirm the sample is present before triage
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
Why: SHA256 is the industry-standard content hash for identifying and re-locating a sample across tools, tickets, and threat-intel lookups; `Get-FileHash` defaults to SHA256 but we set it explicitly (https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash). Expected: prints the SHA256 digest of `sample.exe`, proving the file exists and is intact.

2. `diec.exe` — Detect-It-Easy identifies file type, compiler, and entropy (packing hint).
```powershell
& "C:\Tools\die\diec.exe" -j .\exercise\sample.exe
```
Why: DIE first — file-type identification drives every later choice. The `-j` flag emits machine-parseable JSON so results can be piped into a case record; DIE's console options are documented in the DIE-engine repo (https://github.com/horsicq/DIE-engine). DIE reports *detects* (format, linker/compiler, tooling) and can compute section entropy on demand. Expected: JSON naming the format (`PE64`/`PE32`), the detected compiler/linker (for example `Microsoft Visual C/C++`), and low entropy for the code section. Nuance: entropy near 8.0 bits/byte suggests compression/encryption (packing); a cleanly-linked MSVC binary like this sample sits well below that. Entropy alone is a hint, not proof — DIE's packer *signatures* and the import table (next step) corroborate it (https://github.com/horsicq/Detect-It-Easy).

3. PE-bear — inspect structure. Launch the GUI, then confirm the CLI/headers programmatically.
```powershell
# Open the sample for header/section/import inspection
& "C:\Tools\PE-bear\PE-bear.exe" .\exercise\sample.exe
```
Why: the PE headers and import table tell you how Windows will load the file and which OS services it will call — the single richest static signal for intent. PE-bear renders DOS/NT headers, the section table (name, virtual/raw size, characteristics), and a per-DLL Imports view (https://github.com/hasherezade/pe-bear). Expected: PE-bear opens and shows DOS/NT headers, the `.text`/`.data`/`.rdata` sections, and an Imports tab listing DLLs (for example `KERNEL32.dll`) and APIs. Nuance: a normal MSVC program shows many named imports; a *thin* or entirely resolved-at-runtime import table (only `LoadLibrary`/`GetProcAddress`) is a packing/obfuscation red flag. Non-standard section names (e.g., `UPX0`, `.themida`) or a raw size of 0 with a large virtual size also indicate packing.

4. `floss.exe` — extract strings, including stack and decoded strings.
```powershell
floss.exe --no-color .\exercise\sample.exe > .\exercise\floss_out.txt
Select-String -Path .\exercise\floss_out.txt -Pattern "203.0.113.10|http|CreateFile"
```
Why: FLOSS goes beyond a plain `strings` dump — it emulates the binary's own decoding routines to reveal *stack strings*, *tight strings*, and *decoded strings* that malware hides (https://github.com/mandiant/flare-floss). Redirecting to a file keeps the (often large) output for later grep/pivoting; `--no-color` strips ANSI codes so the saved text stays greppable (https://github.com/mandiant/flare-floss). Expected: FLOSS writes recovered strings to `floss_out.txt`; the filter surfaces the embedded example indicator `203.0.113.10` and API/URL-like strings. Nuance: for this benign sample the IP is a plain static string, so it appears in FLOSS's *static strings* section; in real malware the same value might only appear under FLOSS's *decoded strings* heading after emulation.

5. `capa.exe` — report capabilities and mapped ATT&CK techniques.
```powershell
capa.exe -v .\exercise\sample.exe
```
Why: capa translates low-level code patterns into human-readable capabilities and maps each to MITRE ATT&CK and MBC IDs, giving you candidate techniques without execution (https://github.com/mandiant/capa). `-v` (verbose) shows which capabilities matched and their namespaces; add `-vv` to see the exact rule logic and matched addresses (https://github.com/mandiant/capa). Expected: a capability table (for example "write file on disk") each mapped to ATT&CK IDs; for this benign sample no malicious C2/encryption capabilities are reported. Nuance: capa analyzes unpacked code, so if DIE/PE-bear indicate packing, unpack first or capa may under-report (capa prints a warning when it detects packing) (https://github.com/mandiant/capa).

## Hands-on exercise
Triage the sample `exercise\sample.exe` using all four tools and answer:
1. What is the file format and detected compiler (Detect-It-Easy)?
2. Is the sample packed? Justify using entropy.
3. Which suspicious-looking string (an IP address) does FLOSS recover that is *not* an obvious plaintext string?
4. Name two imported APIs shown in PE-bear.
5. List one capability capa reports.

**Sample declaration.** Type: benign 64-bit Windows PE executable. Safe origin: generated locally from inert C source below — it only prints text and contains a hard-coded *documentation-range* IP string (`203.0.113.10`, RFC 5737 TEST-NET-3) so FLOSS has something to find. It performs **no network activity and no egress**. Reproducible generator (run in a Developer Command Prompt / Cygwin with a C compiler on FLARE-VM):
```powershell
# Reproducibly build the benign sample into this module's exercise/ dir
$src = @'
#include <stdio.h>
#include <windows.h>
static const char *marker = "beacon-host 203.0.113.10";
int main(void){
    char buf[64];
    HANDLE h = CreateFileA("triage.log", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    printf("benign triage sample %s\n", marker);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    (void)buf;
    return 0;
}
'@
Set-Content -Path .\exercise\sample.c -Value $src -Encoding ASCII
cl.exe /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
The `cl.exe` flags used are standard MSVC options: `/nologo` suppresses the banner and `/Fe` names the output executable (https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file). `CreateFileA` and `CloseHandle` are Win32 APIs documented on Microsoft Learn (https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea, https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle). Because compiler versions differ, verify by the generator + FLOSS/capa findings rather than a fixed digest; record your local SHA256 from the command above.

## SOC analyst perspective
During incident response an analyst who receives a quarantined attachment runs this exact static triage flow *before* detonation to decide urgency.

- **Packing / high entropy → T1027 and T1027.002.** DIE flags high section entropy or a known packer signature (https://github.com/horsicq/Detect-It-Easy). These map to Obfuscated Files or Information (https://attack.mitre.org/techniques/T1027/) and Software Packing (https://attack.mitre.org/techniques/T1027/002/). A packed PE that later unpacks in memory is often visible on the endpoint as image loads without a corresponding on-disk section — pivot EDR/Sysmon on that. Hunt for Sysmon Event ID 7 (Image loaded) where the `Image` path is unusual or the `ImageLoaded` is from a non-standard directory (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **Network indicators → hunt in Security Onion.** Feed FLOSS-recovered IPs/URLs/domains (like `203.0.113.10`) into Kibana/OpenSearch and pivot to Zeek `conn.log` (`id.resp_h`) and `dns.log`/`http.log`, plus Suricata alert records, to see whether any host already contacted them (https://docs.securityonion.net/en/2.4/zeek.html, https://docs.securityonion.net/en/2.4/suricata.html). Example Zeek pivot: filter `destination.ip:203.0.113.10`. This ties to Application Layer Protocol: Web (https://attack.mitre.org/techniques/T1071/001/). For deeper hunting, also pivot on `dns.log` for queries to that domain and `http.log` for `host` headers.
- **capa capabilities → prioritize detections.** capa's ATT&CK mapping lets you pre-populate a case with candidate techniques so detections and Sigma rules can be prioritized — e.g., data-encryption capabilities suggest ransomware (T1486, https://attack.mitre.org/techniques/T1486/), and injection-primitive capabilities suggest Process Injection (T1055, https://attack.mitre.org/techniques/T1055/) (https://github.com/mandiant/capa). Additionally, if capa reports "modify registry" or "create service", those map to T1547.001 (Registry Run Keys) or T1543.003 (Windows Service). Hunt for corresponding Windows Event IDs: Event ID 4657 for registry modifications, Event ID 4697 for service creation.
- **Suspicious import combos → EDR watchlist.** PE-bear imports reveal which APIs to watch in endpoint telemetry; the classic injection trio `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` maps to T1055 (https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex; https://attack.mitre.org/techniques/T1055/). Also watch for `CreateFile` → `WriteFile` patterns indicating data staging (T1074).
- **Hunt for persistence (T1542.003 / T1502).** If capa shows "create scheduled task" or PE-bear reveals imports for `netapi32.dll` or `wtsapi32.dll`, pivot on Windows Event ID 4698 (Scheduled Task Creation). For service-based persistence (T1543.003), hunt Event ID 4697 (Service Installed).
- **PowerShell-based execution (T1059.001).** FLOSS-recovered strings often contain `powershell -enc` or `-Command` arguments. Hunt for Windows Event ID 4688 where `CommandLine` includes those strings. In Sysmon Event ID 1, pivot on `powershell.exe` with encoded arguments (https://attack.mitre.org/techniques/T1059/001/).
- **Indicator Removal: File Deletion (T1070.004).** If FLOSS reveals `del`, `Remove-Item`, or `wevtutil cl`, hunt for corresponding process creation events that delete files or clear logs (https://attack.mitre.org/techniques/T1070/004/).
- **Hide Artifacts: Hidden Files (T1564.001).** Strings like `attrib +h`, `Set-ItemProperty -Path ... -Name Attributes` indicate attempts to hide files. Pivot on Sysmon Event ID 11 (FileCreate) with `FileAttributes` containing hidden flag (https://attack.mitre.org/techniques/T1564/001/).

This static-only step keeps analysis reproducible and avoids tipping off adversaries with sandbox callbacks.

### Sub‑section: Threat Hunting & Detection Engineering (deepening)
Once static triage artifacts are extracted (e.g., embedded IPs, domains, or suspicious strings), pivot into **threat hunting** and **detection engineering** to validate and operationalize findings. Focus on **T1562.001 (Impair Defenses: Disable or Modify Tools)** and **T1036.005 (Masquerading: Match Legitimate Name or Location)**—two techniques frequently missed by static-only analysis.

- **Detection Logic (Concrete Fields & Pivots):**
  - **Windows Event Logs (Security.evtx):**
    - Hunt for **Event ID 4688** (Process Creation) where `NewProcessName` matches a triage-extracted binary name but `ParentProcessName` is atypical (e.g., `svchost.exe` spawning `powershell.exe` from `C:\Temp\`). Correlate with FLOSS-recovered strings like `powershell -enc` for encoded commands.
    - Filter for **Event ID 1102** (Audit Log Cleared) or **Event ID 104** (Log File Cleared) to detect **T1562.001**—correlate with static triage outputs (e.g., `wevtutil cl` strings in samples).
  - **Sysmon (Event ID 1):**
    - Pivot on `CommandLine` fields containing triage-extracted IPs/domains (e.g., `cmd.exe /c curl http://[extracted_IP]`). Use **T1036.005** logic to flag processes with mismatched `OriginalFileName` vs. `Image` paths (e.g., `lsass.exe` running from `C:\Users\Public\`). Sysmon can also log Event ID 7 (Image loaded) for DLL side‑loading attempts.
  - **Linux Audit Logs (`/var/log/audit/audit.log`):**
    - Hunt for **execve syscalls** (`type=EXECVE`) where `a0` (command) matches triage-extracted strings (e.g., `chmod +x /tmp/[extracted_binary]`). Correlate with **T1562.001** by checking for `auditd` service stops (`systemctl stop auditd`).
  - **Security Onion / Zeek:**
    - Hunt for **T1071.001** via Zeek `http.log` where `host` or `uri` contain triage‑extracted IPs/domains. Query: `event.dataset:zeek.http AND url:"*203.0.113.10*"`.
    - Hunt for **T1573** (Encrypted Channel) by pivoting on `ssl.log` for certificates with extracted domain names.
- **Hunt Pivots:**
  - Cross-reference triage outputs with **VirusTotal** (e.g., `behavior: "modifies auditd config"`) or **Unprotect Project** (e.g., `T1562.001` bypasses).
  - For **T1036.005**, query EDR telemetry for `process.name` mismatches (e.g., `svchost.exe` with `pe.original_file_name: "ransomware.exe"`). Also hunt for unsigned executables with legitimate names (e.g., `cmd.exe` in user‑writable paths).
- **Sources:**
  - [CISA: Hunting for T1562.001 (Disable Defenses)](https://www.cisa.gov)
  - [Mitre: T1562.001](https://attack.mitre.org/techniques/T1562/001/)
  - [Mitre: T1036.005](https://attack.mitre.org/techniques/T1036/005/)
  - [Sysmon documentation (Microsoft)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Attacker perspective
Attackers know static triage is the first defensive step, so they invest in defeating it.

- **Packing / crypting (T1027.002).** UPX or custom crypter stubs raise entropy and collapse the import table so only `LoadLibrary`/`GetProcAddress` remain (https://attack.mitre.org/techniques/T1027/002/). Artifacts left behind: near-8.0-bits/byte sections, non-standard section names (`UPX0`, `.themida`), and an `AddressOfEntryPoint` pointing outside `.text` — all visible to DIE and PE-bear (https://github.com/horsicq/Detect-It-Easy, https://github.com/hasherezade/pe-bear). Evasion: use custom crypter that mimics normal imports size but resolves at runtime.
- **String obfuscation (T1027 / recovered via T1140).** Stack-built strings and XOR/RC4-encoded C2 addresses hide IPs and URLs from a naive `strings` dump. FLOSS is purpose-built to defeat this by emulating the decoding routines, so decoded C2 like `203.0.113.10` surfaces anyway under its *decoded/stack strings* output (https://github.com/mandiant/flare-floss; https://attack.mitre.org/techniques/T1140/). Evasion: use multi‑layer encoding or dynamic API‑resolved strings that are reconstructed only at runtime.
- **Behavioral fingerprints survive obfuscation.** Even after strings are hidden, capa recognizes code patterns (crypto constants/loops, injection API sequences), leaving a capability fingerprint (https://github.com/mandiant/capa). To evade capa, actors dynamically resolve APIs by hash and move logic behind indirect calls — but that resolution routine itself becomes a detectable pattern. Some attackers pack with packers that confuse disassemblers, like polymorphic obfuscation that changes each generation.
- **Evasion trade-off.** Anti-analysis stubs, timing checks, and API hashing raise the cost of packing but produce their own tells (thin imports, high entropy, unusual TLS callbacks), which is why combining all four tools beats any single one.
- **Defense evasion (T1562.001).** Adversaries may disable tools like Windows Defender or auditd. Artifacts include modifications to registry keys (e.g., `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`). FLOSS may recover strings like `powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true`. In Linux, commands like `systemctl stop auditd` or `service iptables stop` appear in logs. Static triage of embedded scripts can reveal these.
- **Masquerading (T1036.005).** Attackers rename their executable to match a legitimate system binary (e.g., `svchost.exe`). Artifacts: the `OriginalFileName` in PE metadata may differ from the actual filename; PE‑bear or `Get-PEFileHeader` can reveal this. FLOSS may recover strings used for the fake name.
- **PowerShell abuse (T1059.001).** Attackers often embed PowerShell commands in stagers. FLOSS recovers these strings. To evade, adversaries encode commands with Base64 or use `-EncodedCommand`. Artifacts: long Base64 strings in the binary that decode to PowerShell scripts.
- **Indicator Removal (T1070.004).** Malware may delete itself after execution or clear event logs. FLOSS may reveal `del`, `wevtutil cl`, or `Clear-EventLog` strings. EDR telemetry showing file deletion events (Sysmon ID 23) or event log clear events (Event ID 1102) can be correlated.

### Sub‑section: Adversary Emulation & Red‑Team Perspective (deepening)
From an adversary's perspective, the static triage case can be exploited using techniques such as [T1204](https://attack.mitre.org/techniques/T1204) - "User Execution" and [T1218](https://attack.mitre.org/techniques/T1218) - "Signed Binary Proxy Execution". An attacker may use social engineering tactics to trick a user into executing a malicious file, which can then lead to the exploitation of vulnerabilities in the system. The adversary may also use signed binary proxy execution (e.g., `rundll32.exe`, `regsvr32.exe`, `mshta.exe`) to bypass security controls and execute malicious code. The artifacts left behind by these techniques can include suspicious executable files, modified system configuration files, and unusual network activity. To evade detection, the adversary may use code obfuscation, anti-debugging techniques, and fileless malware. Understanding these TTPs is crucial for effective incident response and threat hunting. For example, a red team may deploy a C2 payload as a DLL and use `rundll32.exe` to execute it, leaving a `DllRegisterServer` export visible in PE‑bear. Static triage of the DLL would reveal the export and any embedded indicators. For more information on adversary emulation and red‑team operations, visit the [CISA](https://www.cisa.gov/) and [NSA Cybersecurity](https://www.nsa.gov/what-we-do/cybersecurity/) websites.

## Answer key
Run these to produce the graded findings:
```powershell
& "C:\Tools\die\diec.exe" .\exercise\sample.exe          # Q1/Q2: format + compiler + entropy
floss.exe --no-color .\exercise\sample.exe | Select-String "203.0.113.10"   # Q3
capa.exe .\exercise\sample.exe                            # Q5
Get-FileHash .\exercise\sample.exe -Algorithm SHA256     # record digest
```
Expected findings:
1. **Format:** PE64 (PE32+); **compiler:** Microsoft Visual C/C++ (linker version reported by DIE) (https://github.com/horsicq/Detect-It-Easy).
2. **Not packed** — entropy of `.text` is well below ~7.0 and imports are cleanly named (entropy interpretation per DIE; import-table reasoning per PE-bear: https://github.com/hasherezade/pe-bear).
3. FLOSS recovers `203.0.113.10` (part of the `beacon-host 203.0.113.10` marker), demonstrating static string extraction (https://github.com/mandiant/flare-floss).
4. Imports visible in PE-bear include `CreateFileA`, `CloseHandle` (from `KERNEL32.dll`); `printf`-related CRT imports also appear (Win32 API refs: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea, https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle).
5. capa reports capabilities such as **"write file on disk"** (maps to file-manipulation behavior) (https://github.com/mandiant/capa, https://github.com/mandiant/capa-rules).
Sample SHA256: compiler-dependent — record the digest emitted by `Get-FileHash .\exercise\sample.exe` after building with the generator command above.

## MITRE ATT&CK & DFIR phase
- **T1027 / T1027.002** — Obfuscated Files or Information / Software Packing (detected via DIE entropy + PE-bear imports). https://attack.mitre.org/techniques/T1027/ , https://attack.mitre.org/techniques/T1027/002/
- **T1140** — Deobfuscate/Decode Files or Information (FLOSS recovering decoded strings). https://attack.mitre.org/techniques/T1140/
- **T1071.001** — Application Layer Protocol: Web (candidate from embedded IP/URL indicators). https://attack.mitre.org/techniques/T1071/001/
- **T1005 / T1074** — Data from Local System / Data Staged (file‑write capability from capa). https://attack.mitre.org/techniques/T1005/ , https://attack.mitre.org/techniques/T1074/
- **T1055** — Process Injection (candidate when capa/PE-bear reveal injection API primitives). https://attack.mitre.org/techniques/T1055/
- **T1486** — Data Encrypted for Impact (candidate when capa reports encryption capabilities). https://attack.mitre.org/techniques/T1486/
- **T1547.001** — Boot or Logon Autostart: Registry Run Keys (if capa or imports suggest registry persistence). https://attack.mitre.org/techniques/T1547/001/
- **T1543.003** — Windows Service (if capa shows "create service"). https://attack.mitre.org/techniques/T1543/003/
- **T1562.001** — Impair Defenses: Disable or Modify Tools (evidenced by strings in FLOSS or capa). https://attack.mitre.org/techniques/T1562/001/
- **T1036.005** — Masquerading: Match Legitimate Name or Location (revealed by PE-bear OriginalFileName mismatch). https://attack.mitre.org/techniques/T1036/005/
- **T1204** — User Execution (social engineering vector). https://attack.mitre.org/techniques/T1204/
- **T1218** — Signed Binary Proxy Execution (LOLBins like rundll32). https://attack.mitre.org/techniques/T1218/
- **T1059.001** — Command and Scripting Interpreter: PowerShell (recovered strings indicating PowerShell usage). https://attack.mitre.org/techniques/T1059/001/
- **T1070.004** — Indicator Removal: File Deletion (strings like del/wevtutil). https://attack.mitre.org/techniques/T1070/004/
- **T1564.001** — Hide Artifacts: Hidden Files and Directories (strings like attrib +h). https://attack.mitre.org/techniques/T1564/001/
- **DFIR phase:** Identification & Examination (initial static triage before dynamic analysis).


### Essential Commands & Features

When triaging suspicious binaries, leveraging **DIE (Detect It Easy)** and **FLOSS** with precise flags can uncover hidden behaviors tied to adversary techniques like **T1027.005 (Indicator Removal from Tools)** or **T1105 (Ingress Tool Transfer)**. Below are the most impactful commands and features not yet demonstrated:

#### **DIE: Critical Console Flags**
- **`-json`**: Export analysis in machine-readable JSON for automated pipelines. Use when integrating DIE with SIEMs or custom scripts.
  ```bash
  diec -json suspicious.exe > analysis.json
  ```
- **`-d`**: Enable deep inspection (e.g., entropy scans, packer detection). Critical for spotting **T1027.005** obfuscation.
  ```bash
  diec -d suspicious.exe
  ```
- **`-a`**: Force analysis of all sections, including non-standard regions. Helps detect **T1105** payloads hidden in overlay data.
  ```bash
  diec -a suspicious.exe
  ```
- **Entropy Visualization**: DIE’s built-in entropy graph (GUI) highlights high-entropy regions, often indicative of encrypted/obfuscated payloads (e.g., **T1027.002**).

#### **FLOSS: Advanced String Extraction**
- **`--no-decoded-strings`**: Skip decoded stack strings to focus on raw embedded strings. Useful for identifying hardcoded C2 IPs (e.g., **T1071.001**).
  ```bash
  floss --no-decoded-strings suspicious.exe
  ```
- **`--min-length <N>`**: Filter strings by length to reduce noise. Set `--min-length 8` to exclude trivial strings while preserving meaningful artifacts.
  ```bash
  floss --min-length 12 suspicious.exe
  ```

**Sources**:
- [DIE Official Documentation (GitHub Wiki)](https://github.com/horsicq/Detect-It-Easy/wiki/Command-line-interface)
- [FireEye FLOSS User Guide (PDF)](https://www.fireeye.com/content/dam/fireeye-www/services/freeware/ug-floss.pdf)

### Threat Hunting & Detection Engineering

Once the static triage artifacts are collected, pivot to **threat hunting** and **detection engineering** to uncover adversary tradecraft. Focus on **Windows Event Logs** (Security, Sysmon) and **network telemetry** (Zeek, Suricata) to detect two high-confidence MITRE ATT&CK techniques:

1. **T1047: Windows Management Instrumentation (WMI)**
   - *Detection Logic*: Hunt for WMI process creation (`Event ID 4688` or `Sysmon Event ID 1`) where `ParentImage` is `wmiprvse.exe` and `CommandLine` contains `wmic`, `Get-WmiObject`, or `Invoke-WmiMethod`. Pivot to `Microsoft-Windows-WMI-Activity/Operational` (`Event ID 5861`) for WMI subscription persistence.
   - *Network Pivot*: Zeek’s `dce_rpc` logs (`operation` field = `IWbemServices_ExecMethod`) or Suricata’s `DCE/RPC` protocol alerts (e.g., `ET POLICY WMI Activity`).

2. **T1574.002: Hijack Execution Flow: DLL Side-Loading**
   - *Detection Logic*: Correlate `Sysmon Event ID 7` (Image Load) with `Event ID 1` (Process Creation) where a legitimate binary (e.g., `msiexec.exe`) loads a DLL from a non-standard path (e.g., `C:\Temp\`). Cross-reference with `Event ID 4663` (File System audit) for suspicious write operations to `System32` or `Program Files`.
   - *Hunting Query*: Use Velociraptor’s `Windows.EventLogs.Evtx` artifact to filter for `TargetObject` containing `*.dll` and `SubjectLogonId` from untrusted sessions.

**Authoritative Sources**:
- [CrowdStrike: Detecting WMI Abuse (T1047)](https://www.crowdstrike.com/blog/wmi-persistence/)
- [Elastic Security Labs: Detecting DLL Side-Loading (T1574.002)](https://www.elastic.co/security-labs/detecting-dll-side-loading-with-elastic-security)


### Essential Commands & Features

When automating static triage with **DIE (Detect It Easy) console (`diec.exe`)**, the following commands and flags are critical for scripting and deeper analysis but are often overlooked:

- **`-json`**: Export results in JSON format for parsing in automation pipelines. Use when integrating DIE output with SIEMs or custom analysis tools.
  ```bash
  diec.exe -json suspicious.exe > output.json
  ```
  *Relevant to*: [T1027.003 Obfuscated Files or Information: Steganography](https://attack.mitre.org/techniques/T1027/003/) (detecting hidden payloads in files).

- **`-d`**: Dump detailed file metadata, including entropy values and packer signatures. Ideal for identifying packed or encrypted malware.
  ```bash
  diec.exe -d malware.dll
  ```
  *Relevant to*: [T1553.002 Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/) (spotting tampered or unsigned binaries).

- **`-f <format>`**: Force analysis of a specific file format (e.g., `-f PE`, `-f ELF`). Useful when DIE misclassifies a file.
  ```bash
  diec.exe -f PE obfuscated.bin
  ```

- **Entropy Histogram Flags**: Generate entropy histograms (`-entropy`) to visualize packed/encrypted regions. Combine with `-csv` for scripting:
  ```bash
  diec.exe -entropy -csv sample.exe > entropy.csv
  ```

For further reference:
- [DIE GitHub Wiki: Command-Line Options](https://github.com/horsicq/DIE-engine/wiki/Command-line-options)
- [SANS FOR610: Reverse-Engineering Malware (DIE Usage)](https://www.sans.org/blog/for610-reverse-engineering-malware/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_case_anomalies.yar, author: Florian Roth (Nextron Systems)):

```yara
rule PowerShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated PowerShell hacktools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
      date = "2017-08-11"
      modified = "2022-06-12"
      score = 70
      id = "41c97d15-c167-5bdd-a8b4-871d14f66fe1"
   strings:
      // first detect 'powershell' keyword case insensitive
      $s1 = "powershell" nocase ascii wide
      // define the normal cases
      $sn1 = "powershell" ascii wide
      $sn2 = "Powershell" ascii wide
      $sn3 = "PowerShell" ascii wide
      $sn4 = "POWERSHELL" ascii wide
      $sn5 = "powerShell" ascii wide
      $sn6 = "PowerShelL" ascii wide /* PSGet.Resource.psd1 - part of PowerShellGet */
      $sn7 = "PowershelL" ascii wide /* SCVMM.dll - part of Citrix */

      // PowerShell with \x19\x00\x00
      $a1 = "wershell -e " nocase wide ascii
      // expected casing
      $an1 = "wershell -e " wide ascii
      $an2 = "werShell -e " wide ascii

      // adding a keyword with a sufficent length and relevancy
      $k1 = "-noprofile" fullword nocase ascii wide
      // define normal cases
      $kn1 = "-noprofile" ascii wide
      $kn2 = "-NoProfile" ascii wide
      $kn3 = "-noProfile" ascii wide
      $kn4 = "-NOPROFILE" ascii wide
      $kn5 = "-Noprofile" ascii wide

      $fp1 = "Microsoft Code Signing" ascii fullword
      $fp2 = "Microsoft Corporation" ascii
      $fp3 = "Microsoft.Azure.Commands.ContainerInstance" wide
      $fp4 = "# Localized PSGet.Resource.psd1" wide
   condition:
      filesize < 800KB and (
         // find all 'powershell' occurrences and ignore the expected cases
         ( #s1 > #sn1 + #sn2 + #sn3 + #sn4 + #sn5 + #sn6 + #sn7 ) or
         ( #a1 > #an1 + #an2 ) or
         // find all '-noprofile' occurrences and ignore the expected cases
         ( #k1 > #kn1 + #kn2 + #kn3 + #kn4 + #kn5 )
      ) and not 1 of ($fp*)
}
```

**Real-world context (MITRE T1027 -- Obfuscated Files or Information):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1027/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

When automating static triage with **DIE (Detect It Easy) console (`diec.exe`)**, the following undemonstrated commands and flags are critical for scripting and deeper analysis. These enable structured output, recursive scanning, and entropy visualization—key for detecting obfuscation and packed binaries (e.g., **T1027.001: Obfuscated Files or Information** and **T1553.004: Install Root Certificate**).

1. **`-json`**: Export results in JSON for parsing in SIEMs or custom tools.
   ```bash
   diec.exe -json suspicious.exe > output.json
   ```
   *Use when*: Integrating DIE with automated pipelines (e.g., Splunk, ELK).

2. **`-d`**: Recursively scan directories for embedded artifacts.
   ```bash
   diec.exe -d C:\Temp\malware_samples\
   ```
   *Use when*: Analyzing nested payloads (e.g., **T1105: Ingress Tool Transfer**).

3. **`-f`**: Force scan files regardless of extension (e.g., `.dat`, `.tmp`).
   ```bash
   diec.exe -f unknown_file.dat
   ```
   *Use when*: Investigating files with misleading extensions (e.g., **T1036.003: Rename System Utilities**).

4. **Entropy Graph Flags**: Visualize entropy to identify packed/encrypted sections.
   ```bash
   diec.exe --entropy-graph suspicious.dll
   ```
   *Use when*: Detecting compression/encryption (e.g., **T1027.004: Compile After Delivery**).

**Sources**:
- [DIE GitHub: Command-Line Options](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/CLI.md)
- [SANS FOR578: Entropy Analysis in Malware](https://www.sans.org/blog/entropy-analysis-with-die/)

### Adversary Emulation & Red-Team Perspective

From an adversary’s standpoint, static triage of a malware sample is a critical step in evasion. A red teamer emulating an advanced threat will first analyze the binary’s import tables, embedded strings, and cryptographic constants to identify which execution hooks it triggers—using **T1053.005 Scheduled Task** for persistent re‑infection, for example. The adversary crafts a task XML that launches the payload at logon or system startup, often naming it after a legitimate service (e.g., “MicrosoftEdgeUpdateTask”) to blend in. Artifacts include the scheduled task XML stored in `%WINDIR%\Tasks` and entries in the Task Scheduler’s registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`.

Another common persistence vector is **T1546.015 Component Object Model Hijacking**, where the attacker overwrites a CLSID’s `InprocServer32` registry key to point to their own DLL. During static triage, the red team looks for references to `CLSID` or `ProgID` and later modifies keys like `HKCU\Software\Classes\CLSID\{...}\InprocServer32`. This leaves registry modifications as the primary artifact. Evasion considerations include using benign‑looking GUIDs, encrypting the hijacked DLL, and leveraging well‑known CLSIDs (e.g., for Microsoft Office components) to avoid triggering behavioral analytics.

Sources:  
- Varonis: *“Scheduled Tasks for Persistence”* – https://www.varonis.com/blog/scheduled-tasks-persistence  
- Cybereason: *“COM Hijacking: A Sophisticated Persistence Technique”* – https://www.cybereason.com/blog/com-hijacking-persistence-technique

## Sources
- Detect-It-Easy: official repo and console flags – https://github.com/horsicq/Detect-It-Easy, https://github.com/horsicq/DIE-engine
- capa: official repo, rules, and ATT&CK mapping – https://github.com/mandiant/capa, https://github.com/mandiant/capa-rules
- FLOSS (FLARE Obfuscated String Solver): official repo – https://github.com/mandiant/flare-floss
- FLARE-VM: official repo – https://github.com/mandiant/flare-vm
- PE-bear: official repo – https://github.com/hasherezade/pe-bear
- Microsoft Learn: Get-FileHash – https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- Microsoft Learn: cl.exe /Fe flag – https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file
- Microsoft Learn: CreateFileA API – https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea
- Microsoft Learn: CloseHandle API – https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle
- Microsoft Learn: VirtualAllocEx API – https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
- Microsoft Learn: Sysmon documentation – https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- MITRE ATT&CK: T1027 – https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK: T1027.002 – https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK: T1140 – https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK: T1071.001 – https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK: T1005 – https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK: T1074 – https://attack.mitre.org/techniques/T1074/
- MITRE ATT&CK: T1055 – https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK: T1486 – https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK: T1547.001 – https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK: T1543.003 – https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK: T1562.001 – https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK: T1036.005 – https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK: T1204 – https://attack.mitre.org/techniques/T1204/
- MITRE ATT&CK: T1218 – https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK: T1059.001 – https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK: T1070.004 – https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK: T1564.001 – https://attack.mitre.org/techniques/T1564/001/
- Security Onion documentation: Zeek – https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion documentation: Suricata – https://docs.securityonion.net/en/2.4/suricata.html
- CISA (Cybersecurity and Infrastructure Security Agency) – https://www.cisa.gov/
- SANS FOR610 Reverse-Engineering Malware – https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- RFC 5737 (documentation IP ranges, TEST-NET-3) – https://datatracker.ietf.org/doc/html/rfc5737

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- shares capa
- [PE static analysis deep-dive](../30-pe-static-deep/README.md) -- shares detect-it-easy (die)
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- shares floss
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- shares capa

<!-- cyberlab-enriched: v3 -->
- https://github.com/horsicq/Detect-It-Easy/wiki/Command-line-interface
- https://www.fireeye.com/content/dam/fireeye-www/services/freeware/ug-floss.pdf
- https://www.crowdstrike.com/blog/wmi-persistence/
- https://www.elastic.co/security-labs/detecting-dll-side-loading-with-elastic-security

<!-- cyberlab-enriched: v4 -->
- https://attack.mitre.org/techniques/T1027/003/
- https://attack.mitre.org/techniques/T1553/002/
- https://github.com/horsicq/DIE-engine/wiki/Command-line-options
- https://www.sans.org/blog/for610-reverse-engineering-malware/
- https://attack.mitre.org/techniques/T1114/
- https://attack.mitre.org/

<!-- cyberlab-enriched: v5 -->
- https://github.com/horsicq/Detect-It-Easy/blob/master/docs/CLI.md
- https://www.sans.org/blog/entropy-analysis-with-die/
- https://www.varonis.com/blog/scheduled-tasks-persistence
- https://www.cybereason.com/blog/com-hijacking-persistence-technique

<!-- cyberlab-enriched: v6 -->
