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

- **Packing / high entropy → T1027 and T1027.002.** DIE flags high section entropy or a known packer signature (https://github.com/horsicq/Detect-It-Easy). These map to Obfuscated Files or Information (https://attack.mitre.org/techniques/T1027/) and Software Packing (https://attack.mitre.org/techniques/T1027/002/). A packed PE that later unpacks in memory is often visible on the endpoint as image loads without a corresponding on-disk section — pivot EDR/Sysmon on that.
- **Network indicators → hunt in Security Onion.** Feed FLOSS-recovered IPs/URLs/domains (like `203.0.113.10`) into Kibana/OpenSearch and pivot to Zeek `conn.log` (`id.resp_h`) and `dns.log`/`http.log`, plus Suricata alert records, to see whether any host already contacted them (https://docs.securityonion.net/en/2.4/zeek.html, https://docs.securityonion.net/en/2.4/suricata.html). Example Zeek pivot: filter `event.dataset:conn AND destination.ip:203.0.113.10`. This ties to Application Layer Protocol: Web (https://attack.mitre.org/techniques/T1071/001/).
- **capa capabilities → prioritize detections.** capa's ATT&CK mapping lets you pre-populate a case with candidate techniques so detections and Sigma rules can be prioritized — e.g., data-encryption capabilities suggest ransomware (T1486, https://attack.mitre.org/techniques/T1486/), and injection-primitive capabilities suggest Process Injection (T1055, https://attack.mitre.org/techniques/T1055/) (https://github.com/mandiant/capa).
- **Suspicious import combos → EDR watchlist.** PE-bear imports reveal which APIs to watch in endpoint telemetry; the classic injection trio `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` maps to T1055 (https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex; https://attack.mitre.org/techniques/T1055/).

This static-only step keeps analysis reproducible and avoids tipping off adversaries with sandbox callbacks.

## Attacker perspective
Attackers know static triage is the first defensive step, so they invest in defeating it.

- **Packing / crypting (T1027.002).** UPX or custom crypter stubs raise entropy and collapse the import table so only `LoadLibrary`/`GetProcAddress` remain (https://attack.mitre.org/techniques/T1027/002/). Artifacts left behind: near-8.0-bits/byte sections, non-standard section names (`UPX0`, `.themida`), and an `AddressOfEntryPoint` pointing outside `.text` — all visible to DIE and PE-bear (https://github.com/horsicq/Detect-It-Easy, https://github.com/hasherezade/pe-bear).
- **String obfuscation (T1027 / recovered via T1140).** Stack-built strings and XOR/RC4-encoded C2 addresses hide IPs and URLs from a naive `strings` dump. FLOSS is purpose-built to defeat this by emulating the decoding routines, so decoded C2 like `203.0.113.10` surfaces anyway under its *decoded/stack strings* output (https://github.com/mandiant/flare-floss; https://attack.mitre.org/techniques/T1140/).
- **Behavioral fingerprints survive obfuscation.** Even after strings are hidden, capa recognizes code patterns (crypto constants/loops, injection API sequences), leaving a capability fingerprint (https://github.com/mandiant/capa). To evade capa, actors dynamically resolve APIs by hash and move logic behind indirect calls — but that resolution routine itself becomes a detectable pattern.
- **Evasion trade-off.** Anti-analysis stubs, timing checks, and API hashing raise the cost of packing but produce their own tells (thin imports, high entropy, unusual TLS callbacks), which is why combining all four tools beats any single one.

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
- **T1005 / T1074** — Data from Local System / Data Staged (file-write capability from capa). https://attack.mitre.org/techniques/T1005/ , https://attack.mitre.org/techniques/T1074/
- **T1055** — Process Injection (candidate when capa/PE-bear reveal injection API primitives). https://attack.mitre.org/techniques/T1055/
- **T1486** — Data Encrypted for Impact (candidate when capa reports encryption capabilities). https://attack.mitre.org/techniques/T1486/
- **DFIR phase:** Identification & Examination (initial static triage before dynamic analysis).


### Threat Hunting & Detection Engineering

Once static triage artifacts are extracted (e.g., embedded IPs, domains, or suspicious strings), pivot into **threat hunting** and **detection engineering** to validate and operationalize findings. Focus on **T1562.001 (Impair Defenses: Disable or Modify Tools)** and **T1036.005 (Masquerading: Match Legitimate Name or Location)**—two techniques frequently missed by static-only analysis.

**Detection Logic (Concrete Fields & Pivots):**
- **Windows Event Logs (Security.evtx):**
  - Hunt for **Event ID 4688** (Process Creation) where `NewProcessName` matches a triage-extracted binary name but `ParentProcessName` is atypical (e.g., `svchost.exe` spawning `powershell.exe` from `C:\Temp\`).
  - Filter for **Event ID 1102** (Audit Log Cleared) or **Event ID 104** (Log File Cleared) to detect **T1562.001**—correlate with static triage outputs (e.g., `wevtutil cl` strings in samples).

- **Sysmon (Event ID 1):**
  - Pivot on `CommandLine` fields containing triage-extracted IPs/domains (e.g., `cmd.exe /c curl http://[extracted_IP]`). Use **T1036.005** logic to flag processes with mismatched `OriginalFileName` vs. `Image` paths (e.g., `lsass.exe` running from `C:\Users\Public\`).

- **Linux Audit Logs (`/var/log/audit/audit.log`):**
  - Hunt for **execve syscalls** (`type=EXECVE`) where `a0` (command) matches triage-extracted strings (e.g., `chmod +x /tmp/[extracted_binary]`). Correlate with **T1562.001** by checking for `auditd` service stops (`systemctl stop auditd`).

**Hunt Pivots:**
- Cross-reference triage outputs with **VirusTotal** (e.g., `behavior: "modifies auditd config"`) or **Unprotect Project** (e.g., `T1562.001` bypasses).
- For **T1036.005**, query EDR telemetry for `process.name` mismatches (e.g., `explorer.exe` with `pe.original_file_name: "ransomware.exe"`).

**Sources:**
- [CISA: Hunting for T1562.001 (Disable Defenses)](https://www.cisa

### Adversary Emulation & Red-Team Perspective
From an adversary's perspective, the static triage case can be exploited using techniques such as [T1204](https://attack.mitre.org/techniques/T1204) - "User Execution" and [T1218](https://attack.mitre.org/techniques/T1218) - "Signed Binary Proxy Execution". An attacker may use social engineering tactics to trick a user into executing a malicious file, which can then lead to the exploitation of vulnerabilities in the system. The adversary may also use signed binary proxy execution to bypass security controls and execute malicious code. The artifacts left behind by these techniques can include suspicious executable files, modified system configuration files, and unusual network activity. To evade detection, the adversary may use code obfuscation, anti-debugging techniques, and fileless malware. Understanding these tactics, techniques, and procedures (TTPs) is crucial for effective incident response and threat hunting. For more information on adversary emulation and red-team operations, visit the [Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [NSA Cybersecurity](https://www.nsa.gov/what-we-do/cybersecurity/) websites.

## Sources
Claim → source mapping (all URLs are official tool repos, Microsoft Learn, MITRE ATT&CK, SANS, or RFCs):

- capa capabilities, `-v`/`-vv`/`--version`, ATT&CK/MBC mapping, packing warning — Mandiant/FLARE capa: https://github.com/mandiant/capa
- capa community rules (capability namespaces) — capa-rules: https://github.com/mandiant/capa-rules
- FLOSS static/stack/tight/decoded strings, `--no-color`, `--version` — Mandiant/FLARE FLOSS: https://github.com/mandiant/flare-floss
- FLARE-VM install/tooling context — Mandiant FLARE-VM: https://github.com/mandiant/flare-vm
- DIE file/compiler/packer detection and entropy — Detect-It-Easy: https://github.com/horsicq/Detect-It-Easy
- DIE console (`diec`) options incl. `-j` JSON output — DIE engine: https://github.com/horsicq/DIE-engine
- PE-bear headers/sections/imports (GUI, no CLI) — PE-bear: https://github.com/hasherezade/pe-bear
- `Get-FileHash` (SHA256 default/behavior) — Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- `cl.exe` `/nologo` and `/Fe` flags — Microsoft Learn: https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file
- `CreateFileA` API — Microsoft Learn: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea
- `CloseHandle` API — Microsoft Learn: https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle
- `VirtualAllocEx` (injection primitive) — Microsoft Learn: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
- MITRE ATT&CK — Obfuscated Files or Information (T1027): https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — Software Packing (T1027.002): https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK — Deobfuscate/Decode (T1140): https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK — Application Layer Protocol: Web (T1071.001): https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK — Data from Local System (T1005): https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK — Data Staged (T1074): https://attack.mitre.org/techniques/T1074/
- MITRE ATT&CK — Process Injection (T1055): https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK — Data Encrypted for Impact (T1486): https://attack.mitre.org/techniques/T1486/
- Security Onion — Zeek: https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion — Suricata: https://docs.securityonion.net/en/2.4/suricata.html
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- RFC 5737 (documentation address ranges, TEST-NET-3): https://datatracker.ietf.org/doc/html/rfc5737

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- shares capa for capability-dri

<!-- cyberlab-enriched: v1 -->
- http://[extracted_IP]`
- https://www.cisa
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1218
- https://www.cisa.gov/
- https://www.nsa.gov/what-we-do/cybersecurity/

<!-- cyberlab-enriched: v2 -->
