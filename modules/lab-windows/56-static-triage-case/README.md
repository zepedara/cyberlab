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
Expected output: capa prints its version (for example `capa 7.x.x`), FLOSS prints its version banner, and `Get-ChildItem` lists `diec.exe` and `PE-bear.exe` with a nonzero size, confirming the tools are installed.

## Guided walkthrough
1. Build the benign sample used throughout (see Hands-on exercise) so a real PE exists to triage.
```powershell
# Confirm the sample is present before triage
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
Expected: prints the SHA256 digest of `sample.exe`, proving the file exists and is intact.

2. `diec.exe` — Detect-It-Easy identifies file type, compiler, and entropy (packing hint).
```powershell
& "C:\Tools\die\diec.exe" -j .\exercise\sample.exe
```
Expected: JSON output naming the format (`PE64`/`PE32`), the detected compiler/linker (for example `Microsoft Visual C/C++`), and low entropy — indicating the sample is **not packed**.

3. PE-bear — inspect structure. Launch the GUI, then confirm the CLI/headers programmatically.
```powershell
# Open the sample for header/section/import inspection
& "C:\Tools\PE-bear\PE-bear.exe" .\exercise\sample.exe
```
Expected: PE-bear opens and shows DOS/NT headers, the `.text`/`.data`/`.rdata` sections, and an Imports tab listing DLLs (for example `KERNEL32.dll`) and APIs.

4. `floss.exe` — extract strings, including stack and decoded strings.
```powershell
floss.exe --no-color .\exercise\sample.exe > .\exercise\floss_out.txt
Select-String -Path .\exercise\floss_out.txt -Pattern "203.0.113.10|http|CreateFile"
```
Expected: FLOSS writes recovered strings to `floss_out.txt`; the filter surfaces the embedded example indicator `203.0.113.10` and API/URL-like strings.

5. `capa.exe` — report capabilities and mapped ATT&CK techniques.
```powershell
capa.exe -v .\exercise\sample.exe
```
Expected: a capability table (for example "contain a resource," "read/write file on disk") each mapped to ATT&CK IDs; for this benign sample no malicious C2/encryption capabilities are reported.

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
Because compiler versions differ, verify by the generator + FLOSS/capa findings rather than a fixed digest; record your local SHA256 from the command above.

## SOC analyst perspective
During incident response an analyst who receives a quarantined attachment runs this exact static triage flow *before* detonation to decide urgency. Detect-It-Easy quickly flags packers (high entropy) — a common evasion tied to ATT&CK T1027/T1027.002. FLOSS-recovered IPs, URLs, and mutex names become pivot points: you feed the `203.0.113.10`-style indicators into Security Onion (Kibana/OpenSearch) to hunt Zeek `conn.log` and Suricata alerts for matching destinations, and check whether any endpoint already contacted them. capa's capability-to-ATT&CK mapping lets you pre-populate a case with candidate techniques (T1071, T1486, T1055) so detections and Sigma rules can be prioritized. PE-bear imports reveal which APIs to watch in EDR telemetry. This static-only step keeps analysis reproducible and avoids tipping off adversaries with sandbox callbacks.

## Attacker perspective
Attackers know static triage is the first defensive step, so they invest in defeating it. They pack or crypt payloads (UPX, custom stubs) to raise entropy and hide imports — which is exactly what Detect-It-Easy and PE-bear expose when the import table looks abnormally thin or a section is near-maximum entropy. They obfuscate strings (stack strings, XOR-encoded C2 addresses) to hide IPs and URLs from a naive `strings` dump — the very technique FLOSS is built to defeat by emulating decoding routines, so decoded C2 like `203.0.113.10` surfaces anyway. Even after obfuscation, capa still recognizes behavioral patterns from the code (crypto loops, process injection sequences), leaving a capability fingerprint. Artifacts left for defenders include telltale packer signatures, mismatched section names, suspicious import combos (`VirtualAlloc`+`WriteProcessMemory`+`CreateRemoteThread`), and recoverable indicators embedded in the binary.

## Answer key
Run these to produce the graded findings:
```powershell
& "C:\Tools\die\diec.exe" .\exercise\sample.exe          # Q1/Q2: format + compiler + entropy
floss.exe --no-color .\exercise\sample.exe | Select-String "203.0.113.10"   # Q3
capa.exe .\exercise\sample.exe                            # Q5
Get-FileHash .\exercise\sample.exe -Algorithm SHA256     # record digest
```
Expected findings:
1. **Format:** PE64 (PE32+); **compiler:** Microsoft Visual C/C++ (linker version reported by DIE).
2. **Not packed** — entropy of `.text` is well below ~7.0 and imports are cleanly named.
3. FLOSS recovers `203.0.113.10` (part of the `beacon-host 203.0.113.10` marker), demonstrating static string extraction.
4. Imports visible in PE-bear include `CreateFileA`, `CloseHandle` (from `KERNEL32.dll`); `printf`-related CRT imports also appear.
5. capa reports capabilities such as **"write file on disk"** (maps to file-manipulation behavior).
Sample SHA256: compiler-dependent — record the digest emitted by `Get-FileHash .\exercise\sample.exe` after building with the generator command above.

## MITRE ATT&CK & DFIR phase
- **T1027 / T1027.002** — Obfuscated Files or Information / Software Packing (detected via DIE entropy + PE-bear imports).
- **T1140** — Deobfuscate/Decode Files or Information (FLOSS recovering decoded strings).
- **T1071.001** — Application Layer Protocol: Web (candidate from embedded IP/URL indicators).
- **T1005 / T1074** — Data from Local System / Data Staged (file-write capability from capa).
- **DFIR phase:** Identification & Examination (initial static triage before dynamic analysis).

## Sources
- Mandiant / FLARE — capa: https://github.com/mandiant/capa
- Mandiant / FLARE — FLOSS: https://github.com/mandiant/flare-floss
- Mandiant — FLARE-VM: https://github.com/mandiant/flare-vm
- Detect-It-Easy (DIE): https://github.com/horsicq/Detect-It-Easy
- PE-bear: https://github.com/hasherezade/pe-bear
- MITRE ATT&CK — Obfuscated Files or Information (T1027): https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — Deobfuscate/Decode (T1140): https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- RFC 5737 (documentation address ranges): https://datatracker.ietf.org/doc/html/rfc5737