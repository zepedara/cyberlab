# 27 * Ghidra decompiler & scripting deep-dive -- LAB-WINDOWS

## Overview (plain language)
Ghidra is a free software reverse-engineering suite built by the NSA that takes a compiled program (like an .exe) and turns its raw machine code back into something humans can read — both assembly and a C-like "decompiled" view. It also has a scripting engine so you can automate boring, repetitive tasks like renaming functions or extracting strings. capa is a companion tool that reads a program and tells you, in plain English, what capabilities it has (for example "reads clipboard data" or "communicates over HTTP") by matching well-known code patterns. Together they let an analyst quickly understand what an unknown binary does without ever running it, which is safer and faster for triaging suspicious files.

> Sourcing note: Ghidra is described as a "software reverse engineering (SRE) framework" with a decompiler and a scripting API by its official site and repository ([ghidra-sre.org](https://ghidra-sre.org/), [github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)). capa "detects capabilities in executable files" by matching a rule set, per Mandiant's project docs ([github.com/mandiant/capa](https://github.com/mandiant/capa)).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Ghidra | FLARE-VM (`choco install ghidra`) | Disassembler/decompiler with a Python/Java scripting engine (headless + GUI) |
| capa | FLARE-VM (`choco install capa`) | Detects program capabilities via a rule set; integrates with Ghidra via the capa plugin |

Both tools are packaged by the FLARE-VM installer profile ([github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)). Ghidra ships both a GUI (`ghidraRun.bat`) and a headless launcher (`analyzeHeadless.bat`), documented in the official Installation/Getting-Started guide bundled under `docs/` and on the repo ([Ghidra InstallationGuide](https://ghidra-sre.org/InstallationGuide.html), [Ghidra repo `support/analyzeHeadless`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/Windows/support/analyzeHeadless.bat)). capa exposes a Ghidra integration/plugin (`capa_explorer`) documented in the capa repo ([capa Ghidra integration](https://github.com/mandiant/capa/tree/master/capa/ghidra)).

## Learning objectives
- Load a benign PE into Ghidra and auto-analyze it, then read the decompiled C output for the entry function.
- Run a Ghidra headless (analyzeHeadless) script to extract all function names and strings without opening the GUI.
- Run capa against the same sample and map its reported capabilities to MITRE ATT&CK technique IDs.
- Correlate capa findings with the Ghidra decompilation to confirm at least one capability at the code level.

## Environment check
```powershell
# Confirm Ghidra and capa are installed on FLARE-VM (paths may vary by version)
Get-Command capa.exe | Select-Object Source
capa.exe --version

# Locate the Ghidra install and headless launcher
Get-ChildItem "C:\Tools\ghidra*" -Directory | Select-Object -First 1 FullName
Get-ChildItem -Recurse "C:\Tools" -Filter "analyzeHeadless.bat" -ErrorAction SilentlyContinue | Select-Object -First 1 FullName
```
Expected output: `capa.exe` prints a version string (e.g. `capa 7.x.x`), the Ghidra directory resolves to something like `C:\Tools\ghidra_11.x_PUBLIC`, and `analyzeHeadless.bat` is found under `support\`.

> Why these paths: Ghidra's Windows distribution places `ghidraRun.bat` at the install root and `analyzeHeadless.bat` under `support\`, per the Installation Guide and the repo's `RuntimeScripts/Windows` layout ([Ghidra InstallationGuide](https://ghidra-sre.org/InstallationGuide.html), [repo layout](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/RuntimeScripts/Windows/support)). `capa --version` is a documented flag ([capa usage](https://github.com/mandiant/capa#usage)). Actual install root under FLARE-VM depends on the chocolatey package layout; adjust the glob if your `C:\Tools` differs ([flare-vm](https://github.com/mandiant/flare-vm)).

## Guided walkthrough
1. Build the benign sample (see Hands-on exercise) and stage a Ghidra project directory.
```powershell
New-Item -ItemType Directory -Force -Path "C:\cases\27\ghidra_proj" | Out-Null
Set-Location "C:\cases\27"
```
Expected: an empty project directory `ghidra_proj` is created for headless analysis output. *Why:* `analyzeHeadless` needs a project location (a folder plus a project name) to store the imported program database; supplying it up front keeps output deterministic ([analyzeHeadless usage](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/README.md), [Ghidra InstallationGuide](https://ghidra-sre.org/InstallationGuide.html)).

2. Run Ghidra headless analysis and dump functions/strings with a script. The `-postScript` runs after auto-analysis; here we invoke a script located via `-scriptPath`.
```powershell
$GH = (Get-ChildItem "C:\Tools\ghidra*" -Directory | Select-Object -First 1).FullName
& "$GH\support\analyzeHeadless.bat" "C:\cases\27\ghidra_proj" hello27 `
  -import "C:\cases\27\exercise\hello.exe" `
  -postScript "FunctionNamesToConsole.py" `
  -scriptPath "C:\cases\27\exercise" `
  -deleteProject
```
Expected: Ghidra logs auto-analysis progress, then the post-script prints each recovered function name (including the entry point) to the console before the temporary project is deleted.

> Why each flag: `-import` ingests the target and runs auto-analysis by default; `-postScript` runs a script AFTER analysis (as opposed to `-preScript`, which runs before), so function recovery is complete when the script iterates functions; `-scriptPath` tells Ghidra where to find the named script; `-deleteProject` removes the temporary project when done so repeated runs stay clean. All are documented in the headless analyzer README ([analyzeHeadless README](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/README.md), [Ghidra InstallationGuide](https://ghidra-sre.org/InstallationGuide.html)). Note: `FunctionNamesToConsole.py` is an example script name you provide in `-scriptPath`; Ghidra ships example scripts (browse **Window > Script Manager**, or the repo `ghidra_scripts` folders) that you can adapt to print `getFunctionManager().getFunctions(true)` ([Ghidra scripting API `FlatProgramAPI`](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html)). Nuance: auto-analysis names are best-effort — user functions may appear as `FUN_00401000` if symbols were stripped; here the sample retains symbol/PDB info from the local compile.

3. Run capa against the same file to enumerate capabilities.
```powershell
capa.exe -v "C:\cases\27\exercise\hello.exe"
```
Expected: capa prints matched rules; the `-v` (verbose) flag adds per-rule detail and namespaces. Output is grouped by ATT&CK and Malware Behavior Catalog (MBC) mappings. For a trivial console app you will see few or no capabilities (a good baseline); richer binaries show entries like "write file" or "encode data using XOR".

> Why/nuance: capa statically extracts features (API calls, strings, bytes, numbers) and matches them against its rule set; matches carry ATT&CK and MBC labels when the rule author supplied them ([capa README](https://github.com/mandiant/capa#usage), [Mandiant capa announcement](https://cloud.google.com/blog/topics/threat-intelligence/capa-automatically-identify-malware-capabilities)). A near-empty result on a minimal PE is expected and is the intended baseline for comparison against real malware. Use `-vv` for full feature-level evidence per match ([capa README](https://github.com/mandiant/capa#usage)).

4. Open the file in the Ghidra GUI, run **Auto Analyze**, then double-click the entry function to view the Decompiler window (C-like pseudocode).
```powershell
$GH = (Get-ChildItem "C:\Tools\ghidra*" -Directory | Select-Object -First 1).FullName
& "$GH\ghidraRun.bat"
```
Expected: the Ghidra GUI launches; after importing and analyzing `hello.exe`, the Decompiler panel shows readable C for `main`/`entry`.

> Why: the GUI Decompiler reconstructs high-level C from the p-code intermediate representation Ghidra lifts from the target's instructions, letting you read control flow the disassembly alone obscures ([Ghidra features / Decompiler](https://ghidra-sre.org/), [Ghidra repo `Decompiler`](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/Decompiler)).

## Hands-on exercise
Sample artifact: `exercise\hello.exe` — a **benign, inert Windows console PE** you compile yourself from source; it only prints a string and exits (no network, no persistence, no file writes). Generate it on FLARE-VM using the bundled VC build tools:

```powershell
Set-Location "C:\cases\27\exercise"
@'
#include <stdio.h>
int add_two(int a, int b) { return a + b; }
int main(void) {
    printf("hello from module 27: %d\n", add_two(20, 7));
    return 0;
}
'@ | Out-File -Encoding ascii hello.c

# Compile with the MSVC toolchain (Developer prompt / vcvars already on FLARE-VM)
cl /nologo /Fe:hello.exe hello.c
Get-FileHash .\hello.exe -Algorithm SHA256
```

> `cl.exe` is the MSVC C/C++ compiler; `/Fe:` names the output executable and `/nologo` suppresses the banner, both documented on Microsoft Learn ([cl /Fe (name exe)](https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file), [cl /nologo](https://learn.microsoft.com/en-us/cpp/build/reference/nologo-suppress-startup-banner)). `Get-FileHash` computes SHA256 by default and via `-Algorithm SHA256`, per Microsoft Learn ([Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash)).

Tasks:
1. Recover the function named `add_two` via Ghidra headless and confirm it appears in the console output.
2. Read the Ghidra decompilation of `add_two` and state the arithmetic operation it performs.
3. Run capa on `hello.exe` and record which (if any) capabilities/ATT&CK techniques it reports.

Because the binary is compiler-dependent, verify the sample with the SHA256 your build produces (`Get-FileHash` above) rather than a fixed digest; record that hash in your notes.

## SOC analyst perspective
During incident response an analyst who pulls an unknown executable off a host does static triage before detonation. Ghidra's decompiler lets them read logic — hardcoded C2 domains, XOR loops, hashing of API names — without executing malware, and capa converts raw code patterns into ATT&CK-tagged capabilities that feed straight into a detection hypothesis.

Concrete detection logic and Security Onion pivots:
- **capa flags "encode/decode data using XOR" or API-hashing → T1027 (Obfuscated Files or Information)** ([T1027](https://attack.mitre.org/techniques/T1027/)). Hunt hypothesis: the sample decrypts a config/payload at runtime. In Security Onion, pivot to **Sysmon Event ID 1** (process create, with hashes/command line) and **Event ID 7** (image/DLL load) to catch the loader, correlating the hash from `Get-FileHash` across Elastic (`process.hash.sha256`) ([Sysmon events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Security Onion Elastic](https://docs.securityonion.net/en/2.4/elastic.html)). Detection logic: a process that loads `kernel32.dll` and calls `GetProcAddress` with a numeric hash argument (visible in decompilation) is a strong indicator of runtime API resolution. Search for `process.name:*` and `event.code:7` where `process.parent.name` is the suspicious binary.
- **capa flags "create service" → T1543.003 (Create or Modify System Process: Windows Service)** ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)). Pivot to **Sysmon Event ID 13** (registry value set under `HKLM\SYSTEM\CurrentControlSet\Services\...`) and Windows **Security Event 4697 / System Event 7045** (service install) ([Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [4697](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)). Detection logic: a process calling `CreateServiceW` (visible in capa) that also writes to the Services registry key. In Elastic, filter on `registry.key_path:*Services*` and `event.code:13` with `process.name` matching the binary.
- **capa flags "communicate over HTTP" → T1071.001 (Application Layer Protocol: Web Protocols)** ([T1071.001](https://attack.mitre.org/techniques/T1071/001/)). Pivot to **Zeek `http.log`/`conn.log`** and **Suricata alerts** in Security Onion, filtering on any URIs/User-Agents recovered from the Ghidra decompilation ([Security Onion Zeek](https://docs.securityonion.net/en/2.4/zeek.html), [Security Onion Suricata](https://docs.securityonion.net/en/2.4/suricata.html)). Detection logic: a process that imports `winhttp.dll` or `wininet.dll` (capa) and makes HTTP requests. In Zeek `http.log`, look for `id.resp_h` (destination IP) and `uri` fields matching hardcoded strings from the binary; in Suricata, the `http.uri` and `http.user_agent` sticky-buffer keywords match on the same recovered strings ([Suricata HTTP keywords](https://docs.suricata.io/en/latest/rules/http-keywords.html)).
- **capa flags "persist via registry run key" → T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)** ([T1547.001](https://attack.mitre.org/techniques/T1547/001/)). Pivot to **Sysmon Event ID 13** targeting `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` or `HKCU\...\Run`. Detection logic: a process writing to these registry paths with a value pointing to its own executable path. In Elastic, query `registry.key_path:*Microsoft\\Windows\\CurrentVersion\\Run*` and `event.code:13`.
- **capa flags "create or open process" → T1059 (Command and Scripting Interpreter)** ([T1059](https://attack.mitre.org/techniques/T1059/)). Pivot to **Sysmon Event ID 1** (process creation) and look for child processes spawned by the suspicious binary. Detection logic: a process calling `CreateProcess` or `ShellExecute` (capa) spawning `cmd.exe`, `powershell.exe`, or `wmic.exe`. In Elastic, filter on `process.parent.name` and `process.name` for known interpreters. If the child is `powershell.exe`, pivot to **Windows Event ID 4104** (PowerShell Script Block Logging, sub-technique **T1059.001 PowerShell**) and search `ScriptBlockText` for encoded/`-EncodedCommand` invocations ([PowerShell script block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows), [T1059.001](https://attack.mitre.org/techniques/T1059/001/)).
- **capa flags "resolve DLL by ordinal" or an import table pointing to a DLL name outside `System32`/`SysWOW64` → T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)** ([T1574.001](https://attack.mitre.org/techniques/T1574/001/)). Detection logic: correlate **Sysmon Event ID 7** `ImageLoaded` with a path under the application's own working directory rather than a system directory, combined with `Signed:false` or a `Signature` mismatch on that DLL, and a preceding **Event ID 11** `FileCreate` of a DLL sharing the name of a known system library. In Elastic, filter `event.code:7` where `file.directory` is not `C:\Windows\System32` and the loaded filename matches a well-known Windows DLL (e.g., `version.dll`, `dbghelp.dll`).
- **capa flags "manually map a PE" or a shellcode stub calling `VirtualAlloc`/`memcpy` of a PE header into memory → T1620 (Reflective Code Loading)** ([T1620](https://attack.mitre.org/techniques/T1620/)). Detection logic: the loaded module never appears as a file on disk, so Sysmon **Event ID 7** may fire with no `Hashes` matching any file-backed image, or the `ImageLoaded` path is anomalous/blank; pair this with **Event ID 10** (`ProcessAccess`) showing a `GrantedAccess` value consistent with memory-write rights (e.g., `0x1F0FFF` or subsets including `PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION`) targeting the host process. Hunt for processes with memory regions marked `PAGE_EXECUTE_READWRITE` that have no backing file, a classic reflective-loading artifact.
- **capa flags PE resource/version-info fields (e.g., `OriginalFileName`, `CompanyName`) that don't match the on-disk filename or expected vendor → T1036 (Masquerading)** ([T1036](https://attack.mitre.org/techniques/T1036/)). Detection logic: in Sysmon **Event ID 1**, compare `OriginalFileName` (from the PE version resource) against `Image` (the actual path/filename) — a mismatch (e.g., `OriginalFileName: svchost.exe` but `Image: C:\Users\Public\update.exe`) is a strong masquerading indicator; Ghidra's PE header/resource view surfaces the same version-info fields for manual confirmation.
- **capa flags process/module enumeration APIs (`CreateToolhelp32Snapshot`, `Process32First/Next`, `EnumProcesses`) → T1057 (Process Discovery)** ([T1057](https://attack.mitre.org/techniques/T1057/)). Detection logic: a burst of **Sysmon Event ID 10** `ProcessAccess` events (or repeated `OpenProcess` calls visible in an ETW/API-monitor trace) from a single source process against many distinct target PIDs in a short window is atypical for normal software and worth a hunt query grouping by `SourceProcessId` with a high distinct-`TargetProcessId` count.
- Turn confirmed strings/bytes into a **Suricata rule** or a **Sigma rule** (process-create) and deploy fleet-wide; Security Onion supports local Suricata rules and Sigma-driven detections ([Suricata rules](https://docs.suricata.io/en/latest/rules/index.html), [Sigma](https://github.com/SigmaHQ/sigma)). For example, a Suricata rule can alert on HTTP traffic containing a hardcoded User-Agent string found in the binary: `alert http any any -> any any (msg:"Suspicious User-Agent from reversed binary"; http.user_agent; content:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) EvilBot"; sid:1000001;)`.

**Threat-hunting pivots.** Once Ghidra/capa surface a candidate IOC or behavior, hunt across the fleet rather than the single host: (1) pivot on the SHA256 recovered by `Get-FileHash` across Elastic's `process.hash.sha256` and Zeek's `files.log` `sha256` field to find every host that touched the file, correlating first-seen `ts` with patient-zero timing ([Security Onion Zeek](https://docs.securityonion.net/en/2.4/zeek.html)); (2) pivot on any hardcoded domain/URI strings recovered in the decompiler against Zeek `dns.log` `query` and `http.log` `host` fields to catch pre-detonation beaconing to the same infrastructure; (3) pivot on the import-hash / rich-header fingerprint (visible via Ghidra's PE loader info) against your EDR's file-metadata index to find variants that share a builder but differ in hash, since packers and recompiles change the hash but often not the rich header; (4) for any registry-persistence or service-creation capability capa reports, sweep `HKLM\SYSTEM\CurrentControlSet\Services\*` and the Run keys fleet-wide via Sysmon Event ID 13 aggregated in Elastic to find other hosts already persisted before the sample was even confirmed malicious.

## Attacker perspective
Adversaries and red teamers use these same tools to understand and defeat defenses. Reversing with Ghidra reveals how an EDR agent hooks APIs or how a license/anti-tamper check works, and its scripting engine automates deobfuscation of packed or string-encrypted payloads. Attackers also run capa against their own implants to see which behaviors are "loud" and likely to be signatured, then refactor to reduce detections.

Concrete TTPs, artifacts, and evasion:
- **Obfuscation / packing (T1027, sub-technique T1027.002 Software Packing)** to defeat static feature extraction — packers strip imports and encrypt sections so capa sees only the stub ([T1027.002](https://attack.mitre.org/techniques/T1027/002/)). Artifact left behind: high section entropy, a tiny import table, and a distinctive unpacking stub — all recoverable statically. Defender counter: entropy analysis and capa's packer-detection rules ([capa rules](https://github.com/mandiant/capa-rules)). Attackers may use custom packers or modify public ones to evade signature-based detection.
- **API hashing / dynamic resolution (T1027)** to hide `GetProcAddress`/import strings; the hashing routine and constant seed remain in the binary and can be scripted out with Ghidra ([T1027](https://attack.mitre.org/techniques/T1027/), [Ghidra scripting API](https://ghidra.re/ghidra_docs/api/index.html)). Artifacts: a loop that calls `LoadLibrary`/`GetModuleHandle` and `GetProcAddress` with a hash comparison. Evasion: use indirect syscalls or manually map DLLs to avoid these APIs entirely.
- **Runtime decode of payloads (T1140 Deobfuscate/Decode Files or Information)** — the decode routine is visible in the decompiler even when the plaintext is not on disk ([T1140](https://attack.mitre.org/techniques/T1140/)). Artifacts: XOR loops, base64 decoding, or custom decryption functions. Evasion: use environmental keying (e.g., derive key from hostname) or only decrypt in memory without leaving a static routine.
- **Process injection (T1055 Process Injection)** — capa may flag `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`. Attackers analyze these signatures and switch to alternative techniques like **Process Hollowing (T1055.012)** or **Thread Local Storage (T1055.005)** to evade ([T1055](https://attack.mitre.org/techniques/T1055/), [T1055.012](https://attack.mitre.org/techniques/T1055/012/), [T1055.005](https://attack.mitre.org/techniques/T1055/005/)). Artifacts: cross-process memory operations and thread creation from an external process, visible as Sysmon **Event ID 8** (`CreateRemoteThread`) and **Event ID 10** (`ProcessAccess`).
- **DLL search order hijacking (T1574.001 Hijack Execution Flow: DLL Search Order Hijacking)** — attackers reverse a signed, trusted binary with Ghidra to find an unqualified `LoadLibrary` call for a DLL that Windows will resolve from the application directory before `System32`, then drop a malicious DLL of that exact name next to the legitimate EXE so it loads with the trusted binary's privileges ([T1574.001](https://attack.mitre.org/techniques/T1574/001/)). Artifacts: a DLL on disk in a non-standard location whose export table mimics the real library, and a Sysmon **Event ID 7** load from that path. Evasion: proxy all real exports to the legitimate DLL (renamed) so the hijacked process keeps functioning normally, hiding the compromise from casual inspection.
- **Reflective code loading (T1620 Reflective Code Loading)** — rather than dropping a DLL to disk, the payload manually maps a PE image into memory (parsing its own PE headers, resolving imports, applying relocations) to avoid file-based AV/EDR scanning and Sysmon file-create events ([T1620](https://attack.mitre.org/techniques/T1620/)). capa can still often flag the manual-mapping stub itself (calls to `VirtualAlloc` + a loop copying/relocating section data) because that logic is a recognizable code pattern regardless of the payload's ultimate stealth. Evasion: attackers may further obfuscate the loader stub or split it across multiple stages to reduce capa/YARA hit rates.
- **Masquerading (T1036 Masquerading)** — attackers edit the PE version-info resource (`OriginalFileName`, `ProductName`, `CompanyName`) or copy an icon from a legitimate application to make the binary look like a trusted process (e.g., naming it `svchost.exe` or spoofing a common utility) ([T1036](https://attack.mitre.org/techniques/T1036/)). Ghidra's resource/version-info viewer and capa's file-metadata rules both surface the mismatch between claimed identity and actual code/location. Evasion: attackers may also code-sign with a stolen or look-alike certificate, though the signing chain and PDB/rich-header fingerprints still differ from the genuine vendor build.
- **Process/module discovery (T1057 Process Discovery)** used pre-injection to find a suitable host process (commonly a signed, running process compatible with the payload's target architecture) — capa flags `CreateToolhelp32Snapshot`/`Process32Next` combinations that reveal this reconnaissance step ([T1057](https://attack.mitre.org/techniques/T1057/)). Attackers minimize noise by hardcoding a single target process name instead of enumerating broadly, trading flexibility for stealth.
- **Lateral tool transfer (T1570 Lateral Tool Transfer)** — capa may flag SMB/WinRM client APIs. Attackers can obfuscate network strings or use living-off-the-land binaries (like `sc.exe` or `wmic.exe`) to move files instead of embedding a custom client ([T1570](https://attack.mitre.org/techniques/T1570/)).
- Static analysis itself is quiet — it runs on the attacker's own box and leaves no artifacts on the victim — but the compiled malware they ship still betrays them: capa's matched rules, distinctive constants, imported API sets, and rich-header/compiler fingerprints all remain in the binary for a defender to recover later ([capa announcement](https://cloud.google.com/blog/topics/threat-intelligence/capa-automatically-identify-malware-capabilities)).

## Answer key
- `FunctionNamesToConsole.py` (or the GUI Symbol Tree) lists a user function `add_two` alongside `main`/`entry`.
- Ghidra's decompiler renders `add_two` as returning `a + b` (a single integer add); the return of `main` calls it with `20` and `7`, yielding `27` in the printed string.
- Verify the printed output at runtime is safe to confirm logic (optional, benign): `& C:\cases\27\exercise\hello.exe` prints `hello from module 27: 27`.
- capa output for this trivial console app is minimal (typically only generic behaviors such as "contains PDB path" or none of the tactic-level techniques); the teaching point is establishing a clean baseline versus a real sample.
- Commands producing the findings:
```powershell
capa.exe -v "C:\cases\27\exercise\hello.exe"
Get-FileHash "C:\cases\27\exercise\hello.exe" -Algorithm SHA256
```
- Record the SHA256 emitted by your compile of `hello.exe` (build-dependent); this is the sample identifier for grading.

## MITRE ATT&CK & DFIR phase
- Analysis technique focus (defender-facing): T1027 (Obfuscated Files or Information) and T1140 (Deobfuscate/Decode Files or Information) — capabilities Ghidra scripting and capa help surface ([T1027](https://attack.mitre.org/techniques/T1027/), [T1140](https://attack.mitre.org/techniques/T1140/)).
- Example capabilities capa may map on richer samples: T1027.002 (Software Packing) ([T1027.002](https://attack.mitre.org/techniques/T1027/002/)), T1543.003 (Create or Modify System Process: Windows Service) ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)), T1071.001 (Application Layer Protocol: Web Protocols) ([T1071.001](https://attack.mitre.org/techniques/T1071/001/)), T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) ([T1547.001](https://attack.mitre.org/techniques/T1547/001/)), T1059 (Command and Scripting Interpreter) ([T1059](https://attack.mitre.org/techniques/T1059/)), T1059.001 (PowerShell) ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)), T1055 (Process Injection) ([T1055](https://attack.mitre.org/techniques/T1055/)), T1570 (Lateral Tool Transfer) ([T1570](https://attack.mitre.org/techniques/T1570/)), T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) ([T1574.001](https://attack.mitre.org/techniques/T1574/001/)), T1620 (Reflective Code Loading) ([T1620](https://attack.mitre.org/techniques/T1620/)), T1036 (Masquerading) ([T1036](https://attack.mitre.org/techniques/T1036/)), and T1057 (Process Discovery) ([T1057](https://attack.mitre.org/techniques/T1057/)).
- DFIR phase: **Examination / Analysis** (static reverse-engineering triage), feeding **Identification** of IOCs for hunting. Phase terminology follows the NIST SP 800-86 forensic process (collection → examination → analysis → reporting) ([NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)) and SANS FOR610 static-analysis methodology ([SANS FOR610](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/)).


```markdown
### Essential Commands & Features

Ghidra scripting enables powerful automation for reverse engineering. Below are **high-impact commands and features** not yet covered, with concrete examples and tactical use cases:

1. **`currentProgram.getFunctionManager().getFunctions(True)`**
   Iterate over all functions (including thunks) to analyze obfuscated code. Critical for detecting **T1027.005 (Indicator Removal from Tools)** or **T1106 (Native API)** misuse.
   ```python
   for func in currentProgram.getFunctionManager().getFunctions(True):
       if "Crypt" in func.getName():  # Hunt for crypto routines
           print(f"Found: {func.getEntryPoint()}")
   ```

2. **`getInstructionAt(addr).getMnemonicString()`**
   Extract mnemonics to identify anti-analysis tricks (e.g., `CPUID` checks for **T1497.001 (System Checks)**).
   ```python
   instr = getInstructionAt(currentAddress)
   if instr and instr.getMnemonicString() == "CPUID":
       print(f"Anti-VM at {currentAddress}")
   ```

3. **`FlatProgramAPI.createFunction(addr, name)`**
   Reconstruct stripped functions (e.g., for **T1562.001 (Disable or Modify Tools)**).
   ```python
   func_addr = toAddr(0x00401234)
   FlatProgramAPI(currentProgram).createFunction(func_addr, "DecryptPayload")
   ```

4. **`getReferencesTo(addr)`**
   Trace cross-references *without* using Ghidra’s XREF system (e.g., to map **T1574.002 (DLL Side-Loading)**).
   ```python
   refs = getReferencesTo(currentAddress)
   for ref in refs:
       print(f"Referenced from: {ref.getFromAddress()}")
   ```

**Sources:**
- Ghidra API Cookbook: [https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Intermediate/Scripting.html](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Intermediate/Scripting.html)
- Mandiant Ghidra Scripting Guide: [https://www.mandiant.com/resources/blog/ghidra-scripting-for-malware-analysis](https://www.mandiant.com/resources/blog/ghidra-scripting-for-malware-analysis)
```

### Threat Hunting & Detection Engineering

Once Ghidra scripts have flagged suspicious code patterns (e.g., `VirtualAlloc` + `RtlMoveMemory` chains), pivot to **detection engineering** to scale hunts across the enterprise. Focus on **Process Injection (T1055.002: Portable Executable Injection)** and **Reflective Code Loading (T1574.009: Reflective DLL Injection)**—both evade static signatures by executing code directly in memory.

**Detection Logic:**
1. **Windows Event Logs (Sysmon Event ID 8: `CreateRemoteThread`)**:
   Hunt for `TargetImage` processes (e.g., `lsass.exe`, `explorer.exe`) with `SourceImage` paths outside `System32` or `Program Files`. Filter for `StartModule` values of `NULL` (common in reflective loading) or non-standard DLLs (e.g., `amsi.dll` hijacking).
   *Pivot*: Cross-reference with Event ID 10 (`ProcessAccess`) to identify `GrantedAccess` flags like `0x1FFFFF` (full access), often used in injection.

2. **Zeek/Suricata**:
   Monitor for **unusual process execution via `cmd.exe`/`powershell.exe` with encoded commands** (T1059.001: PowerShell). Use Zeek’s `exec` events to detect child processes of `svchost.exe` spawning `powershell.exe` with `-EncodedCommand` or `-ep bypass`. Suricata can inspect HTTP traffic for **base64-encoded PE headers** (e.g., `TVqQAAMAAAAEAAAA`) in POST bodies (T1027.001: Binary Padding).
   *Pivot*: Correlate with Zeek’s `files.log` for `.dll` downloads from non-standard ports (e.g., 8080, 8443).

**Authoritative Sources:**
- [MITRE ATT&CK: T1055.002](https://attack.mitre.org/techniques/T1055/002/)
- [SpecterOps: Detecting Reflective DLL Injection](https://posts.specterops.io/defenders-think-in-graphs-too-part-1-572524c71e91) (Detection engineering for T1574.009)


### Essential Commands & Features

#### Ghidra Headless Batch Mode (`-process`)
Use Ghidra’s headless analyzer to automate script execution without launching the GUI. This is critical for bulk analysis or CI/CD pipelines. The `-process` flag processes a single binary, while `-scriptPath` specifies the script directory.

**Example:**
```bash
analyzeHeadless /path/to/project_dir ProjectName -import /malware/sample.exe -process -scriptPath /scripts -postScript CapaGhidra.py
```
**When to use:** Automate analysis of multiple samples (e.g., triaging **T1059.003 Command and Scripting Interpreter: Windows Command Shell** or **T1562.004 Impair Defenses: Disable or Modify System Firewall**).

---

#### Ghidra Python API (`currentScript`)
Access the current script’s context via `currentScript` to interact with the program, listing, or decompiler. Useful for dynamic analysis or modifying program state.

**Example:**
```python
from ghidra.app.script import GhidraScript
currentScript = getState().getScript()
func = currentScript.getFirstFunction()
print(f"First function: {func.getName()}")
```
**When to use:** Programmatically enumerate functions or cross-reference data (e.g., identifying **T1574.007 Hijack Execution Flow: Path Interception by PATH Environment Variable**).

---

#### Capa Verbose/JSON Output (`-v`, `-j`)
Capa’s `-v` (verbose) and `-j` (JSON) flags provide detailed or machine-readable output for integration with other tools. Verbose mode includes rule matches and addresses, while JSON is ideal for parsing.

**Example:**
```bash
capa -v /malware/sample.exe  # Verbose output
capa -j /malware/sample.exe  # JSON output
```
**When to use:** `-v` for manual review (e.g., **T1027.006 Obfuscated Files or Information: HTML Smuggling**), `-j` for automated pipelines.

---

**Sources:**
- [Ghidra Headless Analyzer Docs (NSA)](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessAnalyzer.html)
- [Capa Rule Development Guide (FireEye)](https://github.com/mandiant/capa/blob/master/doc/rules.md)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Suspicious Scripting in a WMI Consumer** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/wmi_event/sysmon_wmi_susp_scripting.yml; license: Detection Rule License / DRL):

```yaml
title: Suspicious Scripting in a WMI Consumer
id: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
status: test
description: Detects suspicious commands that are related to scripting/powershell in WMI Event Consumers
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/615bf1f6bac3c1bdc417025c40c073e6c2771a76/yara/gen_susp_lnk_files.yar#L19
    - https://github.com/RiccardoAncarani/LiquidSnake
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
date: 2019-04-15
modified: 2023-09-09
tags:
    - attack.execution
    - attack.t1059.005
logsource:
    product: windows
    category: wmi_event
detection:
    selection_destination:
        - Destination|contains|all:
              - 'new-object'
              - 'net.webclient'
              - '.downloadstring'
        - Destination|contains|all:
              - 'new-object'
              - 'net.webclient'
              - '.downloadfile'
        - Destination|contains:
              - ' iex('
              - ' -nop '
              - ' -noprofile '
              - ' -decode '
              - ' -enc '
              - 'WScript.Shell'
              - 'System.Security.Cryptography.FromBase64Transform'
    condition: selection_destination
falsepositives:
    - Legitimate administrative scripts
level: high
```

**Real-world context (MITRE T1027 -- Obfuscated Files or Information):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1027/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

#### Ghidra Headless Batch Mode (`-process`)
Use Ghidra’s headless analyzer to automate script execution without launching the GUI. The `-process` flag processes a single binary, ideal for CI/CD pipelines or bulk analysis. Example:
```bash
analyzeHeadless /path/to/project ProjectName -process malware.exe -scriptPath /scripts -postScript FindStrings.py
```
This is particularly useful for detecting **T1059.005 Command-Line Interface** or **T1546.008 Event Triggered Execution: Accessibility Features**, where batch processing can flag suspicious strings or hooks.

#### Python API (`currentScript`)
Access Ghidra’s current script context via `currentScript` to interact with the program database. Example:
```python
from ghidra.app.script import GhidraScript
currentScript = getState().getScript()
func = currentScript.getFunctionContaining(currentAddress)
print(f"Function: {func.getName()}")
```
Use this to automate **T1574.009 Hijack Execution Flow: Path Interception by PATH Environment Variable** by enumerating imported functions or DLLs.

#### Capa’s `-v` (Verbose) and `-j` (JSON) Flags
Enhance capa’s output with `-v` for detailed rule matches or `-j` for machine-readable JSON. Example:
```bash
capa -v malware.exe  # Verbose output for manual review
capa -j malware.exe  # JSON for automated parsing
```
These flags help identify **T1562.006 Indicator Removal: Timestomp** or **T1070.006 Indicator Removal: File Deletion** by surfacing evasion techniques in structured formats.

**Sources:**
- [Ghidra Headless Documentation (NSA GitHub)](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/HeadlessAnalysis.md)
- [FireEye Capa Rules & Usage](https://github.com/fireeye/capa-rules/blob/master/doc/usage.md)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, Ghidra scripting is a powerful post-exploitation tool for **automated binary analysis, payload customization, and evasion**. Attackers leverage Ghidra scripts to rapidly identify vulnerable functions (e.g., unsafe deserialization, buffer overflows) or hardcoded credentials in compiled binaries, accelerating **exploitation development** (MITRE ATT&CK [T1588.002: Obtain Capabilities - Exploits](https://attack.mitre.org/techniques/T1588/002/)). For example, a script could parse a target binary to locate cryptographic functions, then dynamically patch them to weaken encryption (e.g., replacing AES with XOR) for **data exfiltration** (MITRE ATT&CK [T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)).

**Concrete TTPs**:
- **Automated Backdoor Insertion**: Scripts can inject malicious hooks (e.g., `CreateRemoteThread` calls) into legitimate binaries, blending with trusted processes (e.g., `svchost.exe`).
- **Evasion via Obfuscation**: Attackers use Ghidra’s decompiler to identify and modify strings/imports, then recompile binaries to bypass signature-based detection (e.g., altering `VirtualAlloc` to `NtAllocateVirtualMemory`).
- **Artifact Generation**: Scripts may leave traces in Ghidra’s project files (e.g., `.rep`/`.gpr` metadata) or temporary directories (e.g., `%TEMP%\ghidra_*`).

**Evasion Considerations**:
- **Anti-Forensics**: Delete Ghidra project files post-analysis and use memory-only scripting (e.g., Python `exec()`) to avoid disk artifacts.
- **Living-off-the-Land**: Prefer Ghidra’s headless mode (`analyzeHeadless`) to avoid GUI telemetry, and obfuscate script logic (e.g., string encryption) to evade EDR behavioral analysis.

**Sources**:
- [MITRE ATT&CK: Exploitation for Client Execution (T1203)](https://attack.mitre.org/techniques/T1203/)
- [FireEye: Ghidra Scripting for Malware Analysis (2021)](https://www.fireeye.com/blog/threat-research/2021/03/ghidra-scripting-for-malware-analysis.html)

## Sources
Claim → source mapping (all URLs are to official/authoritative pages):

- Ghidra is an NSA SRE framework with a decompiler + scripting engine — https://ghidra-sre.org/ and https://github.com/NationalSecurityAgency/ghidra
- Ghidra GUI launcher (`ghidraRun.bat`) and headless launcher location (`support\analyzeHeadless.bat`); install layout — https://ghidra-sre.org/InstallationGuide.html and https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/RuntimeScripts/Windows/support
- `analyzeHeadless` flags (`-import`, `-preScript`/`-postScript`, `-scriptPath`, `-deleteProject`) and behavior — https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/README.md
- Ghidra scripting / FlatProgramAPI (enumerating functions) — https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html and https://ghidra.re/ghidra_docs/api/index.html
- Ghidra Decompiler feature — https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/Decompiler
- Mandiant capa: capability detection, `-v`/`-vv` verbosity, `--version`, ATT&CK/MBC mapping — https://github.com/mandiant/capa and https://cloud.google.com/blog/topics/threat-intelligence/capa-automatically-identify-malware-capabilities
- capa Ghidra integration/plugin — https://github.com/mandiant/capa/tree/master/capa/ghidra
- capa rules (packer/behavior rules) — https://github.com/mandiant/capa-rules
- FLARE-VM (packages Ghidra & capa) — https://github.com/mandiant/flare-vm
- MSVC `cl` `/Fe` and `/nologo`; PowerShell `Get-FileHash` — https://learn.microsoft.com/en-us/cpp/build/reference/fe-name-exe-file , https://learn.microsoft.com/en-us/cpp/build/reference/nologo-suppress-startup-banner , https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- Sysmon events (1 process create, 7 image load, 8 CreateRemoteThread, 10 ProcessAccess, 11 FileCreate, 13 registry set) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows service-install event 4697 — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697
- PowerShell Script Block Logging (Event ID 4104) — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Security Onion Elastic / Zeek / Suricata pivots — https://docs.securityonion.net/en/2.4/elastic.html , https://docs.securityonion.net/en/2.4/zeek.html , https://docs.securityonion.net/en/2.4/suricata.html
- Suricata rule format and HTTP keywords (`http.uri`, `http.user_agent`) — https://docs.suricata.io/en/latest/rules/index.html and https://docs.suricata.io/en/latest/rules/http-keywords.html
- Sigma detection rules — https://github.com/SigmaHQ/sigma
- MITRE ATT&CK techniques: T1027 — https://attack.mitre.org/techniques/T1027/ ; T1027.002 — https://attack.mitre.org/techniques/T1027/002/ ; T1140 — https://attack.mitre.org/techniques/T1140/ ; T1543.003 — https://attack.mitre.org/techniques/T1543/003/ ; T1071.001 — https://attack.mitre.org/techniques/T1071/001/ ; T1547.001 — https://attack.mitre.org/techniques/T1547/001/ ; T1059 — https://attack.mitre.org/techniques/T1059/ ; T1059.001 — https://attack.mitre.org/techniques/T1059/001/ ; T1055 — https://attack.mitre.org/techniques/T1055/ ; T1055.012 — https://attack.mitre.org/techniques/T1055/012/ ; T1055.005 — https://attack.mitre.org/techniques/T1055/005/ ; T1570 — https://attack.mitre.org/techniques/T1570/ ; T1574.001 — https://attack.mitre.org/techniques/T1574/001/ ; T1620 — https://attack.mitre.org/techniques/T1620/ ; T1036 — https://attack.mitre.org/techniques/T1036/ ; T1057 — https://attack.mitre.org/techniques/T1057/

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- shares capa
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- shares capa
- [Cutter (Rizin) RE on Windows](../46-cutter-windows/README.md) -- shares capa
- [Scenario: .NET malware analysis](../53-dotnet-malware-case/README.md) -- shares capa

<!-- cyberlab-enriched: v3 -->
- https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Intermediate/Scripting.html](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Intermediate/Scripting.html
- https://www.mandiant.com/resources/blog/ghidra-scripting-for-malware-analysis](https://www.mandiant.com/resources/blog/ghidra-scripting-for-malware-analysis
- https://attack.mitre.org/techniques/T1055/002/
- https://posts.specterops.io/defenders-think-in-graphs-too-part-1-572524c71e91

<!-- cyberlab-enriched: v4 -->
- https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessAnalyzer.html
- https://github.com/mandiant/capa/blob/master/doc/rules.md
- https://ghidra-sre.org/"

<!-- cyberlab-enriched: v5 -->
- https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/HeadlessAnalysis.md
- https://github.com/fireeye/capa-rules/blob/master/doc/usage.md
- https://attack.mitre.org/techniques/T1588/002/
- https://attack.mitre.org/techniques/T1041/
- https://attack.mitre.org/techniques/T1203/
- https://www.fireeye.com/blog/threat-research/2021/03/ghidra-scripting-for-malware-analysis.html

<!-- cyberlab-enriched: v6 -->
