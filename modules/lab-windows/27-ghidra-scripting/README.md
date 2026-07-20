# 27 * Ghidra decompiler & scripting deep-dive -- LAB-WINDOWS

## Overview (plain language)
Ghidra is a free software reverse-engineering suite built by the NSA that takes a compiled program (like an .exe) and turns its raw machine code back into something humans can read — both assembly and a C-like "decompiled" view. It also has a scripting engine so you can automate boring, repetitive tasks like renaming functions or extracting strings. capa is a companion tool that reads a program and tells you, in plain English, what capabilities it has (for example "reads clipboard data" or "communicates over HTTP") by matching well-known code patterns. Together they let an analyst quickly understand what an unknown binary does without ever running it, which is safer and faster for triaging suspicious files.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Ghidra | FLARE-VM (`choco install ghidra`) | Disassembler/decompiler with a Python/Java scripting engine (headless + GUI) |
| capa | FLARE-VM (`choco install capa`) | Detects program capabilities via a rule set; integrates with Ghidra via the capa plugin |

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

## Guided walkthrough
1. Build the benign sample (see Hands-on exercise) and stage a Ghidra project directory.
```powershell
New-Item -ItemType Directory -Force -Path "C:\cases\27\ghidra_proj" | Out-Null
Set-Location "C:\cases\27"
```
Expected: an empty project directory `ghidra_proj` is created for headless analysis output.

2. Run Ghidra headless analysis and dump functions/strings with a built-in-style script. The `-postScript` runs after auto-analysis; here we use the shipped Python export.
```powershell
$GH = (Get-ChildItem "C:\Tools\ghidra*" -Directory | Select-Object -First 1).FullName
& "$GH\support\analyzeHeadless.bat" "C:\cases\27\ghidra_proj" hello27 `
  -import "C:\cases\27\exercise\hello.exe" `
  -postScript "FunctionNamesToConsole.py" `
  -scriptPath "C:\cases\27\exercise" `
  -deleteProject
```
Expected: Ghidra logs auto-analysis progress, then the post-script prints each recovered function name (including the entry point) to the console before the temporary project is deleted.

3. Run capa against the same file to enumerate capabilities.
```powershell
capa.exe -v "C:\cases\27\exercise\hello.exe"
```
Expected: capa prints a table of matched rules grouped by ATT&CK tactic. For a trivial console app you will see few or no capabilities (a good baseline); richer binaries show entries like "write file" or "resolve API by hash".

4. Open the file in the Ghidra GUI, run **Auto Analyze**, then double-click the entry function to view the Decompiler window (C-like pseudocode).
```powershell
$GH = (Get-ChildItem "C:\Tools\ghidra*" -Directory | Select-Object -First 1).FullName
& "$GH\ghidraRun.bat"
```
Expected: the Ghidra GUI launches; after importing and analyzing `hello.exe`, the Decompiler panel shows readable C for `main`/`entry`.

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

Tasks:
1. Recover the function named `add_two` via Ghidra headless and confirm it appears in the console output.
2. Read the Ghidra decompilation of `add_two` and state the arithmetic operation it performs.
3. Run capa on `hello.exe` and record which (if any) capabilities/ATT&CK techniques it reports.

Because the binary is compiler-dependent, verify the sample with the SHA256 your build produces (`Get-FileHash` above) rather than a fixed digest; record that hash in your notes.

## SOC analyst perspective
During incident response an analyst who pulls an unknown executable off a host does static triage before detonation. Ghidra's decompiler lets them read logic — hardcoded C2 domains, XOR loops, hashing of API names — without executing malware, and capa converts raw code patterns into ATT&CK-tagged capabilities that feed straight into a detection hypothesis. In Security Onion those hypotheses become hunts: if capa flags "resolve API by hash" (T1027) or "create service" (T1543.003), the analyst pivots to Sysmon (EventID 7/13) and Zeek/Suricata logs to find execution and network artifacts across the fleet, then writes or tunes Sigma/Suricata rules to catch the same behavior on other endpoints.

## Attacker perspective
Adversaries and red teamers use these same tools to understand and defeat defenses. Reversing with Ghidra reveals how an EDR agent hooks APIs or how a license/anti-tamper check works, and its scripting engine automates deobfuscation of packed or string-encrypted payloads. Attackers also run capa against their own implants to see which behaviors are "loud" and likely to be signatured, then refactor to reduce detections. Static analysis itself is quiet — it runs on the attacker's own box and leaves no artifacts on the victim — but the compiled malware they ship still betrays them: capa's matched rules, distinctive constants, imported API sets, and rich-header/compiler fingerprints all remain in the binary for a defender to recover later.

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
- Analysis technique focus (defender-facing): T1027 (Obfuscated Files or Information) and T1140 (Deobfuscate/Decode Files or Information) — capabilities Ghidra scripting and capa help surface.
- Example capabilities capa may map on richer samples: T1543.003 (Create or Modify System Process: Windows Service), T1071.001 (Application Layer Protocol: Web).
- DFIR phase: **Examination / Analysis** (static reverse-engineering triage), feeding **Identification** of IOCs for hunting.

## Sources
- Ghidra project & documentation — https://ghidra-sre.org/ and https://github.com/NationalSecurityAgency/ghidra
- Ghidra headless analyzer (analyzeHeadless) usage — https://ghidra-sre.org/InstallationGuide.html#RunGhidra
- Mandiant capa — https://github.com/mandiant/capa and https://cloud.google.com/blog/topics/threat-intelligence/capa-automatically-identify-malware-capabilities
- FLARE-VM (tool distribution incl. Ghidra & capa) — https://github.com/mandiant/flare-vm
- MITRE ATT&CK techniques T1027 / T1140 — https://attack.mitre.org/techniques/T1027/ and https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware (static analysis methodology) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/