# 14 * .NET reverse engineering -- LAB-WINDOWS

## Overview (plain language)
Many Windows programs today are written in the .NET framework (languages like C# and VB.NET). Instead of compiling straight to raw machine code, these programs compile to an intermediate language (IL) that keeps a lot of the original structure — method names, class names, and readable logic. That makes .NET malware much easier to reverse engineer than native code, because the right tools can turn the compiled file back into something very close to the original source code. This module covers three free tools that decompile .NET binaries so you can read them like source, step through them in a debugger, and strip away obfuscation that malware authors add to hide their intent. In short: you take a suspicious `.exe` or `.dll`, and these tools show you what it actually does in near-source form.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| dnSpyEx | Preinstalled via FLARE-VM (`choco install dnspyex`) | Decompile, edit, and debug .NET assemblies interactively (fork of the original dnSpy). |
| ILSpy | Preinstalled via FLARE-VM (`choco install ilspy`) | Open-source .NET decompiler/assembly browser with CLI (`ilspycmd`) support. |
| de4dot | Preinstalled via FLARE-VM (de4dot-cex) | Deobfuscator/unpacker that cleans obfuscated .NET assemblies back to readable form. |

## Learning objectives
- Confirm a target file is a managed (.NET) assembly and identify its compiler/obfuscator.
- Decompile a .NET binary to near-source C# using dnSpyEx and ILSpy (`ilspycmd`).
- Run de4dot to remove common obfuscation and produce a cleaned assembly.
- Locate suspicious behavior (network, process, crypto) in decompiled code and record artifacts.

## Environment check
```powershell
# Prove the three .NET RE tools are present on FLARE-VM.
# dnSpyEx is a GUI app - confirm the executable exists:
Get-Command dnSpy.exe -ErrorAction SilentlyContinue | Select-Object Source
Test-Path "C:\Tools\dnSpyEx\dnSpy.exe"

# ILSpy ships a command-line front end:
ilspycmd --version

# de4dot (de4dot-cex) prints its banner when run with no target:
de4dot.exe
```
Expected output: `Test-Path` returns `True` (or `Get-Command` resolves a path), `ilspycmd --version` prints a version like `9.x`, and `de4dot.exe` prints its `de4dot v3.x ... Copyright` banner and usage text.

## Guided walkthrough
1. Verify the sample is a managed assembly before decompiling — a native PE will not decompile.
```powershell
# ILSpy's CLI reads metadata; a managed file lists its target framework.
ilspycmd --il "exercise\sample_dotnet.exe" | Select-String -Pattern "TargetFramework|.assembly" | Select-Object -First 5
```
Expected: lines referencing `.assembly` and a `TargetFramework` attribute, confirming a .NET assembly.

2. Decompile the whole assembly to C# source files with ILSpy's CLI.
```powershell
New-Item -ItemType Directory -Force -Path "exercise\decompiled" | Out-Null
ilspycmd -p -o "exercise\decompiled" "exercise\sample_dotnet.exe"
Get-ChildItem -Recurse "exercise\decompiled" -Filter *.cs | Select-Object Name
```
Expected: a project folder populated with `.cs` files (e.g. `Program.cs`) you can open and read.

3. Search decompiled source for suspicious API usage.
```powershell
Select-String -Path "exercise\decompiled\*.cs" -Pattern "WebClient|DownloadString|Process.Start|FromBase64String"
```
Expected: matches (or none) showing which risky APIs the sample references.

4. If the code looks garbled (obfuscated), run de4dot to clean it, then re-decompile.
```powershell
de4dot.exe -f "exercise\sample_dotnet.exe" -o "exercise\sample_dotnet-cleaned.exe"
```
Expected: de4dot prints `Detected <obfuscator or Unknown>`, `Cleaning ...`, and `Saving ...`, producing `sample_dotnet-cleaned.exe`.

5. Open the (cleaned) assembly in dnSpyEx for interactive review/debugging.
```powershell
Start-Process "C:\Tools\dnSpyEx\dnSpy.exe" -ArgumentList "exercise\sample_dotnet-cleaned.exe"
```
Expected: dnSpyEx GUI opens with the assembly tree; you can set breakpoints and step through IL/C#.

## Hands-on exercise
Sample artifact: `exercise/sample_dotnet.exe`.
- **Type:** a small benign 64-bit .NET (C#) console executable that prints a greeting and reads an embedded Base64 string — it performs **no network, file-write, or process-spawn activity**.
- **Safe origin:** compiled locally on the FLARE-VM from an inert "Hello, analyst" C# source stub. It is completely benign/inert with no egress; it is **not** live malware.
- **sha256:** `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

Tasks:
1. Confirm it is a managed assembly.
2. Decompile it with `ilspycmd` and identify the method that decodes the embedded Base64 string.
3. Run de4dot against it and note whether an obfuscator was detected.
4. In dnSpyEx, locate the decoded plaintext string.

## SOC analyst perspective
Defenders reverse .NET malware constantly because commodity loaders, stealers (e.g. AgentTesla, Formbook loaders), and RATs are frequently written in C#. When Security Onion surfaces an alert — a Suricata rule firing on a `.NET`-generated C2 beacon, or a Zeek `files.log` extraction of a suspicious `.exe` — an analyst pulls that extracted binary and decompiles it with ILSpy/dnSpyEx to read the actual logic: hardcoded C2 URLs, decryption keys, mutex names, and scheduled-task persistence. de4dot removes ConfuserEx/obfuscation so hunting queries and YARA signatures target real strings rather than junk. Findings map to MITRE ATT&CK T1027 (Obfuscated/Compressed Files), T1059.003, and T1071 (C2), and feed IOCs (domains, hashes) back into Security Onion for retroactive hunting across PCAP and endpoint logs.

## Attacker perspective
Attackers favor .NET because it enables fast development, in-memory `Assembly.Load` execution, and easy trojanizing of legitimate managed apps. To slow analysis they apply obfuscators (ConfuserEx, .NET Reactor, SmartAssembly) that rename symbols, encrypt strings, and add control-flow flattening — precisely what de4dot is built to reverse. Offensively, the same decompilers here let a red-teamer study a target's proprietary .NET software for vulnerabilities or patch/crack licensing checks in dnSpyEx, then recompile. The artifacts left behind for defenders are rich: managed PE headers with a CLR runtime import (`mscoree.dll`), an embedded manifest/`#Strings` heap, obfuscator marker attributes, unusual `TargetFramework` metadata, and — after execution — .NET assembly-load events and JIT-compiled modules visible in memory and Sysinternals process telemetry.

## Answer key
Sample sha256: `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

1. Managed-assembly confirmation:
```powershell
ilspycmd --il "exercise\sample_dotnet.exe" | Select-String -Pattern ".assembly"
```
Expected: `.assembly` directive present ⇒ it is a .NET assembly.

2. Decompile and find the decoder:
```powershell
ilspycmd -o "exercise\decompiled" "exercise\sample_dotnet.exe"
Select-String -Path "exercise\decompiled\*.cs" -Pattern "FromBase64String"
```
Expected: a match inside a decode method (e.g. `Convert.FromBase64String(...)`), the method that decodes the embedded string.

3. Deobfuscation check:
```powershell
de4dot.exe -f "exercise\sample_dotnet.exe" -o "exercise\sample_dotnet-cleaned.exe"
```
Expected: de4dot reports `Detected Unknown obfuscator` (this benign sample is unobfuscated) and still writes `sample_dotnet-cleaned.exe`.

4. In dnSpyEx, opening the assembly and viewing the string decode method reveals the decoded plaintext greeting (the inert "Hello, analyst" payload) — confirming the sample performs no malicious action.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (de4dot deobfuscation).
- **T1027.009 / packing & string encryption** commonly seen in .NET loaders.
- **T1059.003** — Command and Scripting Interpreter (Windows) for spawned commands found in code.
- **T1071.001** — Application Layer Protocol / Web C2 (hardcoded URLs recovered from source).
- **DFIR phase:** Examination / Analysis (static reverse engineering of an extracted artifact), feeding Identification of IOCs.

## Sources
- FLARE-VM tool distribution (Mandiant/Google): https://github.com/mandiant/flare-vm
- dnSpyEx (maintained fork): https://github.com/dnSpyEx/dnSpy
- ILSpy / `ilspycmd` (ICSharpCode): https://github.com/icsharpcode/ILSpy
- de4dot (0xd4d, de4dot-cex fork): https://github.com/de4dot/de4dot
- SANS FOR610 — Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1071: https://attack.mitre.org/techniques/T1071/
- Security Onion documentation: https://docs.securityonion.net/