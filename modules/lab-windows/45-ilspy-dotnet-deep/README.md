# 45 * ILSpy .NET decompilation deep-dive -- LAB-WINDOWS

## Overview (plain language)
Many Windows programs are written in .NET languages like C#. When compiled, they are not turned into raw machine code but into an intermediate form (IL, or "Common Intermediate Language") that still contains a lot of the original structure. Because of this, tools can turn a compiled .NET file back into readable source code that looks almost like what the developer wrote. ILSpy is one such tool: it opens a `.exe` or `.dll`, reads its internal instructions, and shows you human-readable C# so you can understand exactly what the program does. de4dot is a companion tool that cleans up files that malware authors deliberately scrambled (obfuscated) to make reading them harder — it renames gibberish symbols, decrypts hidden strings, and removes junk so ILSpy can show clearer code. Together they let an analyst recover the logic of a .NET sample without ever running it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| ILSpy | Included in FLARE-VM (`choco install ilspy`) | Open-source .NET assembly browser and C#/IL decompiler |
| de4dot | Included in FLARE-VM (de4dot-cex build) | .NET deobfuscator/unpacker that cleans obfuscated assemblies before decompilation |

## Learning objectives
- Load a .NET assembly into ILSpy and identify its entry point, namespaces, and referenced assemblies.
- Decompile a method to C# and export the entire assembly to a compilable project.
- Recognize obfuscation indicators (renamed symbols, encrypted strings) in a .NET sample.
- Run de4dot to produce a cleaned assembly and compare it against the original in ILSpy.
- Extract embedded resources and hard-coded indicators (URLs, keys) from a managed binary.

## Environment check
```powershell
# Confirm ILSpy command-line decompiler is available (FLARE-VM installs ilspycmd)
ilspycmd --version

# Confirm de4dot is on PATH
de4dot --help | Select-Object -First 5
```
Expected output: `ilspycmd` prints a version string such as `ilspycmd 8.x`. `de4dot` prints its banner (`de4dot vX.X.X`) followed by usage lines. If a command is not found, launch the GUI equivalents from the FLARE-VM Start Menu and confirm they open.

## Guided walkthrough
1. `ilspycmd -l c` — list all C# type members of an assembly so you can survey its structure before decompiling.
```powershell
# Inspect metadata and list types in the sample assembly
ilspycmd -l c .\exercise\sample.exe
```
Expected observable output: a list of namespaces and class/type names printed to the console. Obfuscated samples show meaningless names (e.g., `Class1`, `\u0002`, `a.b.c`).

2. Decompile a single assembly to C# on stdout so you can read the actual logic:
```powershell
# Emit decompiled C# to the console
ilspycmd .\exercise\sample.exe
```
Expected observable output: readable C# source for the `Main` method and helper classes; watch for hard-coded strings such as `http://203.0.113.10/payload`.

3. Export the whole assembly to a project folder for deeper review in VS Code:
```powershell
New-Item -ItemType Directory -Force -Path .\exercise\decompiled | Out-Null
ilspycmd -p -o .\exercise\decompiled .\exercise\sample.exe
```
Expected observable output: a generated `.csproj` plus per-type `.cs` files under `exercise\decompiled\`.

4. If names/strings look scrambled, clean the assembly with de4dot, then re-open the cleaned output in ILSpy:
```powershell
# Produces sample-cleaned.exe next to the input
de4dot -f .\exercise\sample.exe -o .\exercise\sample-cleaned.exe
ilspycmd .\exercise\sample-cleaned.exe | Select-Object -First 40
```
Expected observable output: de4dot reports the detected obfuscator (or "Unknown obfuscator") and writes the cleaned file; the re-decompiled C# is more readable (recovered strings, simplified control flow).

## Hands-on exercise
Sample artifact: `exercise/sample.exe` — a **benign, inert .NET console application** (managed PE, target `net48`). It only prints a string and contains one hard-coded marker URL `http://203.0.113.10/beacon`; it performs **no network, file, or registry activity** (no-egress, safe to analyze). It is generated locally from source — no live malware is distributed.

Safe-origin / reproducible generator (run on FLARE-VM, which ships the VC/.NET build tools):
```powershell
# Build the benign sample from inline C# source using the .NET Framework compiler
$src = @'
using System;
class Program {
    static string Marker = "http://203.0.113.10/beacon";
    static void Main() { Console.WriteLine("benign lab sample " + Marker); }
}
'@
Set-Content -Path .\exercise\sample.cs -Value $src -Encoding ASCII
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $csc /nologo /out:.\exercise\sample.exe .\exercise\sample.cs
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```

Tasks:
1. List the types in `sample.exe` with ILSpy and record the entry-point class name.
2. Decompile `Main` and extract the hard-coded marker URL.
3. Run de4dot against the sample and note the reported obfuscator status.
4. Export the assembly to a project and confirm the recovered string constant.

## SOC analyst perspective
During incident response a defender often recovers a suspicious `.exe` or `.dll` from an endpoint or from a Security Onion alert (e.g., a Suricata hit on a beacon URL, or a Zeek `files.log` entry flagging a downloaded PE). Because .NET binaries decompile cleanly, ILSpy lets the analyst read the malware's real logic — command-and-control endpoints, persistence routines, and encryption keys — without detonating it, then feed the extracted indicators (the `203.0.113.10` host, mutex names, registry keys) back into Security Onion as pivots and into detection rules. Recognizing de4dot-detected obfuscators (ConfuserEx, .NET Reactor) maps directly to ATT&CK **T1027 Obfuscated Files or Information** and helps triage whether a sample is commodity or bespoke. The recovered strings and IOCs become YARA and Suricata content that closes the detection loop across the estate.

## Attacker perspective
Attackers favor .NET for tradecraft because it loads reflectively in memory, integrates with LOLBins (`InstallUtil`, `regsvcs`, `msbuild`), and is easy to weaponize. To slow analysis they obfuscate assemblies with tools like ConfuserEx or .NET Reactor, renaming symbols to unprintable characters, encrypting string tables, and adding control-flow junk — the exact scrambling de4dot is built to reverse (ATT&CK **T1027**, **T1140 Deobfuscate/Decode Files or Information**). Even so, managed binaries leave rich artifacts a defender can find: metadata streams, PDB path leftovers, embedded resource blobs, GUIDs, and — after deobfuscation — plaintext C2 URLs and keys. The very portability that helps the attacker (readable IL, embedded config) is what makes ILSpy-driven analysis so effective at exposing them.

## Answer key
- Entry-point class: `Program`, entry method `Main` (from `ilspycmd -l c .\exercise\sample.exe`).
- Recovered constant / IOC: `http://203.0.113.10/beacon` (from decompiling `Main` / the `Marker` field).
- de4dot result on this sample: reports an **Unknown obfuscator** (the sample is not obfuscated) and still writes `sample-cleaned.exe`; the cleaned decompilation is identical, confirming the file is clean.
- Exact producing commands:
```powershell
ilspycmd -l c .\exercise\sample.exe        # lists type: Program
ilspycmd .\exercise\sample.exe | Select-String "203.0.113.10"   # shows the marker URL
de4dot -f .\exercise\sample.exe -o .\exercise\sample-cleaned.exe # cleaning pass
Get-FileHash .\exercise\sample.exe -Algorithm SHA256            # confirm sample identity
```
Sample identity: the SHA256 printed by the generator's `Get-FileHash` is the authoritative digest for the locally built `exercise/sample.exe` (deterministic for identical source/toolchain; record the value your build emits and store it in `exercise/sample.exe.sha256`).

## MITRE ATT&CK & DFIR phase
- **T1027** Obfuscated Files or Information — detecting/analysing obfuscated .NET assemblies (de4dot).
- **T1140** Deobfuscate/Decode Files or Information — recovering strings/logic prior to review.
- **T1059.001 / T1059** Command and Scripting Interpreter (managed payload execution context).
- DFIR phases: **Examination / Analysis** (static reverse engineering of the recovered artifact) and **Identification** (extracting IOCs for scoping).

## Sources
- ILSpy project (open-source .NET decompiler) — https://github.com/icsharpcode/ILSpy
- FLARE-VM tool set (ILSpy, de4dot-cex packages) — https://github.com/mandiant/flare-vm
- de4dot deobfuscator — https://github.com/de4dot/de4dot
- MITRE ATT&CK T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information — https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware (analysis methodology) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/