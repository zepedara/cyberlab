# 29 * .NET deobfuscation deep-dive -- LAB-WINDOWS

## Overview (plain language)
Many Windows programs are written in .NET languages like C# and compiled into an easy-to-read intermediate format (Common Intermediate Language, CIL/MSIL) instead of raw machine code. Because that format retains rich metadata (type names, method names) and is straightforward to decompile, criminals scramble ("obfuscate") their .NET malware to hide what it does — renaming everything to gibberish, encrypting text, and adding junk. The tools in this module reverse that scrambling. dnSpyEx lets you open a .NET program, read its recovered source code, and even debug it live. ILSpy is a fast, standalone decompiler for browsing that same code. de4dot automatically detects common obfuscators and cleans a file so it reads almost like the original source. Together they turn a confusing, garbled binary back into something a human can understand.

> Why .NET is "reversible": the .NET/CLI file format (ECMA-335) embeds a metadata tables stream and IL that decompilers can map back to high-level C#. See Microsoft Learn: <https://learn.microsoft.com/en-us/dotnet/standard/managed-code> and the ECMA-335 CLI spec: <https://ecma-international.org/publications-and-standards/standards/ecma-335/>.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| dnSpyEx | Included in FLARE-VM | .NET assembly decompiler, editor, and debugger for reading/patching managed code |
| ILSpy | Included in FLARE-VM | Standalone open-source .NET decompiler for browsing IL and reconstructed C# |
| de4dot | Included in FLARE-VM | Automated .NET deobfuscator/cleaner that detects and reverses common protectors |

Tool provenance / capability sources:
- dnSpyEx is the maintained fork of dnSpy; it is a decompiler, debugger, and assembly editor for .NET — see the repo README: <https://github.com/dnSpyEx/dnSpy>.
- ILSpy is the open-source .NET decompiler; the `ilspycmd` console front-end is distributed as a dotnet tool — see: <https://github.com/icsharpcode/ILSpy> and <https://github.com/icsharpcode/ILSpy/blob/master/README.md>.
- de4dot is an automated deobfuscator/unpacker for many .NET protectors — see: <https://github.com/de4dot/de4dot>.
- All three are packaged by Mandiant FLARE-VM; see the package list: <https://github.com/mandiant/VM-Packages> and installer: <https://github.com/mandiant/flare-vm>.

## Learning objectives
- Identify a .NET assembly and determine which obfuscator (if any) was applied using de4dot detection output.
- Produce a cleaned assembly with de4dot and confirm the reduction in obfuscation artifacts.
- Decompile both the original and cleaned assembly with ILSpy and dnSpyEx and compare readability.
- Locate a suspicious string or method in the recovered C# source and explain its behavior.

## Environment check
```powershell
# Confirm the three .NET RE tools are present on FLARE-VM.
# FLARE-VM installs these under the Desktop tools folder or PATH shims.
Get-Command dnSpy.exe   -ErrorAction SilentlyContinue | Select-Object Name, Source
Get-Command ILSpy.exe   -ErrorAction SilentlyContinue | Select-Object Name, Source
Get-Command de4dot.exe  -ErrorAction SilentlyContinue | Select-Object Name, Source

# Also verify the .NET runtime that assemblies target.
dotnet --info
```
Expected output: a `Name`/`Source` row for each of `dnSpy.exe`, `ILSpy.exe`, and `de4dot.exe`, and a `dotnet --info` banner listing installed SDK/runtime versions. If a `Get-Command` line returns nothing, launch the tool once from the FLARE-VM Start menu to register its path.

> Note on `ilspycmd`: the console decompiler is a separate executable from the ILSpy GUI. If `ilspycmd.exe` is not on PATH it can be installed as a .NET global tool (`dotnet tool install --global ilspycmd`), per the ILSpy README: <https://github.com/icsharpcode/ILSpy#ilspycmd>. The `dotnet --info` output format is documented at Microsoft Learn: <https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-info>.

## Guided walkthrough
1. Run de4dot in detection mode to fingerprint the protector without modifying the file. Running detect-only first is important during malware triage: you avoid touching (and potentially triggering anti-tamper logic in) the sample while you decide how to proceed.
```powershell
# -d = detect only. Reports the obfuscator name if recognized.
de4dot.exe -d .\exercise\sample.exe
```
Expected observable output: a line reporting the detected obfuscator (for recognized protectors such as ConfuserEx, .NET Reactor, Dotfuscator, etc.) or an "Unknown obfuscator" indication, plus the assembly full name. de4dot's obfuscator detection and supported-protector list are documented in the repo README: <https://github.com/de4dot/de4dot#detected-obfuscators>. Nuance: de4dot fingerprints by looking for the protector's characteristic runtime/helper types and metadata patterns, so a custom or updated obfuscator may read as "Unknown" even when the file is clearly obfuscated.

2. Clean the assembly. de4dot writes a new `-cleaned` file next to the input. Cleaning renames tokens back toward readable identifiers where possible, decrypts embedded strings, removes proxy-call/anti-debug junk, and rebuilds the assembly.
```powershell
de4dot.exe .\exercise\sample.exe
Get-ChildItem .\exercise\sample-cleaned.exe | Select-Object Name, Length
```
Expected observable output: de4dot logs its actions (loading, cleaning, and saving) and writes `sample-cleaned.exe`; the listing shows the new file with a size close to the original. Nuance: for a benign, un-obfuscated build the "cleaned" copy is essentially a round-trip rewrite and will look nearly identical — the value of this step only becomes obvious on genuinely protected samples. The default output-file naming convention (`-cleaned` suffix next to the input) is described in the de4dot README: <https://github.com/de4dot/de4dot#readme>.

3. Browse the cleaned assembly with the ILSpy command-line decompiler to dump C#. Dumping to files (rather than clicking through the GUI) makes the output greppable, diffable against the original, and easy to feed into detection-content workflows.
```powershell
# ilspycmd ships with ILSpy; -o writes decompiled source to a folder.
ilspycmd.exe -o .\exercise\decompiled .\exercise\sample-cleaned.exe
Get-ChildItem -Recurse .\exercise\decompiled\*.cs | Select-Object -First 5 FullName
```
Expected observable output: one or more `.cs` files under `exercise\decompiled\` containing readable class and method names. The `ilspycmd -o <dir>` option (project/source output) is documented in the ILSpy repo: <https://github.com/icsharpcode/ILSpy#ilspycmd>. Nuance: ILSpy reconstructs C# from IL, so recovered code is behaviorally equivalent but may differ from the original source (compiler-generated names, expanded iterators/async state machines, etc.).

4. Open the cleaned file interactively in dnSpyEx for method-level inspection and (optionally) debugging.
```powershell
Start-Process dnSpy.exe -ArgumentList ".\exercise\sample-cleaned.exe"
```
Expected observable output: the dnSpy GUI opens with the assembly tree on the left; expand namespaces to read decompiled C# with restored control flow. Nuance: dnSpyEx can set breakpoints and step through managed code at runtime, which lets you observe decrypted strings and dynamically resolved calls that never appear in static output — see the dnSpyEx debugging features in the README: <https://github.com/dnSpyEx/dnSpy#features>.

## Hands-on exercise
Work against the sample in this module's `exercise/` directory.

- **Sample type:** a benign .NET (C#) console executable, `sample.exe`, that prints a marker string and contains one Base64-encoded string constant.
- **Safe-origin note:** fully benign/inert. It performs NO network egress and NO file/registry writes — it only writes text to stdout. It is generated locally from source you control (below), so no live malware is ever downloaded.
- **Generator (reproducible build):** run this on FLARE-VM to build the exact sample, then compute its hash.
```powershell
# Create source
@'
using System;
using System.Text;
class Program {
    static void Main() {
        string enc = "TGFiRmxhZ3s1YW1wbGVfMjl9";  // Base64
        Console.WriteLine("benign dotnet deobf sample");
        Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(enc)));
    }
}
'@ | Set-Content -Encoding UTF8 .\exercise\Program.cs

# Compile with the .NET Framework C# compiler bundled on FLARE-VM
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" `
  /nologo /out:.\exercise\sample.exe .\exercise\Program.cs

Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
> The `csc.exe` command-line compiler and its `/out` and `/nologo` options are documented at Microsoft Learn: <https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/output#outputassembly> and <https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/miscellaneous#nologo>. `Convert.FromBase64String` / `Encoding.UTF8.GetString` behavior: <https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string> and <https://learn.microsoft.com/en-us/dotnet/api/system.text.encoding.utf8>. `Get-FileHash` (SHA256 default): <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash>.

**Tasks:**
1. Detect whether `sample.exe` is obfuscated using de4dot.
2. Decompile with ILSpy (`ilspycmd`) and locate the Base64 string constant.
3. Decode the Base64 value (CyberChef or PowerShell) and record the plaintext.
4. Confirm your understanding in dnSpyEx by finding the method that decodes and prints the string.

## SOC analyst perspective
Analysts see .NET malware constantly — droppers, RATs, and commodity stealers (e.g., AgentTesla, Formbook loaders, njRAT variants) frequently ship as managed assemblies wrapped in ConfuserEx or similar packers. When Security Onion surfaces an alert, the pulled binary lands on FLARE-VM for triage. Concrete pivots and detection logic:

- **Zeek** `files.log` provides `mime_type`, `md5`/`sha1`/`sha256`, and `filename` for objects carved off HTTP/SMB; a PE with a `.NET`/CLR header downloaded over an anomalous channel is your first pivot. Zeek file analysis reference: <https://docs.zeek.org/en/master/logs/files.html>.
- **Suricata** rules can flag the download or subsequent C2 beacon; alerts land in `alert` events consumable in Security Onion. See Suricata rule/alert docs: <https://docs.suricata.io/en/latest/rules/index.html> and Security Onion analyst tooling: <https://docs.securityonion.net/en/2.4/analyst-tools.html>.
- **Sysmon** Event ID 1 (Process Create) with `Image`/`CommandLine`/`Hashes`, and Event ID 3 (Network Connection) are the endpoint pivots forwarded into Elastic. Sysmon schema: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>.
- Once de4dot + ILSpy/dnSpyEx expose hard-coded **C2 URLs, mutex names, or decryption keys**, promote them to detection content: YARA rules over the file, Zeek intel-framework matches (<https://docs.zeek.org/en/master/frameworks/intel.html>) on the extracted domains/IPs, and Sysmon EID 3 / Suricata DNS filters for the C2.

Map recovered behavior to ATT&CK to drive fleet-wide hunts:
- **T1027 — Obfuscated Files or Information** (<https://attack.mitre.org/techniques/T1027/>): the obfuscated managed binary itself.
- **T1140 — Deobfuscate/Decode Files or Information** (<https://attack.mitre.org/techniques/T1140/>): runtime string/resource decryption you observe in dnSpyEx.
- **T1055 — Process Injection** (<https://attack.mitre.org/techniques/T1055/>): common in .NET loaders staging a second payload; hunt for cross-process access (Sysmon EID 8/10).
- **T1059.001 — Command and Scripting Interpreter: PowerShell** (<https://attack.mitre.org/techniques/T1059/001/>) frequently pairs with .NET droppers that spawn PowerShell.

**Detection Engineering Deep Dive:**
- **Zeek `files.log` pivot:** Look for `mime_type` containing `application/x-dosexec` and `analyzers` field containing `PE` and `CLR` (indicating a .NET assembly). The `sha256` can be used to pivot to VirusTotal or internal sandbox reports. This is documented in the Zeek file analysis framework: <https://docs.zeek.org/en/master/frameworks/file-analysis.html>.
- **Sysmon Event ID 1 detection:** A .NET assembly execution often spawns from `rundll32.exe`, `regsvr32.exe`, or `mshta.exe` (T1218). Look for `ParentImage` ending in one of those and `Image` ending in a suspicious name (e.g., `invoice.exe`). The `Hashes` field (SHA1, MD5, SHA256) can be matched against threat intel feeds. Sysmon Event ID 1 schema: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-create>.
- **Suricata rule logic:** Alert on HTTP POST requests with a `User-Agent` string containing `.NET CLR` or `Mono` to uncommon external IPs. Example Suricata rule keyword: `http.user_agent; content:".NET CLR";` within a rule targeting outbound C2 traffic. Suricata HTTP keyword documentation: <https://docs.suricata.io/en/latest/rules/http-keywords.html>.
- **MITRE ATT&CK T1564.001 — Hidden Files and Directories:** Obfuscated .NET binaries may be dropped in hidden directories (e.g., `AppData\Local\Temp\` with hidden attribute). Hunt for Sysmon Event ID 11 (FileCreate) where `TargetFilename` matches `*.exe` and the directory is hidden. MITRE technique: <https://attack.mitre.org/techniques/T1564/001/>.
- **MITRE ATT&CK T1574.001 — DLL Search Order Hijacking:** .NET malware often abuses DLL side-loading. Hunt for Sysmon Event ID 7 (Image loaded) where `ImageLoaded` is a non-Microsoft DLL loaded from a user-writable directory like `C:\Users\Public\`. MITRE technique: <https://attack.mitre.org/techniques/T1574/001/>.

## Attacker perspective
Adversaries obfuscate .NET payloads to slow analysis and evade signatures. Concrete TTPs and their artifacts:

- **Symbol renaming** to unreadable/Unicode tokens (**T1027**, <https://attack.mitre.org/techniques/T1027/>) — leaves anomalous, non-ASCII identifier tables in metadata that de4dot detects.
- **String encryption** with a runtime decryptor method — the encrypted blobs sit in `#Strings`/resource streams, but the plaintext is materialized in memory at runtime, so a dnSpyEx breakpoint on the decryptor dumps it (defeating the protection).
- **Control-flow flattening / proxy calls** — inflates method count and adds a dispatcher `switch`; de4dot's deobfuscation restores linear flow (<https://github.com/de4dot/de4dot#readme>).
- **Packing / embedded compressed payloads** (**T1027.002 — Software Packing**, <https://attack.mitre.org/techniques/T1027/002/>) — the CLR loader and compressed resource are themselves a detectable artifact.
- **Runtime string decoding at execution** maps to **T1140** (<https://attack.mitre.org/techniques/T1140/>).

Offensive counterparts to the cleaners here include ConfuserEx and .NET Reactor. Evasion focus is on breaking static signatures and tiring out analysts — but because .NET IL is inherently reversible (ECMA-335 metadata is required for the CLR to execute the code), none of these protections prevent recovery; they only add time. Detectable residue includes the obfuscator's own runtime helper types/metadata patterns (which de4dot fingerprints), unusual assembly attributes, and the sheer anomaly of a heavily-renamed managed binary on an endpoint. dnSpyEx live debugging can dump decrypted values on the fly, defeating string encryption entirely (<https://github.com/dnSpyEx/dnSpy#features>).

**Advanced Attacker TTPs:**
- **T1055.001 — Dynamic-link Library Injection:** .NET malware can inject a managed DLL into a remote process using Windows API calls like `CreateRemoteThread` and `LoadLibrary`. This leaves artifacts in Sysmon Event ID 8 (CreateRemoteThread) with a `StartAddress` pointing to `LoadLibrary` and a `SourceImage` that is a .NET executable. MITRE sub-technique: <https://attack.mitre.org/techniques/T1055/001/>.
- **T1562.001 — Disable or Modify Tools:** Obfuscators often include anti-debugging and anti-VM checks. These manifest as calls to `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, or WMI queries for virtual hardware. In dnSpyEx, look for methods with names like `AntiDebug` or `VMDetect`. MITRE sub-technique: <https://attack.mitre.org/techniques/T1562/001/>.
- **T1105 — Ingress Tool Transfer:** After deobfuscation, the payload may download additional modules. The deobfuscated code will reveal URLs and `WebClient` or `HttpClient` usage. This maps to MITRE technique T1105: <https://attack.mitre.org/techniques/T1105/>.
- **T1543.003 — Windows Service:** Some .NET malware installs itself as a service. The deobfuscated code may contain `ServiceBase` or `sc.exe` command-line arguments. Hunt for Sysmon Event ID 1 with `CommandLine` containing `sc create` or `binPath=` pointing to a suspicious .NET executable. MITRE sub-technique: <https://attack.mitre.org/techniques/T1543/003/>.

## Answer key
- **de4dot detection:** the generated `sample.exe` is **not obfuscated** — de4dot reports an unknown/none obfuscator and still emits `sample-cleaned.exe`. This is expected for the benign build; the workflow (detect → clean → decompile) is identical for real obfuscated samples.
```powershell
de4dot.exe -d .\exercise\sample.exe
```
- **String constant (ILSpy):** the source contains the Base64 literal `TGFiRmxhZ3s1YW1wbGVfMjl9`.
```powershell
ilspycmd.exe -o .\exercise\decompiled .\exercise\sample-cleaned.exe
Select-String -Path .\exercise\decompiled\*.cs -Pattern "TGFi"
```
- **Decoded plaintext:** `LabFlag{5ample_29}`
```powershell
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("TGFiRmxhZ3s1YW1wbGVfMjl9"))
```
- **Method (dnSpyEx):** `Program.Main` decodes the constant via `Convert.FromBase64String` + `Encoding.UTF8.GetString` and writes it with `Console.WriteLine`.
- **Sample integrity:** `sample.exe` is built by the generator above; verify with `Get-FileHash .\exercise\sample.exe -Algorithm SHA256`. Because compiler timestamps vary per build, treat the reproducible generator command as the authoritative sample definition and record the SHA256 it emits on your VM for your case notes.

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (identifying the protector): <https://attack.mitre.org/techniques/T1027/>.
- **T1027.002 — Software Packing** (packed/compressed .NET payloads): <https://attack.mitre.org/techniques/T1027/002/>.
- **T1140 — Deobfuscate/Decode Files or Information** (de4dot cleaning, Base64 decoding): <https://attack.mitre.org/techniques/T1140/>.
- **T1059.001 — Command and Scripting Interpreter: PowerShell** (analysis workflow context; common .NET dropper follow-on): <https://attack.mitre.org/techniques/T1059/001/>.
- **T1564.001 — Hidden Files and Directories** (obfuscated binaries dropped in hidden locations): <https://attack.mitre.org/techniques/T1564/001/>.
- **T1574.001 — DLL Search Order Hijacking** (abused by .NET malware for side-loading): <https://attack.mitre.org/techniques/T1574/001/>.
- **T1055.001 — Dynamic-link Library Injection** (managed DLL injection via .NET): <https://attack.mitre.org/techniques/T1055/001/>.
- **T1562.001 — Disable or Modify Tools** (anti-debug/anti-VM checks in obfuscators): <https://attack.mitre.org/techniques/T1562/001/>.
- **T1105 — Ingress Tool Transfer** (downloading additional modules post-deobfuscation): <https://attack.mitre.org/techniques/T1105/>.
- **T1543.003 — Windows Service** (installing as a service via .NET code): <https://attack.mitre.org/techniques/T1543/003/>.
- **DFIR phase:** examination / analysis (static and dynamic malware analysis of a recovered artifact), feeding identification and reporting.

## Sources
- dnSpyEx project (maintained fork of dnSpy; decompiler/debugger/editor + features): https://github.com/dnSpyEx/dnSpy
- ILSpy decompiler & `ilspycmd` (console `-o` output, global-tool install): https://github.com/icsharpcode/ILSpy
- de4dot .NET deobfuscator (detected obfuscators, `-d` detect mode, `-cleaned` output): https://github.com/de4dot/de4dot
- Mandiant FLARE-VM (tool distribution): https://github.com/mandiant/flare-vm
- Mandiant VM-Packages (package list confirming bundled tools): https://github.com/mandiant/VM-Packages
- Microsoft Learn — managed code / .NET overview: https://learn.microsoft.com/en-us/dotnet/standard/managed-code
- ECMA-335 Common Language Infrastructure (IL/metadata format): https://ecma-international.org/publications-and-standards/standards/ecma-335/
- Microsoft Learn — `dotnet --info`: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-info
- Microsoft Learn — C# compiler `/out` option: https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/output#outputassembly
- Microsoft Learn — C# compiler `/nologo` option: https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/miscellaneous#nologo
- Microsoft Learn — `Convert.FromBase64String`: https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string
- Microsoft Learn — `Encoding.UTF8`: https://learn.microsoft.com/en-us/dotnet/api/system.text.encoding.utf8
- Microsoft Learn — `Get-FileHash`: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- Microsoft Sysinternals — Sysmon (Event IDs 1/3/8/10/11, schema): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Zeek docs — `files.log` / file analysis: https://docs.zeek.org/en/master/logs/files.html
- Zeek docs — file analysis framework (PE/CLR detection): https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Zeek docs — Intelligence Framework: https://docs.zeek.org/en/master/frameworks/intel.html
- Suricata docs — rules & alerts: https://docs.suricata.io/en/latest/rules/index.html
- Suricata docs — HTTP keywords (User-Agent): https://docs.suricata.io/en/latest/rules/http-keywords.html
- Security Onion docs — analyst tools: https://docs.securityonion.net/en/2.4/analyst-tools.html
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 Software Packing: https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.001 Dynamic-link Library Injection: https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1059.001 PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1218 System Binary Proxy Execution: https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK T1543.003 Windows Service: https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK T1562.001 Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1564.001 Hidden Files and Directories: https://attack.mitre.org/techniques/T1564/001/
- MITRE ATT&CK T1574.001 DLL Search Order Hijacking: https://attack.mitre.org/techniques/T1574/001/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [.NET reverse engineering](../14-dotnet-re/README.md) -- shares de4dot for managed-code analysis workflows.
- [ILSpy .NET decompilation deep-dive](../45-ilspy-dotnet-deep/README.md) -- shares de4dot and expands on ILSpy decompilation.
- [Scenario: .NET malware analysis](../53-dotnet-malware-case/README.md) -- shares de4dot in an end-to-end case investigation.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- same learning path (Deep-dives) for complementary native-code RE.

<!-- cyberlab-enriched: v2 -->
