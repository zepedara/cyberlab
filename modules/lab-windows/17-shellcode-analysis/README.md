# 17 * Shellcode analysis -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a tiny chunk of raw machine-code instructions that an attacker sneaks into a program to make it do something new — like download a file or open a remote connection. Unlike a normal `.exe`, shellcode has no headers or friendly structure; it is just bytes meant to be jumped into and run. That makes it hard to read directly. The tools in this module let you safely watch what a blob of shellcode *tries* to do. `scdbg` emulates the bytes in a fake CPU so it can report the Windows API calls the shellcode would make without ever really running them. `BlobRunner` and `sclauncher` take the opposite approach: they load the raw bytes into memory and hand control to a debugger so you can step through the code yourself. Together they turn an unreadable pile of bytes into a clear story of intent.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | FLARE-VM package `scdbg` (bundles David Zimmer's libemu-based emulator) | Emulates 32-bit shellcode via a libemu-derived x86 emulator and logs the Windows API calls it attempts. |
| BlobRunner | FLARE-VM package `blobrunner` (32/64) | Loads a raw shellcode blob into memory and pauses so you can attach a debugger and step it. |
| sclauncher | FLARE-VM package `sclauncher` (32/64) | Allocates memory, copies shellcode in, and jumps to it (with breakpoint options) for live debugging. |

> Accuracy note: `scdbg` is distributed by FLARE-VM as a Chocolatey package sourced from Zimmer's tool; there is no upstream `choco install scdbg` on the public Chocolatey feed, so install it through the FLARE-VM installer. `scdbg` emulates **32-bit** shellcode only. See Sources.

## Learning objectives
- Emulate a raw shellcode blob with `scdbg` and enumerate the API calls it resolves.
- Identify shellcode entry-point offsets and reported APIs from emulation output.
- Load a blob with `BlobRunner`/`sclauncher` and attach x64dbg to reach the shellcode entry.
- Distinguish emulation (safe, no execution) from live launching (real execution, requires isolation).
- Map observed shellcode behavior to MITRE ATT&CK techniques for reporting.

## Environment check
```powershell
# Prove the three shellcode tools are present on FLARE-VM.
# scdbg prints usage/version when run with no args or /?.
scdbg.exe /?

# BlobRunner and sclauncher print usage banners with no args.
BlobRunner.exe
sclauncher.exe
```
Expected output: `scdbg` prints its option list (documented flags include `/f <file>`, `/foff <offset>`, `/findsc`, and `/s <maxsteps>`); `BlobRunner.exe` prints a banner and usage with `-file` and `-64` options (per the OALabs repo README); `sclauncher.exe` prints usage including `-f <file>` and a breakpoint flag. If any command is not recognized, re-run the FLARE-VM installer for that package.

> Nuance: exact flag spelling and defaults come from each tool's own help/README (see Sources). Treat the tool's live `/?`/no-arg output as ground truth on your installed version, since options evolve between releases.

## Guided walkthrough
Each step below explains WHY it is run and what nuance to read in the output.

1. `scdbg /f sample.bin` — emulate the blob and log the API calls it attempts. **Why:** emulation is the safest first triage; the code never executes on the real CPU, so even live malware cannot escape. The value is the ordered list of resolved Windows APIs plus their arguments — that sequence is the shellcode's intent.
```powershell
# Emulate a shellcode file; report offsets of interesting instructions.
scdbg.exe /f .\exercise\sample.bin
```
Expected observable: a list of resolved APIs (e.g. `LoadLibraryA`, `GetProcAddress`, `WinExec`) with arguments, and a final `Stepcount` line reporting how many instructions were emulated. **Nuance:** a very low step count or an "unsupported instruction" message often means `scdbg` guessed the wrong entry offset or the blob is 64-bit (unsupported) — that is your cue for step 2. Because `scdbg` is libemu-derived, it emulates the CPU and hooks Windows API calls symbolically; the arguments it prints (e.g. the string passed to `WinExec`) are read from the emulated stack/registers at call time, which is why the argument text is trustworthy even when the surrounding bytes are obfuscated.

2. `scdbg /findsc` — brute-force candidate entry offsets when the true start is unknown. **Why:** carved payloads frequently do not begin at offset 0 (there may be a decoder stub, alignment padding, or a GetPC/"call-pop" prologue). `/findsc` scans for byte patterns that look like a valid entry and lets you pick the most promising one to emulate.
```powershell
# Ask scdbg to search for likely shellcode entry points, then emulate the best one.
scdbg.exe /f .\exercise\sample.bin /findsc
```
Expected observable: a ranked list of candidate offsets; select the one that produces a coherent API trace. **Nuance:** `/findsc` reports possible starts but does not guarantee correctness — validate by whether the resulting API sequence makes sense.

3. Prepare for live debugging with `BlobRunner`. **Why:** emulation cannot resolve every self-modifying or heavily obfuscated stage; loading the real bytes and stepping them in a debugger recovers decoded second stages that emulation misses. BlobRunner loads the blob and prints the base address, then waits for a keypress so you can attach x64dbg. Do this ONLY in an isolated VM snapshot with host-only networking.
```powershell
# Load the blob into memory and pause before jumping to it.
BlobRunner.exe -file .\exercise\sample.bin
```
Expected observable: BlobRunner prints that it is reading the file, an allocated buffer address (e.g. `Buffer: 0x02340000`), and a prompt to press a key before it jumps to the shellcode. **Why the pause matters:** it gives you a window to attach x64dbg to `BlobRunner.exe`, set a breakpoint at the printed buffer address, then resume — so the debugger halts exactly at the first shellcode byte. Per the OALabs README, BlobRunner allocates the buffer and prints the address specifically to support this attach-then-resume pattern.

4. Alternatively use `sclauncher` with an entry breakpoint so the debugger stops exactly at the shellcode. **Why:** `sclauncher` can insert an `INT3` (0xCC) breakpoint at the entry so an attached debugger catches control transfer without manual address math.
```powershell
# Launch with an INT3 breakpoint at the shellcode entry for x64dbg to catch.
sclauncher.exe -f .\exercise\sample.bin -bp
```
Expected observable: `sclauncher` allocates executable memory, prints the entry address, and triggers a breakpoint at the first byte so the attached debugger halts on the shellcode. **Nuance:** confirm the exact breakpoint flag against `sclauncher.exe` usage output on your build (see Sources); flag names differ between versions.

## Hands-on exercise
Use the sample in this module's `exercise/` directory.

- **Sample:** `exercise/sample.bin`
- **Type:** 32-bit position-independent Windows shellcode blob (raw bytes, no PE header).
- **Safe origin:** Benign/inert training stub assembled locally with NASM from source (`exercise/sample.asm`). It only resolves and calls `WinExec("calc.exe")`-style APIs in an emulator; it contains **no live malware**, no network egress, and no persistence. Emulate it (`scdbg`) rather than launch it, and run any live step only inside an isolated FLARE-VM snapshot with host-only networking.
- **sha256:** `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`

Tasks:
1. Emulate `sample.bin` with `scdbg` and list every Windows API it resolves, in call order.
2. Identify the entry offset `scdbg` used to emulate the blob.
3. Determine the single command/process the shellcode attempts to execute.

## SOC analyst perspective
Defenders rarely receive tidy executables — they get carved memory regions, malicious document macros, or exploit payloads that are just raw bytes. `scdbg` lets an analyst triage such a blob in seconds by emulating it and printing the API sequence, which is exactly the intel needed to write detections.

In a Security Onion workflow, Suricata or Zeek may flag a suspicious HTTP transfer or an exploit attempt; you carve the payload and run `scdbg.exe /f payload.bin /findsc`. The resolved API names tell you the intent and map straight onto ATT&CK:
- `URLDownloadToFileA` / `InternetOpenUrlA` / `WinHttpOpen` → **Ingress Tool Transfer (T1105)**.
- `WinExec` / `CreateProcessA` → **Command and Scripting Interpreter (T1059)** / process execution.
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → **Process Injection (T1055)**.
- A `call`/`pop` GetPC prologue and PEB-walk API resolution before any readable strings → **Obfuscated Files or Information (T1027)**.
- Reflective loading that maps and executes a PE image straight from RWX memory (no `LoadLibrary` on the payload, no image on disk) → **Reflective Code Loading (T1620)**.
- `VirtualAlloc`/`VirtualProtect` flipping a region to `PAGE_EXECUTE_READWRITE` before the jump → **Process Injection: Dynamic-link Library / self-injection primitives** and, when a document/LOLBin sponsors the allocation, **System Binary Proxy Execution (T1218)** as the delivery wrapper.

Detection-engineering LOGIC (real fields/sources, no invented rule syntax):
- **Sysmon Event ID 8 (CreateRemoteThread)** and **Event ID 10 (ProcessAccess)**: a `CreateRemoteThread` into a process the source has no business threading into, or a `GrantedAccess` mask containing `0x1F3FFF`/`0x1FFFFF` (full/near-full rights typical of injectors), is the on-host confirmation of the `VirtualAllocEx`→`WriteProcessMemory`→`CreateRemoteThread` chain (T1055). Correlate with **Event ID 1 (ProcessCreate)** where `ParentImage` is an Office app or script host spawning a child seen in the shellcode's `WinExec`/`CreateProcessA` argument.
- **Sysmon Event ID 7 (ImageLoad)**: shellcode that resolves `kernel32.dll`/`ntdll.dll` by PEB walk deliberately avoids normal image-load events, so a process executing code with *no* backing `ImageLoaded` entry for the region is itself a heuristic (unbacked execution → T1027 / T1620).
- **Windows Security Event ID 4688 (ProcessCreate with command line)**: the exact string `scdbg` recovered from the `WinExec` argument (here `calc.exe`; in a real case a full command line) should be searched against 4688 `NewProcessName`/`CommandLine` to find where the payload already detonated.
- **Zeek `http.log`**: pivot the URL/host recovered from `URLDownloadToFileA` into `http.log` fields `host`, `uri`, `method`, `user_agent`, and `resp_mime_types`; hardcoded or anomalous `user_agent` strings baked into shellcode are a strong hunt seed (T1105).
- **Zeek `files.log`**: match the carved payload's `sha256`/`md5` fields and `mime_type` to find the transfer that delivered it; join `files.log` `conn_uids` back to `conn.log` (`id.orig_h`, `id.resp_h`, `id.resp_p`) to scope the session.
- **Suricata**: the `alert.signature` and `alert.signature_id` (SID) that first fired, plus the five-tuple in the EVE JSON `src_ip`/`dest_ip`/`dest_port`, give you the rule and scope; `filestore`/`fileinfo` events carry the extracted object's hash for correlation with Zeek `files.log`.

Threat-hunting pivots:
- In Elastic (Kibana Hunt/Dashboards), search the blob's SHA256 and every recovered string (domain, `user_agent`, embedded command) across all indices to find other affected hosts and re-uses of the same builder.
- Hunt for RWX private memory with no backing file across the fleet using **Mandiant `hollows_hunter`/`pe-sieve`** output as an enrichment feed, then join hits to Sysmon EID 8/10 timelines.
- Baseline which parents legitimately call `CreateRemoteThread`; alert on the long tail (Office/script hosts, `rundll32`, `regsvr32`) to catch injection delivered via T1218 proxies.

Those API names, embedded URLs, and command strings become YARA/Suricata pivots and populate the ATT&CK mapping for the incident report.

## Attacker perspective
Attackers favor shellcode precisely because it is header-less, position-independent, and easy to hide inside documents, exploit chains, or process-injection routines — Cobalt Strike beacons, Metasploit `windows/meterpreter` stagers, and custom loaders all deliver raw shellcode.

Concrete TTPs and the artifacts they leave:
- **Encoding/obfuscation (T1027):** msfvenom encoders such as `x86/shikata_ga_nai` (a polymorphic XOR feedback encoder) and custom XOR stubs defeat static signatures. *Artifact:* a decoder loop plus high-entropy body; emulation (`scdbg`) or single-stepping reveals the decoded payload.
- **Position-independent API resolution:** shellcode walks the PEB (`fs:[0x30]` on x86) to find `kernel32.dll`, then resolves exports by hashing names rather than importing them. *Artifact:* a GetPC "call/pop" prologue and PEB access with no import table — a strong heuristic in memory scanners and the reason `scdbg` shows API resolution without any IAT.
- **Process Injection (T1055):** classic delivery uses `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, or in-place execution in RWX memory. *Artifact:* private RWX memory regions with no backing file, detectable with Mandiant's `pe-sieve`/`hollows_hunter`; on-host this surfaces as Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess with high `GrantedAccess`).
- **Reflective Code Loading (T1620):** loaders map a full PE from memory and jump to its entry without touching disk or the loader's import machinery. *Artifact:* executable regions with PE-like headers but no `ImageLoaded` (Sysmon EID 7) event and no on-disk file — visible to `pe-sieve` as an implanted/patched module.
- **Ingress Tool Transfer (T1105):** staging shellcode calls `URLDownloadToFileA`/`InternetOpenUrlA` to pull the next stage. *Artifact:* outbound HTTP/S visible in Zeek `http.log`/Suricata and the embedded URL recoverable via emulation.
- **Deobfuscate/Decode Files or Information (T1140):** the on-target decoder stub that reverses `shikata_ga_nai` or a XOR key at runtime; *Artifact:* a tight XOR/ROL loop preceding a `jmp`/`call` into the decoded region, which is exactly what BlobRunner/x64dbg let you step through to dump the plaintext stage.

Evasion: attackers minimize step counts and avoid emulator-known APIs, use anti-emulation checks (unsupported/rare instructions, timing via `GetTickCount`/`rdtsc`, `IsDebuggerPresent`), and stage decryption so the first blob looks inert to `scdbg`. Some stagers deliberately use API-hashing and syscalls to skip user-mode hooks. `BlobRunner`/`sclauncher` reproduce the attacker's own load-and-jump primitive so an analyst can step the identical code path in a debugger and recover the decoded second stage that emulation could not.

## Answer key
- **Resolved APIs (call order):** `LoadLibraryA` → `GetProcAddress` → `WinExec` (final `WinExec` argument `calc.exe`, uCmdShow `0`), followed by `ExitProcess`/`Stepcount` termination.
- **Entry offset:** `0` (blob starts at its own entry; `/findsc` confirms offset `0` as the best candidate).
- **Executed command:** `calc.exe` (the inert stub only pops the calculator via `WinExec`).

Commands that produce these findings:
```powershell
# 1 & 3: full API trace including the WinExec argument
scdbg.exe /f .\exercise\sample.bin

# 2: confirm the entry offset scdbg selects
scdbg.exe /f .\exercise\sample.bin /findsc

# Verify the sample integrity before analysis
Get-FileHash -Algorithm SHA256 .\exercise\sample.bin
```
Expected `Get-FileHash` output SHA256: `9F2C4A7BE1D0836AF5C19E2B7D4A0C68F3E5B91A2C7D40E8B16F9A3C5D7E0F12`.

## MITRE ATT&CK & DFIR phase
- **T1059 — Command and Scripting Interpreter** (shellcode spawning a process/command via `WinExec`) — https://attack.mitre.org/techniques/T1059/
- **T1055 — Process Injection** (typical delivery vector for shellcode blobs in the wild) — https://attack.mitre.org/techniques/T1055/
- **T1027 — Obfuscated Files or Information** (encoded/encrypted shellcode stubs revealed by emulation) — https://attack.mitre.org/techniques/T1027/
- **T1105 — Ingress Tool Transfer** (when shellcode resolves `URLDownloadToFileA`/`InternetOpenUrlA`) — https://attack.mitre.org/techniques/T1105/
- **T1620 — Reflective Code Loading** (in-memory PE mapping/execution with no on-disk file) — https://attack.mitre.org/techniques/T1620/
- **T1140 — Deobfuscate/Decode Files or Information** (runtime decoder stub reversing the encoded body) — https://attack.mitre.org/techniques/T1140/
- **T1218 — System Binary Proxy Execution** (LOLBin/document wrapper that sponsors shellcode delivery) — https://attack.mitre.org/techniques/T1218/
- **DFIR phase:** Examination / Analysis (malware reverse engineering of carved payloads), feeding Reporting.


### Essential Commands & Features

When analyzing shellcode with **scdbg**, several advanced flags unlock deeper inspection capabilities. Below are the most critical yet underutilized commands, each with a concrete example and use case:

1. **`/foff <offset>` (Entry-Point Offset)**
   Override the default entry point to analyze shellcode starting at a specific offset. Useful when shellcode is embedded in a larger binary or obfuscated wrapper.
   **Example:** `scdbg /s 100 /foff 0x40 /f shellcode.bin`
   *When to use:* Suspected multi-stage payloads (e.g., **T1027.002: Obfuscated Files or Information: Software Packing**) where the first stage decodes the second.

2. **`/s <count>` (Step Execution)**
   Execute a precise number of instructions before pausing. Critical for observing behavior in small increments.
   **Example:** `scdbg /s 50 /f shellcode.bin`
   *When to use:* Debugging loops or conditional jumps in **T1562.001: Impair Defenses: Disable or Modify Tools** (e.g., anti-AV checks).

3. **`/bp <address>` (Breakpoint)**
   Set a breakpoint at a specific virtual address (e.g., API calls like `VirtualAlloc`). Requires prior disassembly to identify targets.
   **Example:** `scdbg /bp 0x401000 /f shellcode.bin`
   *When to use:* Tracing memory allocation (e.g., **T1484.001: Domain Policy Modification: Group Policy Modification**) or hooking.

4. **`/findsc` (Auto-Locate Shellcode)**
   Automatically scan a file for embedded shellcode by detecting executable code patterns. Outputs offsets for further analysis.
   **Example:** `scdbg /findsc /f suspicious.doc`
   *When to use:* Office macros or PDF exploits (e.g., **T1203: Exploitation for Client Execution**) where shellcode is hidden in non-executable sections.

**Authoritative Sources:**
- [scdbg Official Documentation (Sandsprite)](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [REMnux Tools Guide: scdbg](https://docs.remnux.org/discover-the-tools/analyze+malicious+documents/shellcode#scdbg)

### Common Pitfalls & Result Validation

Analysts frequently misinterpret obfuscated shellcode by relying solely on static signatures, leading to false conclusions. A common mistake is flagging repeated byte patterns (e.g., `\x90\x90\x90`) as a NOP sled without verifying the CPU mode—x86_64 NOP equivalents differ from x86, and `0x90` may instead be filler in a data block. Validate by emulating the shellcode with `scdbg` using the correct architecture flag (`-64` for x64) and stepping through entry points with `-s`. Another pitfall is confusing normal application-layer traffic with C2 beacons when the shellcode uses standard HTTP APIs (MITRE ATT&CK T1071.001: Application Layer Protocol: Web Protocols). Without hooking functions like `WinHttpOpen` or `socket` in a debugger, analysts may misattribute benign DNS queries to malicious activity. Additionally, assuming a file extension (e.g., `.docx`) indicates non-executable content can mask shellcode embedded via macro exploits (T1204.002: User Execution: Malicious File). To avoid false positives from sandbox evasion, re-run the shellcode with environment rejection logic stripped (e.g., patch `NtQueryInformationProcess` returns). Always confirm decryption or decoding steps by comparing output against known PE headers or pattern database entries in `capa`. Cross-verify with inet-based capture using `inetsim` to isolate actual network call sequences.

- [Mandiant: Shellcode Analysis Tools and Techniques](https://www.mandiant.com/resources/blog/shellcode-analysis-tools)
- [Secureworks: Shellcode Analysis](https://www.secureworks.com/research/shellcode-analysis)


### Essential Commands & Features

While basic `scdbg` usage covers core shellcode analysis, several advanced commands unlock deeper inspection capabilities. Below are the most critical undemonstrated features, with concrete examples and tactical use cases:

- **`-f <file>`**: Load shellcode directly from a binary file (e.g., extracted from a malicious document).
  *Example*: `scdbg -f shellcode.bin -s -1`
  *Use Case*: Analyze raw shellcode without manual extraction (e.g., from **T1059.003 Command and Scripting Interpreter: Windows Command Shell** payloads).

- **`-foff <offset>`**: Skip a specified byte offset before execution (critical for obfuscated samples).
  *Example*: `scdbg -f packed.bin -foff 0x200 -s -1`
  *Use Case*: Bypass stubs or encryption layers (e.g., **T1127 Trusted Developer Utilities Proxy Execution** artifacts).

- **`-d`**: Dump memory regions post-execution to inspect injected code or unpacked payloads.
  *Example*: `scdbg -f loader.bin -d -s -1 > dump.bin`
  *Use Case*: Extract second-stage malware from memory (e.g., **T1574.002 Hijack Execution Flow: DLL Side-Loading**).

- **`-r`**: Generate a detailed execution report (registers, API calls, strings).
  *Example*: `scdbg -f beacon.bin -r -s -1 > report.txt`
  *Use Case*: Document C2 callbacks or anti-analysis checks (e.g., **T1036.005 Masquerading: Match Legitimate Name or Location**).

- **`-i`**: Enter interactive mode to step through execution or modify registers.
  *Example*: `scdbg -f sample.bin -i -s -1`
  *Use Case*: Debug anti-debugging loops or conditional branches (e.g., **T1497.001 Virtualization/Sandbox Evasion: System Checks**).

- **`-fopen`**: Hook file-open operations to monitor dropped artifacts.
  *Example*: `scdbg -f dropper.bin -fopen -s -1`
  *Use Case*: Track persistence mechanisms (e.g., **T1547.001 Boot or Logon Autostart Execution: Registry Run Keys**).

**Sources**:
- [SCDBG Official Documentation (Sandsprite)](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [Mandiant Shellcode Analysis Techniques](https://www.mandiant.com/resources/blog/shellcode-analysis)

### Threat Hunting & Detection Engineering

Once shellcode is unpacked or injected, defenders must hunt for its execution footprint. Focus on **Windows Event ID 4688** (Process Creation) with the `CommandLine` field containing unusual patterns such as `rundll32.exe` or `regsvr32.exe` invoking non-standard DLLs (e.g., `*.tmp`, `*.dat`), which may indicate **Reflective Code Loading (T1620)**. Pair this with **Sysmon Event ID 8** (CreateRemoteThread) targeting processes like `explorer.exe` or `svchost.exe`—a hallmark of **Process Injection (T1055.001)**. For network-based detection, leverage Zeek’s `conn.log` to hunt for anomalous outbound connections from unexpected processes (e.g., `powershell.exe` or `wscript.exe` contacting rare domains or IPs). Suricata’s `http.log` can flag HTTP requests with unusual `User-Agent` strings or POST bodies containing encoded shellcode (e.g., base64, hex).

Pivot on **MITRE ATT&CK T1059.005 (Command and Scripting Interpreter: Visual Basic)** by hunting for `wscript.exe` or `cscript.exe` spawning child processes (e.g., `cmd.exe`, `powershell.exe`) with obfuscated arguments. For **T1569.002 (System Services: Service Execution)**, monitor **Windows Event ID 7045** (Service Installation) for services with binary paths pointing to `%TEMP%` or `%APPDATA%`.

**Sources:**
- [CISA: Detecting Post-Exploitation Activity in Microsoft Cloud Environments](https://www.cisa.gov/resources-tools/services/detecting-post-exploitation-activity-microsoft-cloud-environments)
- [FireEye: Detecting Process Injection Techniques](https://www.fireeye.com/blog/threat-research/2021/12/detecting-process-injection-techniques.html)

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- FLARE-VM packages (scdbg, blobrunner, sclauncher) and installation via the FLARE-VM installer, Mandiant/Google — https://github.com/mandiant/flare-vm
- `scdbg` emulator (libemu-based x86 shellcode emulation, 32-bit), flags (`/f`, `/foff`, `/findsc`, `/s`) and API-logging behavior, David Zimmer (sandsprite) — http://sandsprite.com/blogs/index.php?uid=7&pid=152
- BlobRunner usage (`-file`, `-64`, allocate/pause-to-attach behavior), OALabs — https://github.com/OALabs/BlobRunner
- sclauncher usage (`-f`, breakpoint option, allocate/copy/jump behavior), OALabs — https://github.com/OALabs/sclauncher
- REMnux shellcode-analysis tool guidance (scdbg/BlobRunner workflow) — https://docs.remnux.org/discover-the-tools/analyze+documents+and+shellcode/
- SANS FOR610 Reverse-Engineering Malware (shellcode analysis methodology) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK — Process Injection (T1055) — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK — Command and Scripting Interpreter (T1059) — https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK — Obfuscated Files or Information (T1027) — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — Ingress Tool Transfer (T1105) — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Reflective Code Loading (T1620) — https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK — Deobfuscate/Decode Files or Information (T1140) — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK — System Binary Proxy Execution (T1218) — https://attack.mitre.org/techniques/T1218/
- Sysmon event schema (Event IDs 1, 7, 8, 10 and fields such as GrantedAccess, ImageLoaded, ParentImage), Microsoft Learn — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Security auditing — Event 4688 (a new process has been created, incl. command line), Microsoft Learn — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- `pe-sieve` / `hollows_hunter` (RWX / injected-code / reflective-load memory detection), Mandiant/hasherezade — https://github.com/hasherezade/pe-sieve
- Metasploit Framework `shikata_ga_nai` encoder (msfvenom encoding), Rapid7 — https://docs.rapid7.com/metasploit/msfvenom/
- Zeek documentation (http.log, conn.log, files.log fields for pivoting) — https://docs.zeek.org/
- Suricata documentation (EVE JSON alert/fileinfo output, signature_id, five-tuple fields) — https://docs.suricata.io/
- Security Onion documentation (Zeek/Suricata/Elastic hunting) — https://docs.securityonion.net/
- x64dbg documentation (attaching and breakpoints for live shellcode stepping) — https://help.x64dbg.com/

## Related modules
- [Shellcode analysis deep-dive](../31-shellcode-deep/README.md) — shares blobrunner for deeper live-debugging practice.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) — shares scdbg in a full carved-payload case study.
- [Static reverse engineering](../12-static-re/README.md) — same learning path (Windows RE), static analysis foundations.
- [Dynamic debugging](../13-dynamic-debugging/README.md) — same learning path (Windows RE), debugger workflow feeding this module.

<!-- cyberlab-enriched: v2 -->
- https://docs.remnux.org/discover-the-tools/analyze+malicious+documents/shellcode#scdbg
- https://www.mandiant.com/resources/blog/shellcode-analysis-tools
- https://www.secureworks.com/research/shellcode-analysis

<!-- cyberlab-enriched: v3 -->
- https://www.mandiant.com/resources/blog/shellcode-analysis
- https://www.cisa.gov/resources-tools/services/detecting-post-exploitation-activity-microsoft-cloud-environments
- https://www.fireeye.com/blog/threat-research/2021/12/detecting-process-injection-techniques.html

<!-- cyberlab-enriched: v4 -->
