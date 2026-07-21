# 17 * Shellcode analysis -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a tiny chunk of raw machine-code instructions that an attacker sneaks into a program to make it do something new — like download a file or open a remote connection. Unlike a normal `.exe`, shellcode has no headers or friendly structure; it is just bytes meant to be jumped into and run. That makes it hard to read directly. The tools in this module let you safely watch what a blob of shellcode *tries* to do. `scdbg` emulates the bytes in a fake CPU so it can report the Windows API calls the shellcode would make without ever really running them. `BlobRunner` and `sclauncher` take the opposite approach: they load the raw bytes into memory and hand control to a debugger so you can step through the code yourself. Together they turn an unreadable pile of bytes into a clear story of intent.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | FLARE-VM package `scdbg` (bundles David Zimmer's libemu-based emulator) | Emulates 32-bit shellcode via a libemu-derived x86 emulator and logs the Windows API calls it attempts. [Source: Sandsprite scdbg docs](http://sandsprite.com/blogs/index.php?uid=7&pid=152) |
| BlobRunner | FLARE-VM package `blobrunner` (32/64) | Loads a raw shellcode blob into memory and pauses so you can attach a debugger and step it. [Source: OALabs BlobRunner README](https://github.com/OALabs/BlobRunner) |
| sclauncher | FLARE-VM package `sclauncher` (32/64) | Allocates memory, copies shellcode in, and jumps to it (with breakpoint options) for live debugging. [Source: FLARE-VM sclauncher package](https://github.com/fireeye/flare-vm) |

> Accuracy note: `scdbg` is distributed by FLARE-VM as a Chocolatey package sourced from Zimmer's tool; there is no upstream `choco install scdbg` on the public Chocolatey feed, so install it through the FLARE-VM installer. `scdbg` emulates **32-bit** shellcode only. See [Sandsprite scdbg documentation](http://sandsprite.com/blogs/index.php?uid=7&pid=152).

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
Expected output: `scdbg` prints its option list (documented flags include `/f <file>`, `/foff <offset>`, `/findsc`, and `/s <maxsteps>`); `BlobRunner.exe` prints a banner and usage with `-file` and `-64` options (per the [OALabs repo README](https://github.com/OALabs/BlobRunner)); `sclauncher.exe` prints usage including `-f <file>` and a breakpoint flag. If any command is not recognized, re-run the FLARE-VM installer for that package.

> Nuance: exact flag spelling and defaults come from each tool's own help/README (see Sources). Treat the tool's live `/?`/no-arg output as ground truth on your installed version, since options evolve between releases.

## Guided walkthrough
Each step below explains WHY it is run and what nuance to read in the output.

1. `scdbg /f sample.bin` — emulate the blob and log the API calls it attempts. **Why:** emulation is the safest first triage; the code never executes on the real CPU, so even live malware cannot escape. The value is the ordered list of resolved Windows APIs plus their arguments — that sequence is the shellcode's intent.
```powershell
# Emulate a shellcode file; report offsets of interesting instructions.
scdbg.exe /f .\exercise\sample.bin
```
Expected observable: a list of resolved APIs (e.g. `LoadLibraryA`, `GetProcAddress`, `WinExec`) with arguments, and a final `Stepcount` line reporting how many instructions were emulated. **Nuance:** a very low step count or an "unsupported instruction" message often means `scdbg` guessed the wrong entry offset or the blob is 64-bit (unsupported) — that is your cue for step 2. Because `scdbg` is libemu-derived, it emulates the CPU and hooks Windows API calls symbolically; the arguments it prints (e.g. the string passed to `WinExec`) are read from the emulated stack/registers at call time, which is why the argument text is trustworthy even when the surrounding bytes are obfuscated. [Source: Sandsprite scdbg docs](http://sandsprite.com/blogs/index.php?uid=7&pid=152)

2. `scdbg /findsc` — brute-force candidate entry offsets when the true start is unknown. **Why:** carved payloads frequently do not begin at offset 0 (there may be a decoder stub, alignment padding, or a GetPC/"call-pop" prologue). `/findsc` scans for byte patterns that look like a valid entry and lets you pick the most promising one to emulate.
```powershell
# Ask scdbg to search for likely shellcode entry points, then emulate the best one.
scdbg.exe /f .\exercise\sample.bin /findsc
```
Expected observable: a ranked list of candidate offsets; select the one that produces a coherent API trace. **Nuance:** `/findsc` reports possible starts but does not guarantee correctness — validate by whether the resulting API sequence makes sense. [Source: Sandsprite scdbg docs](http://sandsprite.com/blogs/index.php?uid=7&pid=152)

3. Prepare for live debugging with `BlobRunner`. **Why:** emulation cannot resolve every self-modifying or heavily obfuscated stage; loading the real bytes and stepping them in a debugger recovers decoded second stages that emulation misses. BlobRunner loads the blob and prints the base address, then waits for a keypress so you can attach x64dbg. Do this ONLY in an isolated VM snapshot with host-only networking.
```powershell
# Load the blob into memory and pause before jumping to it.
BlobRunner.exe -file .\exercise\sample.bin
```
Expected observable: BlobRunner prints that it is reading the file, an allocated buffer address (e.g. `Buffer: 0x02340000`), and a prompt to press a key before it jumps to the shellcode. **Why the pause matters:** it gives you a window to attach x64dbg to `BlobRunner.exe`, set a breakpoint at the printed buffer address, then resume — so the debugger halts exactly at the first shellcode byte. Per the [OALabs README](https://github.com/OALabs/BlobRunner), BlobRunner allocates the buffer and prints the address specifically to support this attach-then-resume pattern.

4. Alternatively use `sclauncher` with an entry breakpoint so the debugger stops exactly at the shellcode. **Why:** `sclauncher` can insert an `INT3` (0xCC) breakpoint at the entry so an attached debugger catches control transfer without manual address math.
```powershell
# Launch with an INT3 breakpoint at the shellcode entry for x64dbg to catch.
sclauncher.exe -f .\exercise\sample.bin -bp
```
Expected observable: `sclauncher` allocates executable memory, prints the entry address, and triggers a breakpoint at the first byte so the attached debugger halts on the shellcode. **Nuance:** confirm the exact breakpoint flag against `sclauncher.exe` usage output on your build (see [FLARE-VM sclauncher package](https://github.com/fireeye/flare-vm)); flag names differ between versions.

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
- `URLDownloadToFileA` / `InternetOpenUrlA` / `WinHttpOpen` → **Ingress Tool Transfer (T1105)**. [Source: MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- `WinExec` / `CreateProcessA` → **Command and Scripting Interpreter (T1059)** / process execution. [Source: MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → **Process Injection (T1055)**. [Source: MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
  - **T1055.001 — Dynamic-link Library Injection** (when shellcode injects a DLL into a remote process). [Source: MITRE ATT&CK T1055/001](https://attack.mitre.org/techniques/T1055/001/)
  - **T1055.012 — Process Hollowing** (when shellcode replaces a legitimate process's memory). [Source: MITRE ATT&CK T1055/012](https://attack.mitre.org/techniques/T1055/012/)
- A `call`/`pop` GetPC prologue and PEB-walk API resolution before any readable strings → **Obfuscated Files or Information (T1027)**. [Source: MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- Reflective loading that maps and executes a PE image straight from RWX memory (no `LoadLibrary` on the payload, no image on disk) → **Reflective Code Loading (T1620)**. [Source: MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)
- `VirtualAlloc`/`VirtualProtect` flipping a region to `PAGE_EXECUTE_READWRITE` before the jump → **Process Injection: Dynamic-link Library / self-injection primitives** and, when a document/LOLBin sponsors the allocation, **System Binary Proxy Execution (T1218)** as the delivery wrapper. [Source: MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/)
- Shellcode that deletes the original file or cleans up artifacts after execution → **Indicator Removal: File Deletion (T1070.004)**. (E.g., if the sample called `DeleteFileA` on the source document.) [Source: MITRE ATT&CK T1070/004](https://attack.mitre.org/techniques/T1070/004/)
- Shellcode that enumerates running processes to find a target for injection → **Process Discovery (T1057)**. (E.g., calling `CreateToolhelp32Snapshot`/`Process32FirstW`.) [Source: MITRE ATT&CK T1057](https://attack.mitre.org/techniques/T1057/)
- Shellcode that modifies file timestamps to cover tracks → **Indicator Removal: Timestomp (T1070.006)**. (E.g., calling `SetFileTime`.) [Source: MITRE ATT&CK T1070/006](https://attack.mitre.org/techniques/T1070/006/)

Detection-engineering LOGIC (real fields/sources, no invented rule syntax):
- **Sysmon Event ID 8 (CreateRemoteThread)** and **Event ID 10 (ProcessAccess)**: a `CreateRemoteThread` into a process the source has no business threading into, or a `GrantedAccess` mask containing `0x1F3FFF`/`0x1FFFFF` (full/near-full rights typical of injectors), is the on-host confirmation of the `VirtualAllocEx`→`WriteProcessMemory`→`CreateRemoteThread` chain (T1055). Correlate with **Event ID 1 (ProcessCreate)** where `ParentImage` is an Office app or script host spawning a child seen in the shellcode's `WinExec`/`CreateProcessA` argument. [Source: Microsoft Sysmon Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Sysmon Event ID 7 (ImageLoad)**: shellcode that resolves `kernel32.dll`/`ntdll.dll` by PEB walk deliberately avoids normal image-load events, so a process executing code with *no* backing `ImageLoaded` entry for the region is itself a heuristic (unbacked execution → T1027 / T1620). [Source: Microsoft Sysmon Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Windows Security Event ID 4688 (ProcessCreate with command line)**: the exact string `scdbg` recovered from the `WinExec` argument (here `calc.exe`; in a real case a full command line) should be searched against 4688 `NewProcessName`/`CommandLine` to find where the payload already detonated. [Source: Microsoft Security Auditing Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- **Sysmon Event ID 11 (FileCreate)**: if the shellcode writes a secondary payload to disk (e.g., `CreateFileA`/`WriteFile`), monitor for files created in unusual locations like `%TEMP%` or `%APPDATA%` with executable extensions. [Source: Microsoft Sysmon Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Zeek `http.log`**: pivot the URL/host recovered from `URLDownloadToFileA` into `http.log` fields `host`, `uri`, `method`, `user_agent`, and `resp_mime_types`; hardcoded or anomalous `user_agent` strings baked into shellcode are a strong hunt seed (T1105). [Source: Zeek Documentation](https://docs.zeek.org/en/master/logs/http.html)
- **Zeek `files.log`**: match the carved payload's `sha256`/`md5` fields and `mime_type` to find the transfer that delivered it; join `files.log` `conn_uids` back to `conn.log` (`id.orig_h`, `id.resp_h`, `id.resp_p`) to scope the session. [Source: Zeek Documentation](https://docs.zeek.org/en/master/logs/files.html)
- **Suricata**: the `alert.signature` and `alert.signature_id` (SID) that first fired, plus the five-tuple in the EVE JSON `src_ip`/`dest_ip`/`dest_port`, give you the rule and scope; `filestore`/`fileinfo` events carry the extracted object's hash for correlation with Zeek `files.log`. [Source: Suricata Documentation](https://suricata.readthedocs.io/en/suricata-6.0.0/)

Threat-hunting pivots:
- In Elastic (Kibana Hunt/Dashboards), search the blob's SHA256 and every recovered string (domain, `user_agent`, embedded command) across all indices to find other affected hosts and re-uses of the same builder. [Source: Elastic Security Documentation](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html)
- Hunt for RWX private memory with no backing file across the fleet using **Mandiant `hollows_hunter`/`pe-sieve`** output as an enrichment feed, then join hits to Sysmon EID 8/10 timelines. [Source: Mandiant pe-sieve](https://github.com/hasherezade/pe-sieve)
- Baseline which parents legitimately call `CreateRemoteThread`; alert on the long tail (Office/script hosts, `rundll32`, `regsvr32`) to catch injection delivered via T1218 proxies. [Source: SANS FOR508](https://www.sans.org/posters/hunt-evil/)
- For **Process Discovery (T1057)**, hunt for **Sysmon Event ID 1** where `Image` is a suspicious process (e.g., `wscript.exe` or `powershell.exe`) that has `ParentImage` containing `winword.exe` or `excel.exe`, and the command line includes calls to `CreateToolhelp32Snapshot` or `NtQuerySystemInformation` (detectable via Event ID 4688 command line or ETW). [Source: Microsoft ETW Docs](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)

Those API names, embedded URLs, and command strings become YARA/Suricata pivots and populate the ATT&CK mapping for the incident report.

## Attacker perspective
Attackers favor shellcode precisely because it is header-less, position-independent, and easy to hide inside documents, exploit chains, or process-injection routines — Cobalt Strike beacons, Metasploit `windows/meterpreter` stagers, and custom loaders all deliver raw shellcode.

Concrete TTPs and the artifacts they leave:
- **Encoding/obfuscation (T1027):** msfvenom encoders such as `x86/shikata_ga_nai` (a polymorphic XOR feedback encoder) and custom XOR stubs defeat static signatures. *Artifact:* a decoder loop plus high-entropy body; emulation (`scdbg`) or single-stepping reveals the decoded payload. [Source: Metasploit Framework Docs](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-shellcode.html)
- **Software packing (T1027.002):** some shellcode is packed with UPX or a custom packer; the unpacking stub executes at runtime. *Artifact:* a small unpacker loop followed by a jump to the decompressed region; `scdbg` may fail to emulate unpacked content unless you dump the memory after unpacking via `-d` flag. [Source: MITRE ATT&CK T1027.002](https://attack.mitre.org/techniques/T1027/002/)
- **Position-independent API resolution:** shellcode walks the PEB (`fs:[0x30]` on x86) to find `kernel32.dll`, then resolves exports by hashing names rather than importing them. *Artifact:* a GetPC "call/pop" prologue and PEB access with no import table — a strong heuristic in memory scanners and the reason `scdbg` shows API resolution without any IAT. [Source: SANS FOR508](https://www.sans.org/posters/hunt-evil/)
- **Process Injection (T1055):** classic delivery uses `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, or in-place execution in RWX memory. *Sub-technique:* **T1055.001 (Dynamic-link Library Injection)** when the shellcode loads a malicious DLL into a remote process; *T1055.012 (Process Hollowing)* when the shellcode replaces a legitimate process's memory with its own. [Source: MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- **Reflective Code Loading (T1620):** loaders map a full PE from memory and jump to its entry without touching disk or the loader's import machinery. *Artifact:* executable regions with PE-like headers but no `ImageLoaded` (Sysmon EID 7) event and no on-disk file — visible to `pe-sieve` as an implanted/patched module. Cobalt Strike's reflective DLL loader is a canonical example. [Source: MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)
- **Ingress Tool Transfer (T1105):** staging shellcode calls `URLDownloadToFileA`/`InternetOpenUrlA` to pull the next stage. *Artifact:* outbound HTTP/S visible in Zeek `http.log`/Suricata and the embedded URL recoverable via emulation. [Source: MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- **Deobfuscate/Decode Files or Information (T1140):** the on-target decoder stub that reverses `shikata_ga_nai` or a XOR key at runtime; *Artifact:* a tight XOR/ROL loop preceding a `jmp`/`call` into the decoded region, which is exactly what BlobRunner/x64dbg let you step through to dump the plaintext stage. [Source: MITRE ATT&CK T1140](https://attack.mitre.org/techniques/T1140/)
- **Indicator Removal (T1070):** shellcode may call `DeleteFileA` to erase the source document or downloader after execution (**T1070.004 File Deletion**), or modify timestamps with `SetFileTime` to hide its creation (**T1070.006 Timestomp**). [Source: MITRE ATT&CK T1070](https://attack.mitre.org/techniques/T1070/)

Evasion: attackers minimize step counts and avoid emulator-known APIs, use anti-emulation checks (unsupported/rare instructions, timing via `GetTickCount`/`rdtsc`, `IsDebuggerPresent`), and stage decryption so the first blob looks inert to `scdbg`. Some stagers deliberately use API-hashing and syscalls to skip user-mode hooks. `BlobRunner`/`sclauncher` reproduce the attacker's own load-and-jump primitive so an analyst can step the identical code path in a debugger and recover the decoded second stage that emulation could not. [Source: Mandiant Shellcode Analysis](https://www.mandiant.com/resources/blog/shellcode-analysis-tools)

## Answer key
- **Resolved APIs (call order):** `LoadLibraryA` → `GetProcAddress` → `WinExec` (final `WinExec` argument `calc.exe`, uCmdShow `0`), followed by `ExitProcess`/`Stepcount` termination.
- **Entry offset:** `0` (blob starts at its own entry; `/findsc` confirms offset `0` as the best candidate).
- **Executed command:** `calc.exe` (the inert stub only pops the calculator via `WinExec`).
- **Sample SHA256 (verification):** `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`

Commands that produce these findings:
```powershell
# 1 & 3: full API trace including the WinExec argument
scdbg.exe /f .\exercise\sample.bin

# 2: confirm the entry offset scdbg selects
scdbg.exe /f .\exercise\sample.bin /findsc

# Verify the sample integrity before analysis
Get-FileHash -Algorithm SHA256 .\exercise\sample.bin
```
Expected `Get-FileHash` output SHA256: `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`

## MITRE ATT&CK & DFIR phase
- **T1059 — Command and Scripting Interpreter** (shellcode spawning a process/command via `WinExec`) — [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- **T1055 — Process Injection** (typical delivery vector for shellcode blobs in the wild) — [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
  - **T1055.001 — Dynamic-link Library Injection** (when shellcode injects a DLL into a remote process) — [MITRE ATT&CK T1055/001](https://attack.mitre.org/techniques/T1055/001/)
  - **T1055.012 — Process Hollowing** (when shellcode replaces a legitimate process's memory) — [MITRE ATT&CK T1055/012](https://attack.mitre.org/techniques/T1055/012/)
- **T1027 — Obfuscated Files or Information** (encoded/encrypted shellcode stubs revealed by emulation) — [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
  - **T1027.002 — Software Packing** (when shellcode is packed with UPX or custom packer) — [MITRE ATT&CK T1027/002](https://attack.mitre.org/techniques/T1027/002/)
- **T1105 — Ingress Tool Transfer** (when shellcode resolves `URLDownloadToFileA`/`InternetOpenUrlA`) — [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- **T1620 — Reflective Code Loading** (in-memory PE mapping/execution with no on-disk file) — [MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)
- **T1140 — Deobfuscate/Decode Files or Information** (runtime decoder stub reversing the encoded body) — [MITRE ATT&CK T1140](https://attack.mitre.org/techniques/T1140/)
- **T1218 — System Binary Proxy Execution** (LOLBin/document wrapper that sponsors shellcode delivery) — [MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/)
- **T1070 — Indicator Removal** (shellcode cleaning up artifacts after execution) — [MITRE ATT&CK T1070](https://attack.mitre.org/techniques/T1070/)
  - **T1070.004 — File Deletion** (deleting the source file) — [MITRE ATT&CK T1070/004](https://attack.mitre.org/techniques/T1070/004/)
  - **T1070.006 — Timestomp** (modifying file timestamps) — [MITRE ATT&CK T1070/006](https://attack.mitre.org/techniques/T1070/006/)
- **T1057 — Process Discovery** (shellcode enumerating processes to find injection target) — [MITRE ATT&CK T1057](https://attack.mitre.org/techniques/T1057/)
- **DFIR phase:** Examination / Analysis (malware reverse engineering of carved payloads), feeding Reporting.


### Essential Commands & Features

The following `scdbg` commands and flags unlock deeper shellcode analysis capabilities, particularly for evasive or obfuscated payloads. Use these to inspect runtime behavior, extract artifacts, and validate emulation fidelity:

1. **`-f dumpfile`**
   *When to use*: Analyze shellcode extracted from memory dumps (e.g., process hollowing artifacts) or raw binaries without headers.
   *Example*:
   ```bash
   scdbg -f shellcode_dump.bin -s -1
   ```
   *Why*: Bypasses PE parsing, directly emulating the dumped bytes. Critical for analyzing **T1129 (Shared Modules)** or **T1574.002 (Hijack Execution Flow: DLL Side-Loading)** where shellcode may lack standard headers.

2. **`-r` (Raw Output)**
   *When to use*: Capture unfiltered API call logs for post-processing (e.g., grep for `VirtualAlloc`/`CreateThread` patterns).
   *Example*:
   ```bash
   scdbg -f payload.bin -r > api_calls.log
   ```
   *Why*: Enables automated detection of **T1497.003 (Virtualization/Sandbox Evasion: Time Based Evasion)** by identifying delayed execution patterns.

3. **`-d` (Dump API Arguments)**
   *When to use*: Extract function parameters (e.g., `WriteProcessMemory` target addresses) for forensic reconstruction.
   *Example*:
   ```bash
   scdbg -f obfuscated.bin -d -o 0x1000
   ```
   *Why*: Reveals hidden payloads in **T1027.009 (Obfuscated Files or Information: Embedded Payloads)** by exposing memory writes to non-standard regions.

4. **`-vv` (Verbose Debugging)**
   *When to use*: Diagnose emulation failures (e.g., unsupported instructions or anti-analysis hooks).
   *Example*:
   ```bash
   scdbg -f evasive.bin -vv -foffset 0x200
   ```
   *Why*: Flags emulation gaps (e.g., missing `NtQueryInformationProcess` hooks) that adversaries exploit in **T1601.001 (Modify System Image: Patch System Image)**.

**Emulation Limits**: `scdbg` does not emulate hardware breakpoints, SEH chains, or kernel-mode syscalls. For full fidelity, pair with **Unicorn Engine** or **Qiling Framework**.

**Sources**:
- [FireEye FLARE Shellcode Analysis Guide](https://www.fireeye.com/blog/threat-research/2019/08/definitive

### Threat Hunting & Detection Engineering

Once shellcode is unpacked or injected, defenders must hunt for its execution footprint. Focus on **Process Injection (T1055.002 – Portable Executable Injection)** and **Reflective Code Loading (T1574.009 – Reflective DLL Injection)** by correlating Windows Event Logs with network telemetry.

**Detection Logic:**
- **Windows Event ID 10:** Process creation with `ParentImage` ending in `cmd.exe` or `powershell.exe` and `CommandLine` containing `VirtualAlloc`, `CreateThread`, or `memcpy` (case-insensitive regex). Pair with **Event ID 8** (CreateRemoteThread) where `SourceImage` ≠ `TargetImage` and `StartAddress` falls within a non-standard module range (e.g., `0x10000000`–`0x7FFFFFFF`).
- **Zeek:** Hunt for `conn.log` entries where `service == "dns"` and `query` matches base64-encoded shellcode patterns (e.g., `\xfc\xe8` or `\x48\x31\xc9`). Pivot to `files.log` for `mime_type == "application/octet-stream"` with `rx_hosts` containing known C2 IPs.
- **Suricata:** Detect shellcode execution via **SMB2 Write Requests** (signature: `smb2.file.data contains "|FC E8|"`) or **HTTP POSTs** with `content:"|FF E0|"` (JMP EAX) in unencrypted traffic.

**Threat-Hunting Pivots:**
1. Stack `Sysmon Event ID 7` (ImageLoaded) with `Image` ≠ `ImageLoaded` to identify reflective DLLs (e.g., `LoadLibrary` calls from `svchost.exe`).
2. Query **ETW Microsoft-Windows-Kernel-Process** for `ThreadStart` events where `StartAddr` is in a `MEM_PRIVATE` region (flag `0x20000`).

**Sources:**
- [MITRE ATT&CK: T1055.002](https://attack.mitre.org/techniques/T1055/002/)
- [CISA: Detecting Post-Exploitation with ETW](https://www.cisa.gov/resources-tools/services/detecting-post-exploitation-behavior)

## Sources
1. **scdbg Official Documentation** – [Sandsprite scdbg docs](http://sandsprite.com/blogs/index.php?uid=7&pid=152) (tool behavior, command-line flags, emulation logic)
2. **BlobRunner GitHub Repository** – [OALabs BlobRunner README](https://github.com/OALabs/BlobRunner) (usage, memory allocation, debugger attach pattern)
3. **FLARE-VM Tools** – [FireEye FLARE-VM GitHub](https://github.com/fireeye/flare-vm) (installation, `sclauncher` package details)
4. **MITRE ATT&CK Framework** – [MITRE ATT&CK Techniques](https://attack.mitre.org/techniques/enter-technique-id-here/) (T1059, T1055, T1027, T1105, T1620, T1140, T1218, T1070, T1057)
5. **Microsoft Sysmon Documentation** – [Microsoft Learn Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (Event IDs 1, 7, 8, 10, 11 and detection logic)
6. **Zeek Network Security Monitor** – [Zeek Documentation](https://docs.zeek.org/en/master/) (`http.log`, `files.log`, `conn.log` fields and pivots)
7. **Suricata IDS** – [Suricata Documentation](https://suricata.readthedocs.io/en/suricata-6.0.0/) (EVE JSON fields, `filestore`, `fileinfo`)
8. **SANS FOR508 Poster** – [SANS Hunt Evil Poster](https://www.sans.org/posters/hunt-evil/) (PEB walk, process injection heuristics)
9. **Mandiant Shellcode Analysis** – [Mandiant Blog](https://www.mandiant.com/resources/blog/shellcode-analysis-tools) (anti-emulation, reflective loading, evasion)
10. **Metasploit Framework** – [Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-shellcode.html) (`shikata_ga_nai` encoder, shellcode generation)

## Related modules
- [[18 * Memory forensics with Volatility -- LAB-LINUX]]
- [[22 * Process injection triage -- LAB-WINDOWS]]
- https://www.fireeye.com/blog/threat-research/2019/08/definitive
- https://attack.mitre.org/techniques/T1055/002/
- https://www.cisa.gov/resources-tools/services/detecting-post-exploitation-behavior

<!-- cyberlab-enriched: v5 -->
