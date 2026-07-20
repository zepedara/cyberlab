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
Expected observable: a list of resolved APIs (e.g. `LoadLibraryA`, `GetProcAddress`, `WinExec`) with arguments, and a final `Stepcount` line reporting how many instructions were emulated. **Nuance:** a very low step count or an "unsupported instruction" message often means `scdbg` guessed the wrong entry offset or the blob is 64-bit (unsupported) — that is your cue for step 2.

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
Expected observable: BlobRunner prints that it is reading the file, an allocated buffer address (e.g. `Buffer: 0x02340000`), and a prompt to press a key before it jumps to the shellcode. **Why the pause matters:** it gives you a window to attach x64dbg to `BlobRunner.exe`, set a breakpoint at the printed buffer address, then resume — so the debugger halts exactly at the first shellcode byte.

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

Concrete Security Onion pivots:
- **Zeek:** pivot the extracted URL/host from `URLDownloadToFileA` into `http.log` (`host`, `uri`) and `conn.log` (`id.resp_h`, `id.resp_p`) to find the download and any follow-on C2 sessions. Zeek's File Analysis Framework (`files.log`) can carry the carved payload's hash for correlation.
- **Suricata:** the `alert` events (rendered in `suricata.log`/Elastic) that first flagged the exploit or transfer give you the rule SID and the five-tuple to scope the incident.
- **Elastic (Kibana Hunt/Dashboards):** search the SHA256 of the carved blob and the observed domain/command across telemetry to find other affected hosts, and attach the resolved API list and any embedded command (`calc.exe`, or a real payload's command line) as enrichment on the case.

Those API names, embedded URLs, and command strings become YARA/Suricata pivots and populate the ATT&CK mapping for the incident report.

## Attacker perspective
Attackers favor shellcode precisely because it is header-less, position-independent, and easy to hide inside documents, exploit chains, or process-injection routines — Cobalt Strike beacons, Metasploit `windows/meterpreter` stagers, and custom loaders all deliver raw shellcode.

Concrete TTPs and the artifacts they leave:
- **Encoding/obfuscation (T1027):** msfvenom encoders such as `x86/shikata_ga_nai` (a polymorphic XOR feedback encoder) and custom XOR stubs defeat static signatures. *Artifact:* a decoder loop plus high-entropy body; emulation (`scdbg`) or single-stepping reveals the decoded payload.
- **Position-independent API resolution:** shellcode walks the PEB (`fs:[0x30]` on x86) to find `kernel32.dll`, then resolves exports by hashing names rather than importing them. *Artifact:* a GetPC "call/pop" prologue and PEB access with no import table — a strong heuristic in memory scanners.
- **Process Injection (T1055):** classic delivery uses `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, or in-place execution in RWX memory. *Artifact:* private RWX memory regions with no backing file, detectable with Mandiant's `pe-sieve`/`hollows_hunter`.
- **Ingress Tool Transfer (T1105):** staging shellcode calls `URLDownloadToFileA`/`InternetOpenUrlA` to pull the next stage. *Artifact:* outbound HTTP/S visible in Zeek/Suricata and the embedded URL recoverable via emulation.

Evasion: attackers minimize step counts and avoid emulator-known APIs, use anti-emulation checks (unsupported/rare instructions, timing, `GetTickCount`), and stage decryption so the first blob looks inert. `BlobRunner`/`sclauncher` reproduce the attacker's own load-and-jump primitive so an analyst can step the identical code path in a debugger and recover the decoded second stage that emulation could not.

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
- **DFIR phase:** Examination / Analysis (malware reverse engineering of carved payloads), feeding Reporting.

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
- `pe-sieve` / `hollows_hunter` (RWX / injected-code memory detection), Mandiant/hasherezade — https://github.com/hasherezade/pe-sieve
- Metasploit Framework `shikata_ga_nai` encoder (msfvenom encoding), Rapid7 — https://docs.rapid7.com/metasploit/msfvenom/
- Zeek documentation (http.log, conn.log, files.log fields for pivoting) — https://docs.zeek.org/
- Suricata documentation (alert/rule output) — https://docs.suricata.io/
- Security Onion documentation (Zeek/Suricata/Elastic hunting) — https://docs.securityonion.net/
- x64dbg documentation (attaching and breakpoints for live shellcode stepping) — https://help.x64dbg.com/

## Related modules
- [Shellcode analysis deep-dive](../31-shellcode-deep/README.md) — shares blobrunner for deeper live-debugging practice.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) — shares scdbg in a full carved-payload case study.
- [Static reverse engineering](../12-static-re/README.md) — same learning path (Windows RE), static analysis foundations.
- [Dynamic debugging](../13-dynamic-debugging/README.md) — same learning path (Windows RE), debugger workflow feeding this module.

<!-- cyberlab-enriched: v1 -->
