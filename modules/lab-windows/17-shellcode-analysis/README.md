# 17 * Shellcode analysis -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a tiny chunk of raw machine-code instructions that an attacker sneaks into a program to make it do something new — like download a file or open a remote connection. Unlike a normal `.exe`, shellcode has no headers or friendly structure; it is just bytes meant to be jumped into and run. That makes it hard to read directly. The tools in this module let you safely watch what a blob of shellcode *tries* to do. `scdbg` emulates the bytes in a fake CPU so it can report the Windows API calls the shellcode would make without ever really running them. `BlobRunner` and `sclauncher` take the opposite approach: they load the raw bytes into memory and hand control to a debugger so you can step through the code yourself. Together they turn an unreadable pile of bytes into a clear story of intent.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | `choco install scdbg` (FLARE-VM package) | Emulates 32-bit shellcode via libemu and logs the Windows API calls it attempts. |
| BlobRunner | FLARE-VM package `blobrunner` (32/64) | Loads a raw shellcode blob into memory and pauses so you can attach a debugger and step it. |
| sclauncher | FLARE-VM package `sclauncher` (32/64) | Allocates RWX memory, copies shellcode in, and jumps to it (with breakpoint options) for live debugging. |

## Learning objectives
- Emulate a raw shellcode blob with `scdbg` and enumerate the API calls it resolves.
- Identify shellcode entry-point offsets and hooked/reported APIs from emulation output.
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
Expected output: `scdbg` prints its option list (`/f <file>`, `/foff`, `/findsc`, `/s`, etc.); `BlobRunner.exe` prints a banner with `-file` / `-64` usage; `sclauncher.exe` prints usage including `-f` and breakpoint flags. If any command is not recognized, re-run the FLARE-VM installer for that package.

## Guided walkthrough
1. `scdbg /f sample.bin` — emulate the blob and log API calls it attempts. Expected observable: a list of resolved APIs (e.g. `LoadLibraryA`, `GetProcAddress`, `WinExec`) with their arguments, plus a final `Stepcount` line.
```powershell
# Emulate a shellcode file; report offsets of interesting instructions.
scdbg.exe /f .\exercise\sample.bin
```

2. `scdbg /findsc` — brute-force candidate entry offsets when the true start is unknown.
```powershell
# Ask scdbg to search for likely shellcode entry points, then emulate the best one.
scdbg.exe /f .\exercise\sample.bin /findsc
```

3. Prepare for live debugging with `BlobRunner`. It loads the blob and prints the base address, then waits for you to press a key so you can attach x64dbg. Do this ONLY in an isolated VM snapshot.
```powershell
# Load the blob into memory and pause before jumping to it.
BlobRunner.exe -file .\exercise\sample.bin
```
Expected observable: BlobRunner prints `Reading file...`, an allocated buffer address (e.g. `Buffer: 0x02340000`), and `Press any key to jump to the shellcode...`. Attach x64dbg to `BlobRunner.exe`, set a breakpoint at the printed buffer address, then resume.

4. Alternatively use `sclauncher` with an entry breakpoint so the debugger stops exactly at the shellcode.
```powershell
# Launch with an INT3 breakpoint at the shellcode entry for x64dbg to catch.
sclauncher.exe -f .\exercise\sample.bin -bp
```
Expected observable: `sclauncher` allocates RWX memory, prints the entry address, and triggers a breakpoint (`-bp`) at the first byte so the attached debugger halts on the shellcode.

## Hands-on exercise
Use the sample in this module's `exercise/` directory.

- **Sample:** `exercise/sample.bin`
- **Type:** 32-bit position-independent Windows shellcode blob (raw bytes, no PE header).
- **Safe origin:** Benign/inert training stub assembled locally with NASM from source (`exercise/sample.asm`). It only resolves and calls `WinExec("calc.exe")`-style APIs in an emulator; it contains **no live malware**, no network egress, and no persistence. Emulate it (`scdbg`) rather than launch it, and run any live step only inside an isolated FLARE-VM snapshot with host-only networking.
- **sha256:** `9f2c4a7be1d0836af5c19e2b7d4a0c68f3e5b91a2c7d40e8b16f9a3c5d7e0f12`

Tasks:
1. Emulate `sample.bin` with `scdbg` and list every Windows API it resolves, in call order.
2. Identify the entry offset `scdbg` used to emulate the blob.
3. Determine the single command/process the shellcode attempts to execute.

## SOC analyst perspective
Defenders rarely receive tidy executables — they get carved memory regions, malicious document macros, or exploit payloads that are just raw bytes. `scdbg` lets an analyst triage such a blob in seconds by emulating it and printing the API sequence, which is exactly the intel needed to write detections. In a Security Onion workflow, Suricata or Zeek may flag an HTTP transfer or an EternalBlue-style exploit; you carve the payload, run `scdbg /f payload.bin /findsc`, and the resolved `LoadLibraryA`/`WinExec`/`URLDownloadToFileA` calls tell you whether it downloads a stage (T1105), spawns a process (T1059), or injects (T1055). Those API names and any embedded URLs/commands become pivots you feed into Security Onion hunts and YARA rules, mapping observed behavior straight onto MITRE ATT&CK for the incident report and enrichment of Elastic alerts.

## Attacker perspective
Attackers favor shellcode precisely because it is header-less, position-independent, and easy to hide inside documents, exploit chains, or process-injection routines — Cobalt Strike beacons, Metasploit `windows/meterpreter` stagers, and custom loaders all deliver raw shellcode. It is commonly encoded (msfvenom `shikata_ga_nai`, XOR stubs) to defeat signatures, and injected via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` (T1055) or executed in-place with RWX memory. The very techniques attackers rely on leave artifacts: RWX private memory regions detectable by pe-sieve/HollowsHunter, API-resolution stubs that walk the PEB, and the API call trace itself. `BlobRunner`/`sclauncher` reproduce the attacker's own load-and-jump primitive so an analyst can step the identical code path in a debugger and recover decoded second stages.

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
- **T1059 — Command and Scripting Interpreter** (shellcode spawning a process/command via `WinExec`).
- **T1055 — Process Injection** (typical delivery vector for shellcode blobs in the wild).
- **T1027 — Obfuscated Files or Information** (encoded/encrypted shellcode stubs revealed by emulation).
- **T1105 — Ingress Tool Transfer** (when shellcode resolves `URLDownloadToFileA`/`InternetOpenUrlA`).
- **DFIR phase:** Examination / Analysis (malware reverse engineering of carved payloads), feeding Reporting.

## Sources
- FLARE-VM package list & installer, Mandiant/Google — https://github.com/mandiant/flare-vm
- scdbg / libemu shellcode emulation, David Zimmer — http://sandsprite.com/blogs/index.php?uid=7&pid=152
- BlobRunner, OALabs — https://github.com/OALabs/BlobRunner
- sclauncher, OALabs — https://github.com/OALabs/sclauncher
- REMnux/SANS shellcode analysis guidance — https://docs.remnux.org/discover-the-tools/analyze+documents+and+shellcode/shellcode
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK techniques T1055, T1059, T1027, T1105 — https://attack.mitre.org/techniques/T1055/
- Security Onion documentation — https://docs.securityonion.net/