# 31 * Shellcode analysis deep-dive -- LAB-WINDOWS

## Overview (plain language)
Shellcode is a small chunk of raw machine instructions that attackers drop into a running program to take control — it has no file header, no imports, and often no obvious structure, so normal tools cannot open it like a program. This module shows how to make sense of that raw blob safely. `scdbg` pretends to be a tiny Windows computer and "runs" the bytes in an emulator, writing down every Windows API the code tries to call (like "download a file" or "start a process") without ever really executing anything on your machine. `BlobRunner` takes the opposite approach: it loads the blob into memory in a controlled test process and jumps to it, so you can attach a real debugger and watch it live. Together they let an analyst answer "what does this raw shellcode actually do?" without guessing.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| scdbg | Included in FLARE-VM (`scdbg.exe`) | Emulate 32-bit shellcode and log Windows API calls without native execution (scdbg wraps the libemu x86 emulation library) |
| BlobRunner | Included in FLARE-VM (`BlobRunner.exe` / `BlobRunner64.exe`) | Load a raw shellcode blob into a live process and jump to it for debugger attach |

> Accuracy note: `scdbg` is built on the **libemu** x86 CPU/Windows-environment emulator and is therefore fundamentally a **32-bit x86** shellcode emulator; libemu does not emulate x86-64. For 64-bit shellcode use live analysis with `BlobRunner64.exe` and a debugger. Source: scdbg / sclog project docs (dzzie/sandsprite) and the libemu project (https://github.com/buffer/libemu).

## Learning objectives
- Emulate a raw 32-bit shellcode blob with `scdbg` and read the resulting API call trace.
- Identify shellcode entry offsets and use `scdbg` options to force a start address.
- Load a benign shellcode blob with `BlobRunner` and pause at the buffer for debugger attach.
- Distinguish emulation (scdbg) from live analysis (BlobRunner) and explain when to use each.

## Environment check
```powershell
# Prove both tools are reachable in the FLARE-VM PATH / tool dirs
Get-Command scdbg.exe -ErrorAction SilentlyContinue | Select-Object Source
Get-Command BlobRunner.exe -ErrorAction SilentlyContinue | Select-Object Source

# scdbg prints its usage/help banner
scdbg.exe /?
```
Expected output: the `Get-Command` lines print the full path to each executable (e.g. `C:\Tools\scdbg\scdbg.exe`), and `scdbg.exe /?` prints its usage banner. Per the scdbg documentation the switches include `/f <file>` (load a file to emulate), `/foff <offset>` (start emulation at a file offset), `/s <int>` (max number of steps to emulate), `/d` (spawn a debug shell), and `/r` (report/verbose mode). Confirm the exact switches on your build against the banner, since option coverage varies by version. Source: scdbg usage/README (https://github.com/dzzie/VS_LIBEMU and http://sandsprite.com/blogs/index.php?uid=7&pid=152).

## Guided walkthrough
1. Confirm the benign sample exists before doing anything else — you must hash-verify an untrusted-looking artifact before analysis so you can prove exactly which bytes you examined and so results are reproducible.
```powershell
# The benign sample ships in this module's exercise dir
Get-FileHash .\exercise\sample.bin -Algorithm SHA256
```
Expected output: prints the SHA256 of `sample.bin` matching the value in the Answer key. `Get-FileHash` defaults to SHA256 but we pass `-Algorithm SHA256` explicitly for clarity and auditability. Source: Microsoft Learn `Get-FileHash` (https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash).

2. Emulate the blob with `scdbg` and dump the API trace. `/f` selects the file to load into the emulator. Why emulate first: emulation never executes the bytes on your CPU, so even a malicious download-and-run stub only produces a *log* of the Windows APIs it *would* have called — this is the safest possible first pass on unknown shellcode.
```powershell
scdbg.exe /f .\exercise\sample.bin
```
Expected output: `scdbg` prints an emulation report — a list of executed steps and any simulated Windows API calls (function name, arguments, return). Nuance: scdbg tries several likely entry offsets automatically and reports the one that produced the most interesting trace; for a NOP/`int3` stub it reports execution reaching a trap/stop with no meaningful API calls. A real loader instead shows resolved hooks such as `LoadLibraryA`, `GetProcAddress`, `URLDownloadToFileA`, or `WinExec`, each with decoded arguments — that argument text (URLs, filenames, command lines) is your primary IOC yield. Source: scdbg docs (http://sandsprite.com/blogs/index.php?uid=7&pid=152).

3. If the real entry point is not at offset 0, force a start offset with `/foff`. Why this matters: shellcode frequently begins with a decoder stub or a `call/pop` "GetPC" sequence, and the meaningful entry may sit tens of bytes in; if scdbg's auto-detection picks the wrong start you will see a garbage trace, so pinning the offset you identified (e.g. from a disassembler) gives a deterministic run.
```powershell
scdbg.exe /f .\exercise\sample.bin /foff 0x0
```
Expected output: identical trace but confirming the emulator started at the specified file offset (`0x0` here). Source: scdbg usage banner / README (https://github.com/dzzie/VS_LIBEMU).

4. Prepare the same blob for live analysis. `BlobRunner` allocates memory, copies the blob in, prints the base address, and pauses so you can attach x64dbg before it jumps. Why switch to live analysis: emulation cannot always follow heavily obfuscated or 64-bit code, so detonating the blob under a debugger lets you watch the decoder run and inspect the *decoded* second stage in memory. Per the OALabs README, `BlobRunner.exe` is for 32-bit shellcode and `BlobRunner64.exe` is for 64-bit shellcode.
```powershell
BlobRunner.exe -f .\exercise\sample.bin
```
Expected output: `BlobRunner` prints the base address it allocated the buffer at and a prompt to press a key to jump to the shellcode — leaving a window to attach a debugger and set a breakpoint on the buffer address. Source: BlobRunner README (https://github.com/OALabs/BlobRunner).

## Hands-on exercise
Analyze the sample artifact `exercise/sample.bin` in this module's `exercise/` directory.

- **Type:** raw 32-bit x86 shellcode blob (no PE header), inert.
- **Safe origin:** benign/inert — the blob is generated locally from NOP padding followed by an `int3` (breakpoint / trap) instruction and `ret`. It performs NO network egress, file writes, or process creation. Regenerate it with the command in the Answer key if it is missing.

Tasks:
1. Compute the SHA256 of `sample.bin` and confirm it matches the Answer key.
2. Run `scdbg` against the blob and record how many API calls the emulator observed.
3. Run `BlobRunner` and record the allocated buffer base address it reports.

## SOC analyst perspective
Defenders rarely receive tidy PE files; shellcode arrives embedded in exploit documents, loader stages, or extracted from memory dumps, so being able to emulate a raw blob is core triage. In Security Onion you often start from a Suricata/Zeek alert on an exploit delivery (e.g. an RTF or a suspicious HTTP object), carve the object, extract the shellcode region, and feed it to `scdbg`.

Concrete detection logic and pivots:
- **Delivery / download stage:** A Suricata `file-store` / ET alert on an exploit document or an HTTP object triggers first. Pivot in Security Onion to Zeek `http.log` (the `host`, `uri`, `mime_type`, and `resp_fhash` fields) and `files.log` to identify and carve the delivered object. Suricata and Zeek both ship as core Security Onion sensors. Source: Security Onion docs (https://docs.securityonion.net/).
- **Map scdbg API hits to ATT&CK:** `URLDownloadToFile*` / `InternetOpenUrl*` in the trace implies **T1105 Ingress Tool Transfer**; `WinExec`/`CreateProcess*` implies execution via **T1059 Command and Scripting Interpreter**; `LoadLibrary`/`GetProcAddress` resolved by hash rather than by name is a strong indicator of **T1027 Obfuscated Files or Information** (API hashing). Source: MITRE ATT&CK technique pages (T1105 https://attack.mitre.org/techniques/T1105/, T1059 https://attack.mitre.org/techniques/T1059/, T1027 https://attack.mitre.org/techniques/T1027/).
- **Scoping with IOCs:** The C2 host, URI, and dropped filename decoded from scdbg's argument logging become your pivots. In Security Onion, search Zeek `conn.log` for the destination IP/port to find beaconing peers, `http.log`/`dns.log` for the C2 host across the fleet, and pivot those into the Elastic/Kibana hunt views to scope which endpoints touched the same infrastructure. Source: Security Onion docs (https://docs.securityonion.net/), Zeek log reference (https://docs.zeek.org/en/master/logs/index.html).
- **Host-side confirmation:** Because injected shellcode often runs from RWX/unbacked memory, correlate the network IOCs with Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) if endpoint logs are shipped. Source: Microsoft Learn / Sysmon docs (https://learn.microsoft.com/sysinternals/downloads/sysmon).

## Attacker perspective
Attackers favor position-independent shellcode precisely because it has no header, no imports table, and can be injected into a benign process — making static signatures and simple file scanning far less effective.

Concrete TTPs, artifacts, and evasion:
- **Injection (T1055 Process Injection):** Classic chains call `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, or use the newer `NtQueueApcThread` (early-bird APC injection, **T1055.004**) to run in a suspended process. Artifacts: cross-process handle opens and remote-thread creation surface as Sysmon EID 8/10 and unbacked executable memory regions. Source: MITRE ATT&CK T1055 (https://attack.mitre.org/techniques/T1055/) and sub-technique T1055.004 (https://attack.mitre.org/techniques/T1055/004/).
- **Runtime API resolution & obfuscation (T1027):** Shellcode walks the PEB (`fs:[0x30]` on x86 / `gs:[0x60]` on x64) to find `kernel32`, then hashes export names (e.g. ROR-13) to resolve `LoadLibraryA`/`GetProcAddress` without a readable import table — defeating string and IAT-based signatures. A small XOR/rolling decoder stub commonly precedes the real payload, and egg-hunters may locate a larger staged buffer. Source: MITRE ATT&CK T1027 (https://attack.mitre.org/techniques/T1027/).
- **Download-and-execute (T1105 / T1059):** A minimal stage pulls the next payload via `URLDownloadToFileA` or WinINet and executes it, keeping the on-wire footprint tiny.
- **Artifacts that still leak for defenders:** emulation (scdbg) reveals the decoder loop and the eventual API calls even when the payload is encoded on disk; live detonation (BlobRunner + debugger) exposes the *decoded* second stage in memory; unusual RWX/unbacked executable pages are visible with memory-scanning tools; and sandbox execution produces network (C2) and process-creation telemetry that maps directly back to the shellcode's true intent.

## Answer key
Sample: `exercise/sample.bin`, SHA256 = `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`.

That digest corresponds to the 6-byte inert blob `90 90 90 CC C3 90` (NOP padding, `int3`, `ret`, trailing NOP). Regenerate the exact sample if missing:
```powershell
# Reproducible benign generator: 3 NOPs, int3, ret, NOP -> sample.bin
$bytes = [byte[]](0x90,0x90,0x90,0xCC,0xC3,0x90)
[System.IO.File]::WriteAllBytes("$PWD\exercise\sample.bin", $bytes)
Get-FileHash .\exercise\sample.bin -Algorithm SHA256
```
Expected findings and commands:
```powershell
# 1) Hash check -> matches the SHA256 above
Get-FileHash .\exercise\sample.bin -Algorithm SHA256

# 2) scdbg emulation -> 0 meaningful Windows API calls (inert NOP/int3 stub)
scdbg.exe /f .\exercise\sample.bin

# 3) BlobRunner -> prints an allocated buffer base address (value varies per run)
BlobRunner.exe -f .\exercise\sample.bin
```
Expected: the SHA256 equals `99bd3c262cfc8e3173548986f8dd786d59cc51d3f9e0929b85d34f973c839d55`; `scdbg` reports emulation terminating at the `int3`/trap with no meaningful Windows API calls; `BlobRunner` reports a valid virtual base address for the mapped buffer and pauses before jumping.

> Correction note: a previous revision of this key referenced a truncated hash `9f64a747...806a`; that value was inconsistent with the generated bytes and has been removed. The single authoritative digest for the 6-byte blob `90 90 90 CC C3 90` is the SHA256 shown above.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** (shellcode is the canonical injected payload) — https://attack.mitre.org/techniques/T1055/
- **T1055.004 – Asynchronous Procedure Call** (early-bird APC injection of shellcode) — https://attack.mitre.org/techniques/T1055/004/
- **T1027 – Obfuscated Files or Information** (encoded/self-decoding shellcode, API hashing) — https://attack.mitre.org/techniques/T1027/
- **T1059 – Command and Scripting Interpreter** (shellcode spawning execution primitives) — https://attack.mitre.org/techniques/T1059/
- **T1105 – Ingress Tool Transfer** (download-and-execute shellcode stages) — https://attack.mitre.org/techniques/T1105/
- **DFIR phase:** Examination / Analysis (malware code analysis of a carved artifact), feeding Identification (IOC extraction). Aligns with the NIST SP 800-86 forensic process (Collection → Examination → Analysis → Reporting). Source: NIST SP 800-86 (https://csrc.nist.gov/pubs/sp/800/86/final).

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- **FLARE-VM ships scdbg and BlobRunner; tool set / install** — Mandiant/Google FLARE-VM repo: https://github.com/mandiant/flare-vm
- **scdbg is a libemu-based 32-bit x86 shellcode emulator; `/f`, `/foff`, `/s`, `/d`, `/r` switches; API-call logging** — scdbg docs (dzzie/sandsprite): http://sandsprite.com/blogs/index.php?uid=7&pid=152 and https://github.com/dzzie/VS_LIBEMU
- **libemu emulates x86 (not x86-64), the engine underneath scdbg** — libemu project: https://github.com/buffer/libemu
- **BlobRunner loads a raw blob, prints the buffer base, pauses for debugger attach; `BlobRunner.exe` (x86) vs `BlobRunner64.exe` (x64)** — OALabs BlobRunner repo: https://github.com/OALabs/BlobRunner
- **`Get-FileHash` behavior and `-Algorithm SHA256`** — Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- **MITRE ATT&CK technique IDs and behaviors** — T1055 https://attack.mitre.org/techniques/T1055/ ; T1055.004 https://attack.mitre.org/techniques/T1055/004/ ; T1027 https://attack.mitre.org/techniques/T1027/ ; T1059 https://attack.mitre.org/techniques/T1059/ ; T1105 https://attack.mitre.org/techniques/T1105/
- **Security Onion sensors (Suricata/Zeek/Elastic), file carving, and hunt pivots** — Security Onion docs: https://docs.securityonion.net/
- **Zeek log fields (`http.log`, `conn.log`, `dns.log`, `files.log`)** — Zeek log reference: https://docs.zeek.org/en/master/logs/index.html
- **Sysmon Event IDs 8 (CreateRemoteThread) / 10 (ProcessAccess) for injection detection** — Microsoft Learn / Sysinternals Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- **DFIR phase model (Collection/Examination/Analysis/Reporting)** — NIST SP 800-86: https://csrc.nist.gov/pubs/sp/800/86/final
- **Reverse-engineering / shellcode analysis methodology** — SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Shellcode analysis](../17-shellcode-analysis/README.md) -- shares BlobRunner for live shellcode detonation.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares scdbg in an end-to-end carving/analysis scenario.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- same Deep-dives learning path; disassemble/annotate the shellcode entry you pin with `/foff`.
- [x64dbg unpacking & debugging workflow](../28-x64dbg-workflow/README.md) -- same Deep-dives learning path; the debugger you attach after BlobRunner pauses.

<!-- cyberlab-enriched: v1 -->
