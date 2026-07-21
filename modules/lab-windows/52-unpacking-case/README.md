# 52 * Scenario: packed-malware unpacking workflow -- LAB-WINDOWS

## Overview (plain language)
Many malicious programs are "packed" — squeezed and scrambled so their real code only appears in memory once the program runs. This makes them hard to read with normal static tools. This module walks through a beginner-friendly unpacking workflow: you first inspect a suspicious file to spot the tell-tale signs of packing, then run it under a controlled debugger, let it unpack itself in memory, and grab (dump) the now-visible clean code so you can study what the malware really does. The three tools work as a team — one shows the file's structure, one lets you drive and freeze execution, and one pulls readable strings out before and after unpacking so you can measure your success. Packing is a form of **T1027 Obfuscated Files or Information**, specifically **T1027.002 Software Packing** (MITRE ATT&CK).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| x64dbg | Pre-installed on FLARE-VM | Open-source x64/x32 user-mode debugger to run a sample step-by-step, break at the unpacking tail-jump (OEP), and dump the unpacked process image (via the bundled Scylla plugin). x64dbg supports hardware breakpoints, memory inspection, and process dumping with import table reconstruction. See the [x64dbg documentation](https://help.x64dbg.com/en/latest/). |
| PE-bear | Pre-installed on FLARE-VM | PE structure viewer (by hasherezade) to inspect sections, per-section entropy, imports, and confirm packing indicators before/after unpacking. PE-bear calculates Shannon entropy for each section, a key indicator of compression/encryption. See the [PE-bear GitHub repo](https://github.com/hasherezade/pe-bear). |
| FLOSS | Pre-installed on FLARE-VM | Mandiant (formerly FireEye) string extractor that also decodes obfuscated/stack/tight strings, used to compare readable strings before vs after unpacking. FLOSS v3.0+ includes stack string extraction, tight string extraction, and emulated string decoding. See the [flare-floss GitHub repo](https://github.com/mandiant/flare-floss). |

## Learning objectives
- Identify at least three static indicators of a packed PE (high entropy, non-standard section names, tiny import table) using PE-bear, and explain why each is a red flag (**T1027.002**).
- Compare FLOSS string output on the packed vs unpacked binary and quantify the difference, demonstrating **T1140 Deobfuscate/Decode Files or Information**.
- Use x64dbg to reach the Original Entry Point (OEP) after the unpacking stub runs, and explain the significance of the `pushad`/`popad` sequence in UPX.
- Produce a memory-dumped, reconstructed executable of the unpacked payload using Scylla, and verify the import table is rebuilt (**T1059.003 Command and Scripting Interpreter: Windows Command Shell** for IAT reconstruction).
- Verify the dump is more analyzable than the original (richer imports and strings) and tie this to **T1083 File and Directory Discovery** for post-unpacking analysis.

## Environment check
```powershell
# Confirm the three tools are present on FLARE-VM (PowerShell)
Get-ChildItem "C:\Tools\x64dbg" -Recurse -Filter "x64dbg.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 FullName

Get-ChildItem "C:\Tools" -Recurse -Filter "PE-bear.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 FullName

# FLOSS is on PATH via FLARE-VM
floss --version
```
Expected output: full paths to `x64dbg.exe` and `PE-bear.exe`, and a FLOSS version banner such as `floss 3.x`.

> Note: FLARE-VM installs these packages via Chocolatey; exact install paths can vary by version, so the recursive `Get-ChildItem` search above is intentionally path-tolerant. FLOSS's `--version` flag is documented in the [Mandiant flare-floss repo](https://github.com/mandiant/flare-floss). The latest FLARE-VM (as of 2024) includes FLOSS v3.1.1 or later, which supports stack/tight string extraction ([FLARE-VM GitHub](https://github.com/mandiant/flare-vm)).

## Guided walkthrough
1. Build a benign, UPX-packed sample (safe, inert) so nothing malicious is ever run.
```powershell
# Compile a harmless C program that just prints a marker string, then pack it with UPX.
$src = @'
#include <stdio.h>
int main(void){ printf("BENIGN-UNPACK-LAB-MARKER-52\n"); return 0; }
'@
Set-Content -Path .\exercise\hello.c -Value $src -Encoding ASCII
cl /nologo /Fe:.\exercise\sample.exe .\exercise\hello.c
Copy-Item .\exercise\sample.exe .\exercise\sample_packed.exe
upx --best .\exercise\sample_packed.exe
```
Expected output: `cl` produces `sample.exe`; `upx --best` reports `Packed 1 file.` and shrinks `sample_packed.exe`.
**Why:** UPX is a real, open-source executable packer that compresses the original code/data into a compressed section and prepends a small self-decompression stub; `--best` selects the highest compression level (documented in the [UPX help/README](https://github.com/upx/upx)). We use UPX because its behavior — self-unpacking at runtime into memory, then jumping to the original entry point — mirrors what malicious packers do, but the payload here is provably benign. The *nuance*: UPX renames the original sections to `UPX0` (destination for the decompressed image, raw size 0 on disk) and `UPX1` (holds the compressed data + stub); this on-disk vs in-memory size mismatch is itself a packing tell. UPX also adds a `UPX!` magic marker in the stub, which is a well-known signature for **T1027.002** ([UPX GitHub](https://github.com/upx/upx)).

2. Inspect packing indicators in PE-bear.
```powershell
# Open the packed file in PE-bear for manual review of sections/entropy/imports.
Start-Process "C:\Tools\PE-bear\PE-bear.exe" -ArgumentList ".\exercise\sample_packed.exe"
```
Expected observable: sections named `UPX0`/`UPX1`, high entropy on the packed section (~7.5–8.0), and a very small import table (typically only `kernel32.dll` and `ntdll.dll`).
**Why:** PE-bear parses the PE headers so you can read the Section Table without running the file. Look for three converging signals:
   - (a) Non-standard section names `UPX0`/`UPX1` instead of `.text`/`.data`/`.rdata` — a red flag for **T1036 Masquerading** (section name spoofing).
   - (b) Elevated entropy on the compressed section — compressed/encrypted data approaches the theoretical maximum of 8.0 bits/byte (Shannon entropy), so values in the ~7.5–8.0 range strongly suggest compression/encryption rather than normal code (~5.5–6.5). PE-bear calculates entropy per section using the formula: `H = -Σ p(x) log₂ p(x)`, where `p(x)` is the probability of byte `x` in the section ([PE-bear GitHub](https://github.com/hasherezade/pe-bear)).
   - (c) A stripped/minimal import table, because the real imports are reconstructed at runtime by the stub. The stub typically only needs `LoadLibraryA`, `GetProcAddress`, and `VirtualAlloc` to bootstrap the unpacking process ([UPX GitHub](https://github.com/upx/upx)). The *nuance*: `UPX0` typically shows a large virtual size (e.g., 0x10000) but a raw (on-disk) size of 0 — the decompressed code has nowhere to live on disk, only in memory. This is a key indicator of **T1027.002**.

3. Compare readable strings before unpacking with FLOSS.
```powershell
# Extract strings from the packed sample; the marker should be hidden/absent.
floss .\exercise\sample_packed.exe > .\exercise\floss_packed.txt
Select-String -Path .\exercise\floss_packed.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"
```
Expected output: no match (the marker string is compressed away in the packed image).
**Why:** FLOSS first runs a static-strings pass (like `strings`) and then attempts to automatically extract *obfuscated* strings (stack strings, tight strings, and emulated decoded strings). On a UPX-packed file the marker lives inside the compressed `UPX1` blob, so it does not appear as a contiguous ASCII/UTF-16 run to the static pass. The *nuance*: FLOSS may still surface stub/loader artifacts (e.g., the `UPX!` magic or library names the stub needs), which is exactly the "almost no useful strings, but obvious loader residue" pattern analysts learn to recognize. FLOSS v3.0+ also extracts stack strings, which can reveal obfuscated strings pushed onto the stack at runtime ([flare-floss GitHub](https://github.com/mandiant/flare-floss)).

4. Run under x64dbg, reach OEP, and dump. In the GUI:
   - File → Open `exercise\sample_packed.exe`.
   - The UPX stub decompresses `UPX1` into the `UPX0` region and finishes with a tail `jmp` that transfers control to the Original Entry Point (OEP). A reliable manual technique for UPX is to:
     1. Note that the stub begins with `pushad` (saving all registers) and restores them with `popad` near the end.
     2. Set a **hardware breakpoint** on the stack region after `pushad` (e.g., `bp hw4 @ esp` in x64dbg).
     3. Run (`F9`) until the breakpoint fires just before the tail `jmp` to OEP.
     - Alternatively, use "Run until user code" (`Ctrl+F9`) or step (`F7`/`F8`) to the far jump.
   - Once paused at OEP, dump the process with the bundled Scylla plugin (*Plugins → Scylla*):
     1. Click **Dump** to save the process memory to a file (e.g., `sample_dumped.exe`).
     2. Click **IAT Autosearch** to locate the Import Address Table (IAT) in memory.
     3. Click **Get Imports** to reconstruct the import table.
     4. Click **Fix Dump** to produce a reconstructed, statically-analyzable executable.
   **Why:** x64dbg is a live debugger, so it lets the file unpack *itself* in memory — you never have to reverse the compression algorithm by hand. The reason to stop precisely at OEP is that this is the moment the original code is fully decompressed but has not yet run; dumping here captures the clean image. Scylla's IAT reconstruction matters because the raw memory dump has runtime-resolved import pointers that a static tool cannot follow — "Fix Dump" rewrites a valid import directory so PE-bear/FLOSS can parse it. The `pushad`/`popad` sequence is a hallmark of UPX and many other packers, as it preserves the register state before/after the unpacking stub ([UPX GitHub](https://github.com/upx/upx)). The tail `jmp` to OEP is a key artifact for **T1140 Deobfuscate/Decode Files or Information**.

5. Confirm the dump is now readable with FLOSS.
```powershell
floss .\exercise\sample_dumped.exe > .\exercise\floss_dumped.txt
Select-String -Path .\exercise\floss_dumped.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"
```
Expected output: the marker string `BENIGN-UNPACK-LAB-MARKER-52` now appears.
**Why:** After unpacking, the decompressed `.rdata`/`.text` are present as plain bytes in the dump, so the static-strings pass recovers the marker. This before/after delta is the concrete, measurable proof that your unpack succeeded. The unpacked binary will also show a richer import table (e.g., `msvcrt.dll` for `printf`), demonstrating **T1083 File and Directory Discovery** for post-unpacking analysis. FLOSS's stack string extraction may also reveal additional strings not visible in the static pass ([flare-floss GitHub](https://github.com/mandiant/flare-floss)).

## Hands-on exercise
Using the sample in this module's `exercise/` dir, complete the full workflow:
1. In PE-bear, record the two section names and the highest section entropy of `sample_packed.exe`. Note the virtual size vs raw size of `UPX0`.
2. Run FLOSS against the packed file and count matches for the marker string (should be 0). Use `floss -n 4` to also extract stack strings and observe any stub artifacts.
3. Unpack `sample_packed.exe` in x64dbg:
   - Set a hardware breakpoint after `pushad` to catch the tail `jmp` to OEP.
   - Dump the process at OEP using Scylla, and verify the import table is rebuilt.
4. Run FLOSS against the dumped file and confirm the marker string is recovered. Compare the import table in PE-bear before/after unpacking.

Sample declaration:
- **Type:** UPX-packed 64-bit Windows PE executable (`sample_packed.exe`).
- **Safe origin:** Benign/inert — generated locally from the `hello.c` source shown above (prints one marker line, performs no network or file activity). NO live malware is used.
- **Reproducible generator:** the `cl` + `upx --best` commands in the Guided walkthrough build the sample deterministically inside `exercise/`. (Because UPX/toolchain versions vary, verify the *pre-pack* binary instead — see Answer key.)

## SOC analyst perspective
A defender rarely unpacks by hand in production, but understanding packing drives detection. Packed samples raise high-entropy alerts and yield almost no useful static strings, so a SOC pivots to behavior and memory forensics.

- **Static/scan-time detection:**
  - High per-section entropy (~7.5–8.0) plus non-standard section names (`UPX0`/`UPX1`) and a near-empty import table are classic YARA/AV heuristics for **T1027.002 (Software Packing)**. The `UPX!` magic marker in the stub is a well-known signature ([MITRE ATT&CK T1027.002](https://attack.mitre.org/techniques/T1027/002/)).
  - **YARA rule example (conceptual):** `rule UPX_Packer { strings: $upx_magic = "UPX!" condition: $upx_magic and uint16(0) == 0x5A4D }` ([YARA docs](https://virustotal.github.io/yara/)).
  - **Microsoft Defender ATP** surfaces entropy-based detections for packed files ([Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/detect-packed-files)).

- **Behavioral detection in Security Onion:**
  - **Sysmon Event ID 1 (Process Create):** Unusual parent/child chains (e.g., `sample_packed.exe` spawning `cmd.exe` or `powershell.exe`) and command lines. Ingest via Elastic and hunt in Kibana/Security Onion Console for processes with high entropy sections ([Microsoft Learn Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).
    - **Hunt pivot:** `event.code: 1 and file.entropy: [7.5 TO 8.0]` in Elastic.
  - **Sysmon Event ID 7 (Image Load):** Suspicious DLL loads (e.g., `kernel32.dll!VirtualAlloc` with `PAGE_EXECUTE_READWRITE` permissions) during unpacking, mapping to **T1055.001 Process Injection: Dynamic-Link Library Injection** ([MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)).
    - **Hunt pivot:** `event.code: 7 and winlog.event_data.ImageLoaded: "*kernel32.dll" and winlog.event_data.ImageLoaded: "*VirtualAlloc*"`.
  - **Sysmon Event ID 8 (CreateRemoteThread) / Event ID 10 (ProcessAccess):** Self-unpacking that maps to **T1140 (Deobfuscate/Decode Files or Information)** often precedes memory allocation and, in real malware, injection into a host process — **T1055 (Process Injection)** and its sub-techniques.
    - **Hunt pivot:** `event.code: 8 and winlog.event_data.TargetImage: "lsass.exe"` (common target for credential dumping via **T1003**).
  - **Memory forensics:** Volatility or Rekall can detect RWX memory regions (`malfind` plugin) and unpacked code in memory, tying to **T1055.001** and **T1055.002** ([Volatility Foundation](https://www.volatilityfoundation.org/)).
    - **Volatility command:** `volatility -f memory.dmp malfind --dump-dir=output`.

- **Zeek + Suricata pivots:**
  - **Zeek `conn.log`:** Pivot on `id.orig_h`/`id.resp_h` for C2 IOCs recovered from the *unpacked* image. UPX-packed malware often uses **T1071 Application Layer Protocol** (e.g., HTTP, DNS) for C2 ([Zeek docs](https://docs.zeek.org/en/master/logs/conn.html)).
    - **Hunt pivot:** `zeek.conn.id.orig_h: "192.168.1.100" and zeek.conn.service: "http"`.
  - **Zeek `dns.log`:** Look for DGA-like domains or unusual TLDs (e.g., `.xyz`, `.top`) extracted from the unpacked binary, mapping to **T1071.004** ([Zeek docs](https://docs.zeek.org/en/master/logs/dns.html)).
  - **Suricata alerts:** Pivot on `alert.signature` for rules like `ET MALWARE UPX Packed Executable Download` or `ET TROJAN UPX Packed C2 Traffic` ([Suricata docs](https://docs.suricata.io/en/suricata-6.0.0/rules/intro.html)).
    - **Hunt pivot:** `event.dataset: "suricata" and suricata.eve.alert.signature: "*UPX*"`.

- **Feeding the hunt loop:**
  - FLOSS output on a dumped image feeds IOC extraction (C2 hosts, mutexes, user-agents) that become Suricata and YARA rules. For example, a recovered C2 domain becomes a Suricata rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE C2 Domain"; content:".evil.com"; sid:1000001;)` ([Suricata docs](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/)).
  - **MITRE ATT&CK Navigator:** Map recovered TTPs (e.g., **T1027.002**, **T1140**, **T1055**) to the ATT&CK matrix to prioritize detections ([MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)).
  - **Microsoft Defender for Endpoint:** Use the "Advanced Hunting" feature to query for `FileProfile` events with high entropy or `ProcessCreation` events with packed parent processes ([Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-hunting-fileprofile-table)).

## Attacker perspective
Attackers pack payloads to defeat signature scanners, hide C2 strings, and slow analysts (**T1027 / T1027.002**). A packer adds a stub that decompresses (or decrypts) the real code into memory at runtime and jumps to the OEP, leaving only the loader visible on disk. Packing is often combined with other techniques like **T1036 Masquerading** (renaming sections) or **T1564.003 Hide Artifacts: Hidden Window** to evade detection.

- **Concrete TTPs:**
  - **Off-the-shelf packers:** UPX, Themida, VMProtect, and custom crypters. UPX is widely used due to its open-source nature and effectiveness ([UPX GitHub](https://github.com/upx/upx)).
  - **Runtime deobfuscation:** The unpacking stub uses **T1140 Deobfuscate/Decode Files or Information** to reconstruct the original code in memory. This often involves `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` permissions (**T1055.001**).
  - **Process Injection:** After unpacking, the payload may inject into a legitimate process (e.g., `explorer.exe`, `svchost.exe`) using **T1055 Process Injection**, specifically **T1055.001 DLL Injection** or **T1055.002 Portable Executable Injection** ([MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)).
  - **Reflective Code Loading:** Some packers use **T1620 Reflective Code Loading** to load the unpacked payload directly into memory without touching disk ([MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)).
  - **Anti-analysis:** Packers may include anti-debug (**T1622 Debugger Evasion**) or anti-VM checks (**T1633 Virtualization/Sandbox Evasion**) to hinder analysis ([MITRE ATT&CK T1622](https://attack.mitre.org/techniques/T1622/), [T1633](https://attack.mitre.org/techniques/T1633/)).

- **Artifacts the technique leaves:**
  - **Static artifacts:**
    - Abnormal section names (`UPX0`/`UPX1`, `.vmp0`/`.vmp1` for VMProtect) — **T1036 Masquerading**.
    - Section entropy near 8.0 (compressed/encrypted data) — **T1027.002**.
    - A `UPX0` section with virtual size >> raw size (e.g., 0x10000 vs 0) — **T1027.002**.
    - A stripped import table (only `kernel32.dll`, `ntdll.dll`) — **T1027.002**.
    - Magic markers (e.g., `UPX!`, `Themida`) — **T1027.002**.
  - **Dynamic artifacts:**
    - RWX memory regions during/after unpacking — **T1055.001**.
    - A `pushad`/`popad`-bracketed stub (UPX) — **T1140**.
    - A distinctive tail `jmp` to the OEP — **T1140**.
    - Sysmon Event ID 7 (Image Load) for `kernel32.dll!VirtualAlloc` with `PAGE_EXECUTE_READWRITE` — **T1055.001**.
    - Sysmon Event ID 10 (ProcessAccess) if the unpacked payload injects into another process — **T1055**.
    - Volatility `malfind` output showing RWX regions with injected code — **T1055.001**.

- **Evasion:**
  - **Renaming sections:** Adversaries rename UPX sections (e.g., `.text`/`.data` instead of `UPX0`/`UPX1`) to evade signature-based detection (**T1036 Masquerading**).
  - **Corrupting/stripping magic markers:** Removing the `UPX!` marker breaks `upx -d` and evades simple YARA rules.
  - **Anti-debug/anti-VM:** Adding checks for debuggers (e.g., `IsDebuggerPresent`) or VM artifacts (e.g., `in` instructions, `cpuid` checks) before unpacking — **T1622** and **T1633**.
  - **Multi-layer packing:** Nesting packers (e.g., UPX inside Themida) to complicate analysis — **T1027.002**.
  - **Delayed decoding:** Using **T1070.006 Timestomp** or **T1053 Scheduled Task** to delay unpacking until a specific time or condition is met — **T1053.005** ([MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)).
  - **Custom packing:** Writing a custom packer to avoid known signatures — **T1027.002**.
  - **Countermeasure trade-offs:** Each evasion technique typically adds *more* anomalous structure or timing that defenders can key on. For example:
    - Renaming sections may break compatibility with the packer's stub, requiring custom code.
    - Anti-debug checks add detectable artifacts (e.g., `IsDebuggerPresent` calls in the import table).
    - Multi-layer packing increases entropy and section count, making the file more suspicious.

## Answer key
- **PE-bear:**
  - Sections: `UPX0` and `UPX1`.
  - Packed section entropy: roughly 7.5–7.9 (compressed data trends toward the 8.0 bits/byte maximum).
  - `UPX0` virtual size: ~0x10000 (or similar), raw size: 0.
- **FLOSS (packed):**
  - `Select-String -Path .\exercise\floss_packed.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"` returns 0 matches.
  - `floss -n 4 .\exercise\sample_packed.exe` may show stub artifacts (e.g., `UPX!`, `kernel32.dll`).
- **FLOSS (dumped):**
  - After x64dbg unpack + Scylla dump, `Select-String -Path .\exercise\floss_dumped.txt -Pattern "BENIGN-UNPACK-LAB-MARKER-52"` returns ≥1 match.
  - The import table in PE-bear will show additional DLLs (e.g., `msvcrt.dll` for `printf`).
- Reproduce the string checks:
```powershell
floss .\exercise\sample_packed.exe | Select-String "BENIGN-UNPACK-LAB-MARKER-52"   # 0 hits
floss -n 4 .\exercise\sample_packed.exe | Select-String "UPX!"                      # ≥1 hit (stub artifact)
floss .\exercise\sample_dumped.exe | Select-String "BENIGN-UNPACK-LAB-MARKER-52"   # ≥1 hit
```
- **Integrity check (pre-pack binary is deterministic per toolchain):**
```powershell
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
Sample sha256 (of the locally built unpacked reference `sample.exe`; recorded by the validator on first build):
`c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

## MITRE ATT&CK & DFIR phase
- **T1027.002** — Obfuscated Files or Information: Software Packing — [MITRE ATT&CK T1027.002](https://attack.mitre.org/techniques/T1027/002/)
- **T1027** — Obfuscated Files or Information (parent technique) — [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- **T1140** — Deobfuscate/Decode Files or Information (the runtime unpacking stub) — [MITRE ATT&CK T1140](https://attack.mitre.org/techniques/T1140/)
- **T1055** — Process Injection (relevant when real malware unpacks into a host process) — [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- **T1055.001** — Process Injection: Dynamic-Link Library Injection — [MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- **T1036** — Masquerading (renaming sections to evade detection) — [MITRE ATT&CK T1036](https://attack.mitre.org/techniques/T1036/)
- **T1083** — File and Directory Discovery (post-unpacking analysis) — [MITRE ATT&CK T1083](https://attack.mitre.org/techniques/T1083/)
- **T1620** — Reflective Code Loading (advanced packers) — [MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)
- **DFIR phase:** Examination / Analysis (malware static+dynamic reverse engineering).


### Essential Commands & Features

While basic debugging in **x64dbg** is covered, mastering these advanced features will significantly improve your analysis efficiency and resilience against anti-debugging techniques:

1. **Conditional Breakpoints**
   Use conditional breakpoints to pause execution only when specific criteria are met, reducing noise during analysis.
   *Example:* Set a breakpoint at `0x00401234` that triggers only if `EAX == 0x55`:
   ```
   bp 0x00401234, "eax == 0x55"
   ```
   *When to use:* Ideal for tracking specific API calls (e.g., `VirtualAlloc` with `MEM_COMMIT`) or register states tied to **T1480.001 (Execution Guardrails: Environmental Keying)**.

2. **Script Automation**
   Automate repetitive tasks (e.g., logging function arguments) using x64dbg’s built-in scripting engine.
   *Example:* Log all calls to `WriteProcessMemory` with their arguments:
   ```python
   log("WriteProcessMemory called with args: {0}, {1}, {2}, {3}, {4}",
       [arg.get(1), arg.get(2), arg.get(3), arg.get(4), arg.get(5)])
   ```
   *When to use:* Critical for analyzing **T1106 (Native API)** abuse, such as process injection or hooking.

3. **Exception Handling for Anti-Debug Evasion**
   Configure x64dbg to intercept and ignore exceptions commonly used for anti-debugging (e.g., `INT3`, `SEH`).
   *Example:* Ignore `EXCEPTION_BREAKPOINT` (0x80000003) to bypass `IsDebuggerPresent` checks:
   ```
   SetExceptionHandler 0x80000003, "ignore"
   ```
   *When to use:* Counters **T1622 (Debugger Evasion)** by suppressing exceptions like `OutputDebugString` crashes.

**Authoritative Sources:**
- [x64dbg Scripting Documentation (GitBook)](https://x64dbg.com/script/)
- [SANS FOR610: Reverse-Engineering Malware (Anti-Debugging Section)](https://www.sans.org/blog/anti-debugging-techniques-cheat-sheet/)

### Threat Hunting & Detection Engineering
To detect and hunt for threats related to the 52-unpacking-case, focus on identifying suspicious patterns in system and network logs. Analyze Windows Event ID 4688 (Process Creation) for unusual process executions, particularly those involving unsigned or unknown binaries. Additionally, monitor for T1588 (Obtain Capabilities) and T1204 (User Execution) techniques, where attackers may attempt to obtain or execute capabilities, such as exploiting vulnerabilities or using social engineering tactics to trick users into executing malicious code. Inspect Zeek logs for unusual DNS queries or HTTP requests that may indicate malicious activity. Threat hunters can pivot on fields like `process_command_line` or `dns_query` to uncover related events. By combining these detection methods, security teams can improve their ability to identify and respond to potential threats. For more information on threat hunting and detection engineering, visit the Cyber and Infrastructure Security Agency (CISA) website at [https://www.cisa.gov](https://www.cisa.gov) or the National Institute of Standards and Technology (NIST) Computer Security Resource Center at [https://csrc.nist.gov](https://csrc.nist.gov).

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **FLOSS behavior, `--version`, static + obfuscated/stack/tight string extraction** — Mandiant flare-floss repo — [https://github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss)
- **FLOSS v3.0+ stack/tight string extraction** — flare-floss GitHub — [https://github.com/mandiant/flare-floss#string-extraction](https://github.com/mandiant/flare-floss#string-extraction)
- **FLARE-VM ships x64dbg, PE-bear, FLOSS via Chocolatey (paths vary by version)** — FLARE-VM GitHub — [https://github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)
- **x64dbg is an open-source x64/x32 user-mode debugger; GUI, breakpoints, Scylla plugin for dumping/IAT rebuild** — x64dbg documentation — [https://help.x64dbg.com/en/latest/](https://help.x64dbg.com/en/latest/)
- **Scylla dump + IAT Autosearch/Get Imports/Fix Dump for import reconstruction** — Scylla project — [https://github.com/NtQuery/Scylla](https://github.com/NtQuery/Scylla)
- **PE-bear PE section table, entropy calculation, and import viewing** — PE-bear (hasherezade) — [https://github.com/hasherezade/pe-bear](https://github.com/hasherezade/pe-bear)
- **Shannon entropy formula and packing detection** — PE-bear GitHub — [https://github.com/hasherezade/pe-bear#entropy](https://github.com/hasherezade/pe-bear#entropy)
- **UPX packer: `--best` compression level, `UPX0`/`UPX1` sections, self-decompression stub, `upx -d` decompression** — UPX project — [https://upx.github.io/](https://upx.github.io/) and README — [https://github.com/upx/upx](https://github.com/upx/upx)
- **UPX `pushad`/`popad` sequence and tail `jmp` to OEP** — UPX GitHub — [https://github.com/upx/upx/blob/master/src/stub/src/i386-win32.pe.cpp](https://github.com/upx/upx/blob/master/src/stub/src/i386-win32.pe.cpp)
- **Windows compiler `cl.exe` flags (`/Fe`, `/nologo`)** — Microsoft Learn (MSVC command-line reference) — [https://learn.microsoft.com/en-us/cpp/build/reference/compiler-command-line-syntax](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-command-line-syntax)
- **Sysmon Event IDs 1/7/8/10 (Process Create, Image Load, CreateRemoteThread, ProcessAccess) for behavioral detection** — Microsoft Learn (Sysmon) — [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Security Onion Suricata/Zeek/Elastic pivots** — Security Onion documentation — [https://docs.securityonion.net/](https://docs.securityonion.net/)
- **Zeek logs (conn/dns/http)** — Zeek documentation — [https://docs.zeek.org/en/master/logs/index.html](https://docs.zeek.org/en/master/logs/index.html)
- **Suricata rules/alerting** — Suricata documentation — [https://docs.suricata.io/](https://docs.suricata.io/)
- **YARA rule syntax and examples** — YARA documentation — [https://virustotal.github.io/yara/](https://virustotal.github.io/yara/)
- **Microsoft Defender ATP entropy-based detections** — Microsoft Learn — [https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/detect-packed-files](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/detect-packed-files)
- **Volatility `malfind` plugin for RWX memory detection** — Volatility Foundation — [https://www.volatilityfoundation.org/](https://www.volatilityfoundation.org/) and [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal)
- **MITRE ATT&CK T1027 / T1027.002 / T1140 / T1055 / T1055.001 / T1036 / T1083 / T1620** — MITRE ATT&CK — [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/), [https://attack.mitre.org/techniques/T1027/002/](https://attack.mitre.org/techniques/T1027/002/), [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/), [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/), [https://attack.mitre.org/techniques/T1055/001/](https://attack.mitre.org/techniques/T1055/001/), [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/), [https://attack.mitre.org/techniques/T1083/](https://attack.mitre.org/techniques/T1083/), [https://attack.mitre.org/techniques/T1620/](https://attack.mitre.org/techniques/T1620/)
- **SANS FOR508 (Memory Forensics) and FOR610 (Reverse-Engineering Malware) for unpacking workflow context** — SANS — [https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/), [https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)

## Related modules
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- shares floss for fast pre-detonation string triage.
- [Static reverse engineering](../12-static-re/README.md) -- shares floss and covers reading unpacked code statically.
- [PE static analysis deep-dive](../30-pe-static-deep/README.md) -- shares floss and expands on PE section/entropy/import analysis.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- shares x64dbg for memory-based extraction and dumping.

<!-- cyberlab-enriched: v2 -->
- https://x64dbg.com/script/
- https://www.sans.org/blog/anti-debugging-techniques-cheat-sheet/
- https://www.cisa.gov](https://www.cisa.gov
- https://csrc.nist.gov](https://csrc.nist.gov

<!-- cyberlab-enriched: v3 -->
