# 61 * Emulation-based malware analysis (Speakeasy / Qiling) -- LAB-WINDOWS

## Overview (plain language)
Emulation runs malware instruction-by-instruction inside a virtual CPU + faked OS, so you observe behavior (API calls, network, dropped files) without ever executing it on a real system. Speakeasy targets Windows PE/shellcode; Qiling is a scriptable cross-arch framework. Safer and faster than a live sandbox for many samples.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Speakeasy | pip install speakeasyemulator | Mandiant PE/shellcode emulator: run malware in a virtualized Windows env and log API calls without native execution |
| Qiling | pip install qiling | Cross-platform/cross-arch binary emulation framework with scriptable hooks |
| Unicorn Engine | pip install unicorn | CPU emulator engine underpinning Qiling and many analysis tools |

## Learning objectives
- Emulate a PE or shellcode sample with Speakeasy and read its API-call trace
- Script Qiling to hook and instrument a sample's execution
- Recover behavior/IOCs (URLs, files, registry) without running malware natively
- Understand when emulation beats a debugger or a full sandbox

## Environment check
Confirm `speakeasy -h` and `python -c 'import qiling'` work. Emulate only the provided benign lab samples. No native execution occurs, but treat samples as untrusted.

## Guided walkthrough
1. Emulate a PE and log behavior: `speakeasy -t sample.exe -o report.json` (dumps API calls, memory, dropped artifacts).
2. Review the API trace for network (`InternetOpenUrl`), filesystem (`CreateFile`), and registry calls → extract IOCs.
3. For shellcode: `speakeasy -t sc.bin -r -a x86` to emulate raw shellcode and capture called APIs.
4. Script Qiling to hook an API: load the PE, register a hook on `CreateFileW`, and print each path the sample touches.
5. Compare emulation findings to a scdbg run (module 31) to cross-validate the API sequence.

## Hands-on exercise
Emulate the provided `sample.exe` with Speakeasy, extract the C2 URL and any dropped filename from the API trace, and confirm the same `InternetOpenUrlA` call by hooking it in Qiling.

## SOC analyst perspective
Emulation gives analysts fast, contained behavioral triage — API traces and IOCs (URLs, mutexes, files) — without standing up a full detonation sandbox, ideal for high-volume or evasive samples that detect VMs.

## Attacker perspective
Malware uses anti-VM/anti-debug and API hashing to resist analysis. Emulators sidestep some anti-analysis (no real OS to fingerprint) but authors add anti-emulation checks (unsupported APIs, timing) that analysts must recognize.

## Answer key
Speakeasy's JSON report lists the `InternetOpenUrlA`/`InternetConnect` call with the C2 URL and `CreateFile` with the dropped path. The Qiling hook on `CreateFileW`/`InternetOpenUrlA` prints the same values, cross-validating.

## MITRE ATT&CK & DFIR phase
- **T1106** — Native API — emulation logs the Windows API calls malware makes
- **T1027** — Obfuscated Files or Information — emulation resolves behavior despite packing
- **T1620** — Reflective Code Loading — emulated memory reveals in-memory code

## Sources
- Speakeasy: https://github.com/mandiant/speakeasy
- Qiling Framework: https://github.com/qilingframework/qiling
- Unicorn Engine: https://www.unicorn-engine.org/

## Related modules
- - 31-shellcode-deep — scdbg shellcode emulation
- - 17-shellcode-analysis — shellcode fundamentals
