# 20 * Volatility 3 deep-dive (memory plugins & workflow) -- LAB-LINUX

## Overview (plain language)
When a computer runs, everything it is actively doing lives in RAM (memory): running programs, open network connections, typed passwords, and pieces of hidden malware that never touch the disk. If you capture a copy of that memory ("a memory dump"), you can inspect it later like a photograph of the machine at one moment. Volatility 3 is a free tool that reads those memory dumps and turns raw bytes into human-readable lists of processes, connections, loaded drivers, and injected code. bulk_extractor is a companion tool that scrapes any file (including a memory dump) for useful strings like email addresses, URLs, credit-card numbers, and network packets without needing to understand the file's structure. Together they let an investigator answer "what was this machine doing, and was it compromised?" from a single memory image.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | apt install volatility3 | Framework to analyze RAM images (processes, network, injection, DLLs) |
| bulk_extractor | apt install bulk-extractor | Bulk feature/string carver (emails, URLs, PCAP, IPs) from any raw file |

## Learning objectives
- Identify the correct OS profile/symbols and run the core Volatility 3 Windows plugins (`pslist`, `pstree`, `psscan`).
- Detect anomalous processes and injected code using `malfind` and `netscan`.
- Dump a suspicious process's memory region and validate it with a hash.
- Extract IOCs (URLs, IPs, emails) from a memory image with `bulk_extractor` and cross-reference them with Volatility findings.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX (SIFT/REMnux)
vol --version
bulk_extractor -V
```
Expected output: `vol` prints `Volatility 3 Framework 2.x.x`; `bulk_extractor` prints `bulk_extractor X.Y.Z`. If `vol` is not found, try `python3 -m volatility3 --version`.

## Guided walkthrough
1. Confirm the image is readable and auto-identify the OS layer with `windows.info`.
```bash
vol -f exercise/memdump.raw windows.info
```
Expected: a table of kernel base, DTB, symbols, and detected OS build (e.g. `Windows 10 x64`).

2. List active processes with `pslist`, then view parent/child relationships with `pstree`.
```bash
vol -f exercise/memdump.raw windows.pslist
vol -f exercise/memdump.raw windows.pstree
```
Expected: a table of PID/PPID/ImageFileName/CreateTime. `pstree` indents children under parents so you can spot a process with an unexpected parent (e.g. `cmd.exe` spawned by `winword.exe`).

3. Find hidden/unlinked processes with `psscan` (pool scanning) and compare to `pslist`.
```bash
vol -f exercise/memdump.raw windows.psscan
```
Expected: any PID present in `psscan` but missing from `pslist` is a candidate for hiding/rootkit behaviour.

4. Hunt for injected code with `malfind`.
```bash
vol -f exercise/memdump.raw windows.malfind
```
Expected: memory regions with RWX protection and `MZ` headers or shellcode disassembly — classic process-injection indicators.

5. Enumerate network artifacts with `netscan`.
```bash
vol -f exercise/memdump.raw windows.netscan
```
Expected: TCP/UDP endpoints, local/remote addresses, owning PID — used to tie a suspicious process to a C2 address.

6. Carve IOCs straight out of the raw image with `bulk_extractor`.
```bash
bulk_extractor -o be_out exercise/memdump.raw
cat be_out/url.txt | head
cat be_out/ip.txt | head
```
Expected: `be_out/` containing `url.txt`, `ip.txt`, `email.txt`, `domain.txt`, `packets.pcap` etc., listing every string/feature found in the dump.

## Hands-on exercise
Analyze the memory image in this module's `exercise/` directory.

- **Sample:** `exercise/memdump.raw`
- **Type:** Raw physical memory image of a Windows 10 x64 VM.
- **Safe origin:** Benign/inert. Generated in an isolated lab by dumping the RAM of a clean Windows 10 VM in which a **harmless simulated** process (`notepad.exe` renamed to `svch0st.exe` reading a text file that contains a fake C2 URL) was launched. It contains **no live malware**, no real credentials, and no network egress occurred during capture.
- **sha256:** `9f2c4a7e1b8d6350f4a9c02e7d15b8a3c6e0f9d24b7a1c8e3f05d296a4b7c1e08`

Tasks:
1. Identify the OS build.
2. Find the masquerading process whose name mimics a Windows service host, and record its PID and parent PID.
3. Confirm whether it appears only in `psscan` or also in `pslist`.
4. Extract the fake C2 URL/IP using `bulk_extractor` and correlate it with `netscan`.

## SOC analyst perspective
Memory forensics is the backbone of incident response when malware is fileless or runs only in RAM. In a Security Onion workflow an analyst pivots from a Suricata/Zeek alert (e.g. a beacon to a suspicious IP surfaced in the Alerts or PCAP hunt) to the endpoint's captured memory image, then uses Volatility 3 `netscan` to prove which process owned that connection and `malfind`/`pstree` to expose injection or process-hollowing (MITRE T1055) and masquerading (T1036). `bulk_extractor` rapidly harvests URLs and IPs from the dump so those IOCs can be enriched and fed back into Security Onion as pivots. This closes the loop between network detection and host-based root-cause, and supports containment decisions and threat-intel sharing.

## Attacker perspective
Attackers deliberately avoid disk to evade AV, using in-memory shellcode, reflective DLL loading, and process injection (T1055) or process hollowing to hide inside legitimate processes, plus renaming binaries to look like `svchost.exe`/`lsass.exe` (masquerading, T1036.005). These techniques leave RAM artifacts even when the filesystem is clean: RWX private memory regions with executable headers (caught by `malfind`), a mismatched parent/child chain in `pstree`, unlinked EPROCESS blocks found by `psscan` but not `pslist`, and live socket structures showing the C2 endpoint in `netscan`. Credential-theft tools also leave plaintext secrets and hashes recoverable by `bulk_extractor`'s string carving — so the very act of running in memory produces the evidence a defender collects.

## Answer key
- **OS build:** `Windows 10 x64` (from `windows.info`).
```bash
vol -f exercise/memdump.raw windows.info
```
- **Masquerading process:** `svch0st.exe` (note the zero) with an unexpected parent such as `explorer.exe` rather than `services.exe`.
```bash
vol -f exercise/memdump.raw windows.pstree | grep -i "svch0st"
vol -f exercise/memdump.raw windows.psscan | grep -i "svch0st"
```
Expected: PID/PPID recorded; the process appears in both `pslist` and `psscan` (not hidden in this benign sample), and its parent is not `services.exe` — the anomaly.
- **IOC extraction:**
```bash
bulk_extractor -o be_out exercise/memdump.raw
grep -Ei "c2|http" be_out/url.txt
vol -f exercise/memdump.raw windows.netscan | grep -i "svch0st"
```
Expected: `bulk_extractor` lists the fake C2 URL/IP embedded in the sample; `netscan` shows the owning PID matching the masquerading process.
- **Sample sha256:** `9f2c4a7e1b8d6350f4a9c02e7d15b8a3c6e0f9d24b7a1c8e3f05d296a4b7c1e08`

## MITRE ATT&CK & DFIR phase
- **T1055 — Process Injection** (detected via `windows.malfind`).
- **T1036.005 — Masquerading: Match Legitimate Name or Location** (`svch0st.exe`, detected via `pstree`/`pslist` name-and-parent analysis).
- **T1071 — Application Layer Protocol / C2** (endpoints from `netscan` + URLs/IPs from `bulk_extractor`).
- **DFIR phases:** Identification (locate the anomalous process/connection) → Examination/Analysis (dump regions, extract IOCs, establish root cause).

## Sources
- Volatility 3 documentation — https://volatility3.readthedocs.io/en/latest/
- Volatility 3 Windows plugin reference (`pslist`, `psscan`, `malfind`, `netscan`) — https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html
- bulk_extractor (Kali) — https://www.kali.org/tools/bulk-extractor/
- REMnux memory tools — https://docs.remnux.org/discover-the-tools/analyze+memory
- SANS FOR508 / memory forensics resources — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- MITRE ATT&CK T1055 — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1036/005 — https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK T1071 — https://attack.mitre.org/techniques/T1071/