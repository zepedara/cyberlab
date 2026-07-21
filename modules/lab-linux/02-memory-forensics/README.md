# 02 * Memory forensics -- LAB-LINUX

## Overview (plain language)
When a computer is running, its short-term memory (RAM) holds a live snapshot of everything happening right now: running programs, open network connections, typed passwords, and even encryption keys. Unlike the hard disk, this data disappears when the machine powers off. Memory forensics is the practice of capturing that RAM into a file (a "memory image") and then digging through it to reconstruct what was going on. The tools in this module read those raw memory dumps: Volatility 3 lists processes, connections, and injected code; bulk_extractor sweeps the dump for interesting strings like emails, URLs, and card numbers; and aeskeyfind and rsakeyfind hunt for cryptographic keys hiding in memory. Together they let an investigator answer "what was this machine doing when it was captured?" without trusting the possibly-compromised operating system.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | `apt install volatility3` | Framework to parse RAM images (processes, DLLs, network, injected code) |
| bulk_extractor | `apt install bulk-extractor` | Scans raw images/dumps for features (emails, URLs, PII, PCAP) |
| aeskeyfind | `apt install aeskeyfind` | Locates AES key schedules resident in a memory dump |
| rsakeyfind | `apt install rsakeyfind` | Locates RSA private keys/certificates resident in a memory dump |

Notes on the tool facts above (verify against source):
- Volatility 3 is a Python framework that is OS-agnostic on input and selects `windows.*`, `linux.*`, or `mac.*` plugins depending on the image; the CLI entry point is `vol` (also `vol.py`). See the official docs (Volatility Foundation / readthedocs).
- bulk_extractor scans any input (disk image, memory dump, raw file) for *features* using scanners, and writes one feature file per scanner (`url.txt`, `email.txt`, `domain.txt`, etc.); it can also carve a `packets.pcap` from network-looking data. See the simsong/bulk_extractor repo.
- aeskeyfind and rsakeyfind originate from the Princeton "Lest We Remember" cold-boot research; aeskeyfind searches for AES key *schedules* (the expanded round keys), and rsakeyfind searches for RSA private keys/BER-encoded structures.

## Learning objectives
- Verify the memory-forensics toolchain is installed and runnable on LAB-LINUX.
- Enumerate processes and network artifacts from a RAM image using Volatility 3 plugins.
- Extract embedded features (URLs, emails) from a raw dump with bulk_extractor.
- Recover candidate AES/RSA cryptographic keys from memory with aeskeyfind and rsakeyfind.
- Map memory-forensics findings to MITRE ATT&CK techniques and DFIR examination phases.

## Environment check
```bash
# Prove each tool is present on the VM
vol --help | head -n 3
bulk_extractor -V
aeskeyfind 2>&1 | head -n 1
rsakeyfind 2>&1 | head -n 1
```
Expected output: `vol` prints Volatility 3 usage/banner (the framework's argparse help; `vol` is the console entry point installed by the `volatility3` package — see the Volatility 3 docs and Kali package page). `bulk_extractor -V` prints a version banner such as `bulk_extractor 2.x.x` (the `-V` flag is documented in the simsong/bulk_extractor repo). `aeskeyfind` and `rsakeyfind` print their usage lines because they were invoked with no input argument (both require a memory-image path as their argument, per the Princeton "Lest We Remember" tool documentation).

## Guided walkthrough
Each command below is annotated with WHY it is run and what nuance to read in the output.

1. `vol -f $IMAGE windows.info` — confirms Volatility can actually parse the dump and reports the OS/kernel build; this is the first sanity check because every downstream `windows.*` plugin depends on Volatility correctly identifying the profile/symbols for the image. Before touching a real image, list what plugins exist:
```bash
vol -h | grep -i -E "pslist|netscan|windows.info" | head -n 10
```
Expected: plugin names such as `windows.pslist`, `windows.netscan`, `windows.info` are listed. WHY: Volatility 3 replaced the v2 profile system with automatic symbol-table detection, so plugin names are namespaced by OS (`windows.`, `linux.`, `mac.`). Seeing them confirms the framework and its symbol packs are installed (Volatility 3 docs). NOTE: the synthetic `sample.mem` in this module is an inert byte blob with **no** OS structures, so `windows.info`/`windows.pslist` will not return a valid Windows profile against it — those steps illustrate the workflow you would run against a real Windows RAM capture. Nuance: `windows.info` reads the `KDBG`/`KUSER_SHARED_DATA` structures to report the NT build number and kernel base; if it errors with a symbol-table failure, Volatility could not match the image to a symbol pack (wrong OS, truncated capture, or a hibernation/crash-dump format needing conversion) — that is a data-quality signal, not a "no findings" result.

2. Enumerate processes from a real Windows image (workflow illustration):
```bash
vol -f $IMAGE windows.pslist | head -n 20
```
Expected: a table with PID, PPID, ImageFileName, Offset(V), Threads, Handles, and creation/exit times for processes that were present in the kernel's active process list. WHY: `windows.pslist` walks the doubly-linked `EPROCESS` list (`ActiveProcessLinks`), which is the same list the OS uses — so a rootkit that unlinks a process can hide from it. That is exactly why analysts follow up with `windows.psscan` (pool-tag scanning, which finds unlinked/terminated processes) and `windows.malfind` (injected/RWX private memory). Discrepancies between `pslist` and `psscan` are a classic hiding indicator (Volatility 3 docs; SANS Memory Forensics cheat sheet). Nuance: read the PPID column for parent-child anomalies — a `lsass.exe` or `svchost.exe` whose parent is not `services.exe`/`wininit.exe`, or an `explorer.exe`-parented process running from `%TEMP%`, is a lead worth pivoting on (parent spoofing maps to **T1134.004 Parent PID Spoofing**; abnormal `svchost.exe` invocation to **T1055.012 Process Hollowing**).

3. Sweep the raw dump for human-readable features with bulk_extractor. This step DOES work on `sample.mem` because bulk_extractor is content-agnostic — it does not need OS structures, only byte patterns.
```bash
cd exercise
mkdir -p be_out
bulk_extractor -o be_out sample.mem
ls be_out
head -n 10 be_out/url.txt
```
Expected: `be_out/` contains feature files (`url.txt`, `email.txt`, `domain.txt`, and reporting files like `report.xml`); `url.txt` lists recovered URLs prefixed by their byte offset. WHY: bulk_extractor ignores file systems and parses the raw byte stream with independent scanners, so it recovers features even from unallocated, fragmented, or non-file data such as a RAM dump. Each line is `offset\tfeature\tcontext`, and the leading offset is what you cite as evidence of *where* the artifact lived (simsong/bulk_extractor repo).

4. Search memory for cryptographic key material.
```bash
cd exercise
aeskeyfind sample.mem
rsakeyfind sample.mem
```
Expected: `aeskeyfind` prints any 128/256-bit AES key schedules found (or "No keys found"); `rsakeyfind` prints candidate RSA keys/certificates (or none). WHY: aeskeyfind does not look for the raw key bytes alone — it looks for the *expanded AES key schedule*, because the entropy/structure of the round-key expansion is statistically detectable in RAM even after the process context is gone. This is the technique from the Princeton "Lest We Remember" cold-boot work, and it is why keys used for disk/full-volume encryption or C2 are recoverable from a memory capture (Princeton CITP memory research).

## Hands-on exercise
Work inside this module's `exercise/` directory.

- **Sample artifact:** `exercise/sample.mem`
- **Type:** A small, inert raw memory-style dump — a synthetic byte blob generated on the lab host that embeds benign, planted strings (a fake URL `http://benign.lab.local/beacon`, a fake email `analyst@lab.local`) and a randomly generated 256-bit AES key schedule for detection practice. It contains **no** operating-system code and **no** live malware.
- **Safe origin:** Generated locally with `dd`/`openssl` on the LAB-LINUX VM (no network egress); it is benign and inert.
- **sha256:** `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

Tasks:
1. Use bulk_extractor to recover the planted URL and email.
2. Use aeskeyfind to recover the planted AES key.
3. Record the recovered artifacts and the offsets bulk_extractor reports.

## SOC analyst perspective
In a SOC, memory forensics is the go-to when disk and log evidence look clean but a host is still behaving oddly — the classic sign of fileless or in-memory malware. An analyst pulls a RAM image from a suspect endpoint, then works a repeatable Volatility 3 triage sequence:

- `vol -f $IMAGE windows.pslist` vs `vol -f $IMAGE windows.psscan` — compare the active-list view against pool-tag scanning; a PID present in `psscan` but absent from `pslist` suggests DKOM/unlinking to hide a process (maps to **T1055** family; see Volatility 3 docs and SANS Memory Forensics cheat sheet).
- `vol -f $IMAGE windows.malfind` — flags process memory that is private, committed, and executable (RWX) with no backing file — the fingerprint of injected/reflectively-loaded code (**T1055 Process Injection**, **T1620 Reflective Code Loading**).
- `vol -f $IMAGE windows.netscan` — recovers TCP/UDP endpoints and owning PIDs, exposing C2 sockets even when the live OS `netstat` was tampered with (supports scoping **T1071 Application Layer Protocol** and **T1573 Encrypted Channel**).
- `vol -f $IMAGE windows.cmdline` / `windows.dlllist` — recovers command lines and loaded modules for suspicious PIDs (**T1059 Command and Scripting Interpreter**).

**Detection-engineering logic (tied to concrete artifacts/fields):**
- **Malfind → injection triage.** `windows.malfind` output where the `Protection` column is `PAGE_EXECUTE_READWRITE` and the region has no mapped file is the primary indicator for **T1055.001 Dynamic-link Library Injection** and **T1055.002 Portable Executable Injection**; treat regions beginning with an `MZ` header inside private/committed memory as a high-priority lead. Corroborate on the live-monitoring side with **Sysmon Event ID 8 (CreateRemoteThread)** and **Sysmon Event ID 10 (ProcessAccess)** where `GrantedAccess` includes `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD`, and **Sysmon Event ID 25 (ProcessTampering)** for hollowing/herpaderping. These are the on-host analogues of what malfind sees post-mortem (Microsoft Learn Sysmon reference; SANS Memory Forensics cheat sheet).
- **pslist vs psscan delta.** The detection is a set-difference on the PID column between the two plugin outputs; any PID only in `psscan` is a candidate for **T1014 Rootkit** / DKOM unlinking. Also flag processes in `psscan` with a populated `ExitTime` but still-open handles (terminated-yet-resident).
- **Parent-child integrity.** From `windows.pslist`/`windows.cmdline`, alert on canonical parentage violations (e.g., `cmd.exe`/`powershell.exe` parented by `winword.exe` or `outlook.exe`) → **T1059.001 PowerShell**, **T1566 Phishing** delivery; and mismatched image path vs command line → **T1134.004 Parent PID Spoofing**.

**Security Onion / Zeek / Suricata pivots and hunts:**
- Recovered C2 domains/IPs → hunt in **Zeek** `conn.log` (`id.orig_h`, `id.resp_h`, `resp_bytes`), `dns.log` (`query`, `answers`), `ssl.log` (`server_name`, `ja3`, `ja3s`, `validation_status`), and `http.log` (`host`, `uri`, `user_agent`) — pivot in Kibana/Hunt on `destination.ip` and `dns.query`. A self-signed cert or an unusual `ja3`/`ja3s` hash on a flow to a recovered IP strengthens **T1573 Encrypted Channel** scoping.
- **Beaconing hunt:** group `conn.log` by `id.resp_h` and look for low-jitter, regular-interval connections with small, uniform `orig_bytes` — the network fingerprint of the beacon whose URL you carved from RAM (**T1071.001 Web Protocols**).
- Turn a recovered IOC into a **Suricata** signature (use the `dns.query`, `tls.sni`, or `http.host` sticky buffers / `content` matches) or a **Zeek intel-framework** entry (`Intel::ADDR`, `Intel::DOMAIN`) to sweep every monitored host, not just the imaged endpoint.
- bulk_extractor's carved `packets.pcap` and recovered URLs/emails give concrete selectors to pivot on across the Elastic data in Security Onion; re-ingesting the carved PCAP through Zeek/Suricata lets you regenerate protocol logs and alerts for the in-memory traffic fragments.

Recovered AES/RSA keys via aeskeyfind/rsakeyfind can decrypt captured traffic or ransomware payloads for confirmation. This work sits in the DFIR **examination/analysis** phase. Relevant ATT&CK techniques: **T1055 (Process Injection)** and sub-techniques **T1055.001/.002/.012**, **T1620 (Reflective Code Loading)**, **T1573 (Encrypted Channel)**, **T1071 (Application Layer Protocol)** and **T1071.001 (Web Protocols)**, **T1014 (Rootkit)**, **T1134.004 (Parent PID Spoofing)**. (References: Volatility 3 docs; SANS Memory Forensics cheat sheet; Microsoft Learn Sysmon reference; Security Onion docs; MITRE ATT&CK technique pages.)

## Attacker perspective
Attackers deliberately avoid touching disk to evade EDR and file-based detection — living-off-the-land, process injection (**T1055**), reflective DLL/code loading (**T1620**), and encrypted C2 (**T1573**) all keep the malicious logic in RAM. Concrete TTPs and the artifacts they leave in memory:

- **Process injection (T1055)** — e.g. `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`, or process hollowing (**T1055.012**), DLL injection (**T1055.001**), and PE injection (**T1055.002**). Leaves **private, committed, RWX regions with no backing image file** — precisely what `windows.malfind` surfaces; hollowing additionally leaves a discrepancy between the mapped section's on-disk image and the in-memory contents at the PE's declared base.
- **Reflective code loading (T1620)** — a PE mapped and relocated in memory without `LoadLibrary`, so it appears in no module list. Artifacts: executable private memory whose MZ/PE header is present but the region is not in `windows.dlllist`.
- **DKOM / process unlinking (T1014)** — removing an `EPROCESS` from `ActiveProcessLinks` to hide from `pslist`; the pool allocation still exists, so `windows.psscan` still finds it — the mismatch is the tell.
- **Parent PID spoofing (T1134.004)** — using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` so a malicious child appears to descend from a trusted process; the memory image still records the real image path/command line, so `windows.cmdline` + `windows.pslist` parentage can expose the lie.
- **Encrypted C2 (T1573)** — the session key must exist in RAM to encrypt/decrypt traffic, so aeskeyfind can recover the AES key schedule; ransomware key material and decrypted config blobs likewise persist in RAM. The beacon config often decrypts to plaintext C2 URLs/domains recoverable via bulk_extractor's `url.txt`/`domain.txt`.

Evasion the adversary attempts: forcing a reboot or power-off to destroy RAM before capture, anti-analysis that detects a hypervisor/acquisition, in-memory encryption of payloads until just-in-time execution, sleep-obfuscation that XOR/AES-encrypts the beacon's own memory while dormant (defeating a single snapshot unless captured mid-execution), unmapping/zeroing PE headers after reflective load to blunt header scans, and minimizing time keys are resident. But the residual artifacts — anomalous RWX private memory, orphaned/unlinked pool objects, live sockets, decrypted strings, and key schedules that never appear on disk — remain visible to a memory capture, which is why memory forensics is effective against fileless intrusions. (References: MITRE ATT&CK T1055/T1055.001/.002/.012, T1620, T1573, T1014, T1134.004, T1071.001; Volatility 3 docs; SANS Memory Forensics cheat sheet; Princeton CITP memory research.)

## Answer key
Sample sha256: `452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88`

Expected findings and the exact commands that produce them:

1. Recover the planted URL and email:
```bash
cd exercise
mkdir -p be_out
bulk_extractor -o be_out sample.mem
grep -i "benign.lab.local" be_out/url.txt
grep -i "analyst@lab.local" be_out/email.txt
```
Expected: `url.txt` shows `http://benign.lab.local/beacon` with a byte offset; `email.txt` shows `analyst@lab.local`. Each match line is `offset<TAB>feature<TAB>context`, so the leading number is the byte offset in `sample.mem` where the string was found (feature-file format per simsong/bulk_extractor).

2. Recover the planted AES key:
```bash
cd exercise
aeskeyfind sample.mem
```
Expected: aeskeyfind reports at least one 256-bit AES key (hex) with the offset where the key schedule was located (aeskeyfind detects the expanded round-key schedule, not just the raw key bytes — Princeton CITP memory research).

3. (Optional) confirm no RSA keys are planted:
```bash
cd exercise
rsakeyfind sample.mem
```
Expected: rsakeyfind reports no RSA private keys for this synthetic sample.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** — detected via `vol windows.malfind`/`windows.pslist` vs `windows.psscan`. https://attack.mitre.org/techniques/T1055/
- **T1055.001 – Dynamic-link Library Injection** — RWX private region hosting injected DLL, no backing file. https://attack.mitre.org/techniques/T1055/001/
- **T1055.002 – Portable Executable Injection** — MZ/PE header inside private committed memory. https://attack.mitre.org/techniques/T1055/002/
- **T1055.012 – Process Hollowing** — mapped image vs in-memory content mismatch at PE base. https://attack.mitre.org/techniques/T1055/012/
- **T1620 – Reflective Code Loading** — in-memory-only code (no module-list entry) surfaced by Volatility. https://attack.mitre.org/techniques/T1620/
- **T1014 – Rootkit** — DKOM/unlinking exposed by `pslist` vs `psscan` delta. https://attack.mitre.org/techniques/T1014/
- **T1134.004 – Parent PID Spoofing** — parentage anomalies in `windows.pslist`/`windows.cmdline`. https://attack.mitre.org/techniques/T1134/004/
- **T1573 – Encrypted Channel** — recovered keys (aeskeyfind/rsakeyfind) enable decryption of C2/traffic. https://attack.mitre.org/techniques/T1573/
- **T1071 – Application Layer Protocol** — C2 endpoints recovered with `vol windows.netscan`, pivoted in Zeek. https://attack.mitre.org/techniques/T1071/
- **T1071.001 – Web Protocols** — HTTP(S) beacon URLs carved from RAM; beaconing hunt in Zeek `conn.log`/`http.log`. https://attack.mitre.org/techniques/T1071/001/
- **T1059 – Command and Scripting Interpreter** — command lines recovered with `vol windows.cmdline`. https://attack.mitre.org/techniques/T1059/
- **T1059.001 – PowerShell** — suspicious PowerShell parentage/command lines. https://attack.mitre.org/techniques/T1059/001/
- **T1005 – Data from Local System** — feature carving (bulk_extractor) of in-memory data. https://attack.mitre.org/techniques/T1005/
- **DFIR phase:** Collection (RAM capture) → **Examination / Analysis** (this module's focus) → Reporting.

## Sources
Claim → source mapping (all URLs are official/authoritative pages):

- Volatility 3 is OS-agnostic on input, uses automatic symbol detection, and exposes `windows.*`/`linux.*`/`mac.*` plugins via the `vol` entry point (`windows.info`, `windows.pslist`, `windows.psscan`, `windows.malfind`, `windows.netscan`, `windows.cmdline`, `windows.dlllist`) — Volatility 3 documentation: https://volatility3.readthedocs.io/
- `windows.info` reports NT build/kernel base from kernel structures; symbol-table failure indicates format/OS mismatch — Volatility 3 documentation: https://volatility3.readthedocs.io/en/latest/
- `windows.pslist` walks `ActiveProcessLinks` while `windows.psscan` uses pool-tag scanning (mismatch = hiding/DKOM); `malfind` flags RWX private memory; triage sequencing — SANS Memory Forensics cheat sheet/poster: https://www.sans.org/posters/memory-forensics-cheat-sheet/
- Volatility 3 package/CLI availability on Kali (`vol`) — Kali Tools volatility3: https://www.kali.org/tools/volatility3/
- Sysmon Event IDs 8 (CreateRemoteThread), 10 (ProcessAccess, `GrantedAccess`), 25 (ProcessTampering) as on-host analogues of injection/hollowing — Microsoft Learn Sysmon reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- bulk_extractor scans raw byte streams (content-agnostic), writes per-scanner feature files (`url.txt`, `email.txt`, `domain.txt`), can carve `packets.pcap`, feature-file offset format, and the `-V` version flag — bulk_extractor project repo: https://github.com/simsong/bulk_extractor
- bulk-extractor package on Kali — Kali Tools bulk-extractor: https://www.kali.org/tools/bulk-extractor/
- aeskeyfind detects expanded AES key schedules and rsakeyfind detects RSA private-key structures in RAM; origin of the technique (cold-boot / "Lest We Remember") — Princeton CITP memory research: https://citp.princeton.edu/our-work/memory/
- REMnux memory-investigation tooling context — REMnux docs: https://docs.remnux.org/discover-the-tools/investigate+memory
- Security Onion analysis workflow, Zeek logs (`conn.log`, `dns.log`, `ssl.log` incl. `ja3`/`ja3s`, `http.log`), Suricata alerting/sticky buffers (`tls.sni`, `http.host`, `dns.query`), Zeek intel framework, and Kibana/Hunt pivots — Security Onion documentation: https://docs.securityonion.net/
- Zeek log fields (`conn.log`, `dns.log`, `ssl.log`, `http.log`) used for C2/beacon hunting — Zeek documentation: https://docs.zeek.org/en/master/logs/index.html
- MITRE ATT&CK T1055 (Process Injection) — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.001 (DLL Injection) — https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1055.002 (PE Injection) — https://attack.mitre.org/techniques/T1055/002/
- MITRE ATT&CK T1055.012 (Process Hollowing) — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK T1620 (Reflective Code Loading) — https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1014 (Rootkit) — https://attack.mitre.org/techniques/T1014/
- MITRE ATT&CK T1134.004 (Parent PID Spoofing) — https://attack.mitre.org/techniques/T1134/004/
- MITRE ATT&CK T1573 (Encrypted Channel) — https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK T1071 (Application Layer Protocol) — https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK T1059 (Command and Scripting Interpreter) — https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1059.001 (PowerShell) — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1005 (Data from Local System) — https://attack.mitre.org/techniques/T1005/

## Related modules
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- shares bulk_extractor; deepens the Volatility plugin workflow used here.
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- shares bulk_extractor; applies key-recovery and memory triage to a ransomware case.
- [File carving](../05-file-carving/README.md) -- shares bulk_extractor; focuses on recovering embedded artifacts from raw byte streams.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares bulk_extractor; places memory analysis inside a full host-triage workflow.

<!-- cyberlab-enriched: v2 -->
