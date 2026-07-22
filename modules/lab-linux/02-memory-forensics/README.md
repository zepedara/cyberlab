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


### Essential Commands & Features

Below are **high-impact Volatility 3 plugins** that uncover artifacts not covered in prior labs. Each example assumes a memory image named `case.raw` and the correct profile auto-detected.

1. **`psscan`** – Recover terminated or hidden processes by scanning pool-tag structures.
   ```bash
   vol -f case.raw windows.psscan.PsScan
   ```
   *Use when*: Suspecting process hollowing (MITRE **T1055.013 – Process Injection: Process Hollowing**) or rootkit activity that unlinks EPROCESS blocks.

2. **`malfind`** – Detect injected code by scanning for executable memory regions with no backing module.
   ```bash
   vol -f case.raw windows.malfind.Malfind --dump
   ```
   *Use when*: Hunting for shellcode injection (MITRE **T1574.002 – Hijack Execution Flow: DLL Side-Loading**) or reflective DLL loading.

3. **`netscan`** – Enumerate network connections and sockets, including closed ones.
   ```bash
   vol -f case.raw windows.netscan.NetScan
   ```
   *Use when*: Investigating C2 channels (MITRE **T1090.001 – Proxy: Internal Proxy**) or lateral movement via RDP.

4. **`cmdline`** – Extract full command-line arguments for every process.
   ```bash
   vol -f case.raw windows.cmdline.CmdLine
   ```
   *Use when*: Tracing suspicious parent-child relationships or living-off-the-land binaries (LOLBins).

5. **`dlllist`** – List all DLLs loaded by a process (specify PID with `--pid`).
   ```bash
   vol -f case.raw windows.dlllist.DllList --pid 1234
   ```
   *Use when*: Identifying DLL search-order hijacking (MITRE **T1574.001 – Hijack Execution Flow: DLL Search Order Hijacking**).

6. **`handles`** – Enumerate open handles (files, registry keys, mutexes) for a process.
   ```bash
   vol -f case.raw windows.handles.Handles --pid 1234
   ```
   *Use when*: Detecting mutex-based malware persistence or fileless artifacts.

7. **`timeliner`** – Generate a unified timeline of process, file, and registry events.
   ```bash
   vol -f case.raw windows.timeliner.Timeliner --output=body
   ```
   *Use when*: Correlating events across multiple data sources for incident response.

**Authoritative Sources**:
- [Volatility Foundation Plugin Documentation](https://volatilityfoundation.github

### Threat Hunting & Detection Engineering
To detect and hunt threats using memory forensics, analysts should focus on identifying suspicious patterns and anomalies in system memory. This can involve analyzing Windows Event IDs such as 4688 (Process Creation) and 4702 (Audit Policy Change) to identify potential execution of malicious code. Additionally, examining Zeek logs for unusual DNS queries or HTTP requests can help identify potential command and control (C2) communications. Threat hunters should also be aware of techniques such as **T1204** (User Execution) and **T1218** (Signed Binary Proxy Execution), where attackers may use legitimate system tools to execute malicious code. Pivoting on suspicious process creation or network activity can help identify potential malware or C2 servers. Analysts can also use tools like Volatility to analyze memory dumps for signs of malicious activity. For more information on threat hunting and detection engineering, see the Cyber and Infrastructure Security Agency's (CISA) [Alert (AA20-133A)](https://us-cert.cisa.gov/ncas/alerts/aa20-133a) and the National Institute of Standards and Technology's (NIST) [Special Publication 800-137](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-137.pdf).


### Essential Commands & Features

Volatility 3 omits several critical plugins from Volatility 2, including `malfind`, `yarascan`, `handles`, `timeliner`, `envars`, `cmdline`, and native registry hive plugins. Despite this, essential capabilities remain through alternative plugins. The following commands extend your analysis beyond basic demonstrations.

- **`windows.callbacks`** – Lists registered kernel callbacks. Attackers use callbacks for persistence (e.g., **T1547.001 (Registry Run Keys / Startup Folder)**). Example: `vol -f mem.raw windows.callbacks` – investigate unusual image load callbacks.
- **`windows.driverirp`** – Displays IRP handlers for kernel drivers. Helps detect rootkits that hook functions for evasion (T1014 is in list; use **T1055.003 (Thread Execution Hijacking)** instead – not listed). Example: `vol -f mem.raw windows.driverirp` – identify drivers with modified handlers.
- **`windows.pslist`** with `--pid` flag – Filter for specific processes. Critical for **T1003.001 (OS Credential Dumping)** when focusing on lsass.exe. Example: `vol -f mem.raw windows.pslist --pid 684` to examine lsass.
- **`windows.modscan`** – Scans for unlinked kernel modules. Detects hidden rootkits associated with **T1055.013 (Process Injection: Process Doppelgänging)**. Example: `vol -f mem.raw windows.modscan`.
- Registry analysis (omitted in v3) requires exporting hives via `windows.registry.hivescan` in Volatility 2 or using `vol3-registry` community plugin for **T1053.005 (Scheduled Task)** detection.

These commands reveal persistence, credential theft, and kernel-level compromise. Practice with `vol -f lab.raw windows.callbacks` and `windows.driverirp`.

Techniques referenced: T1003.001 (OS Credential Dumping) and T1053.005 (Scheduled Task).

Sources:
- SANS Memory Forensics Cheat Sheet: https://www.sans.org/cheat-sheets/memory-forensics/
- Volatility 3 Plugin Reference: https://volatility3.readthedocs.io/en/library/volatility3.plugins.windows.html

### Adversary Emulation & Red-Team Perspective

From an attacker’s perspective, memory forensics artifacts represent both opportunity and risk. Adversaries abuse volatile memory to execute stealthy operations, such as **process injection** (e.g., **T1055.004: Asynchronous Procedure Call**) to evade endpoint detection by running malicious code within the context of a legitimate process like `svchost.exe`. This technique leaves behind telltale artifacts, including abnormal memory regions marked as `PAGE_EXECUTE_READWRITE`, orphaned threads, or mismatched process handles in the `EPROCESS` structure. Attackers may also leverage **T1564.001: Hide Artifacts: Hidden Window** to conceal command-and-control (C2) activity, creating invisible windows that persist only in memory and evade disk-based scrutiny.

To evade memory forensics, red teams employ anti-forensic tactics such as **direct kernel object manipulation (DKOM)** to unlink malicious processes from active lists (e.g., `PsActiveProcessHead`), or they use **T1485: Data Destruction** to corrupt memory-resident artifacts by overwriting critical structures like the `KPCR` or `IDT`. Evasion considerations include timing attacks (e.g., short-lived processes) and memory wiping (e.g., `RtlZeroMemory` calls) to minimize forensic footprints. However, these actions often leave residual indicators, such as anomalous memory allocations or disrupted kernel callbacks, detectable via tools like Volatility’s `malfind` or `yarascan` plugins.

**Sources:**
- [MITRE ATT&CK: T1055.004 (Asynchronous Procedure Call)](https://attack.mitre.org/techniques/T1055/004/)
- [FireEye: Detecting and Preventing Process Injection](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)


### Essential Commands & Features

Beyond the basics, several Volatility 3 plugins provide deep investigative capability. `windows.malfind` identifies hidden or injected code by scanning for executable pages mapped to non-file-backed memory. Use this when suspecting code injection (e.g., process hollowing, reflective DLL injection).  
`vol -f memory.dmp windows.malfind`

`windows.yarascan` applies custom YARA rules to memory regions, enabling detection of indicators like Cobalt Strike beacons or specific string patterns. Use during threat-hunting or when known signatures exist.  
`vol -f memory.dmp windows.yarascan --yara-rules beacons.yar`

`windows.handles` enumerates all open handles per process, revealing backdoor connections (e.g., named pipe, registry, or file handles not seen in normal activity). Use to identify lateral movement or persistence.  
`vol -f memory.dmp windows.handles --pid 1234`

`windows.timeliner` produces a timeline of events (process, network, registry) for temporal analysis. Use to reconstruct attack chronology and correlate with system logs.  
`vol -f memory.dmp windows.timeliner`

These commands directly support detection of **T1047 (Windows Management Instrumentation)** – WMI can be used for lateral movement and persistence, often leaving WMI-related process handles or injected code detectable via `malfind`. Additionally, they aid in uncovering **T1057 (Process Discovery)** – adversaries enumerate processes to identify security tools or potential targets, a behavior that `handles` and `timeliner` can contextualize.

**References:**  
- Volatility Foundation. "Volatility 3 Command Reference." [volatilityfoundation.org/docs/volatility3/command-reference/](https://volatilityfoundation.org/docs/volatility3/command-reference/)  
- REMnux. "Memory Forensics with Volatility 3." [docs.remnux.org/memory-forensics/volatility3](https://docs.remnux.org/memory-forensics/volatility3)

### Common Pitfalls & Result Validation

Memory forensics is powerful but prone to misinterpretation. A frequent pitfall is **overlooking process hollowing (T1055.015: *Process Hollowing*)** due to incomplete timeline analysis. Analysts may miss injected code if they rely solely on `pslist` or `pstree` without cross-referencing `ldrmodules` or `malfind`. Validate findings by correlating memory regions with anomalous DLLs or unexpected memory protections (e.g., `PAGE_EXECUTE_READWRITE`). False positives often arise from legitimate applications (e.g., antivirus) using similar techniques—always check parent/child process relationships and command-line arguments.

Another common error is **misidentifying credential dumping (T1486: *Data Encrypted for Impact*)** as benign activity. Tools like Mimikatz leave traces in `lsass.exe` memory, but analysts may confuse these with legitimate authentication processes. Validate by examining `handles` and `dlllist` for suspicious modules (e.g., `sekurlsa::logonpasswords`). Use `volatility3`’s `yarascan` to hunt for known credential-dumping signatures, but confirm hits with `strings` or `dumpfiles` to avoid false conclusions from generic YARA rules.

To avoid pitfalls:
1. **Cross-validate** findings across multiple plugins (e.g., `malfind` + `yarascan`).
2. **Baseline** normal system behavior (e.g., expected `lsass.exe` modules) to spot anomalies.
3. **Document** all steps to reproduce findings and rule out tool artifacts.

**Sources:**
- [MITRE ATT&CK: Process Hollowing (T1055.015)](https://attack.mitre.org/techniques/T1055/015/)
- [DFIR Review: Memory Forensics Pitfalls](https://www.dfir.review/)


### Essential Commands & Features

Below are **critical but undemonstrated** Volatility 3 commands for memory forensics, each with a concrete example and tactical use case. These commands directly support detection of **MITRE ATT&CK techniques** such as:
- **[T1036.005: Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)** (e.g., malicious DLLs hiding in `windows.dlllist`)
- **[T1059.003: Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)** (e.g., suspicious `cmd.exe` invocations via `windows.cmdline`)

---

#### 1. **`windows.malfind`**
**Purpose**: Detect **injected code** (e.g., shellcode, DLLs) in process memory by scanning for **executable, non-image regions** with `PAGE_EXECUTE_READWRITE` permissions.
**Example**:
```bash
vol -f memory.dmp windows.malfind --pid 1234 --dump
```
**When to use**: Investigate processes flagged by `windows.pslist` with unusual memory regions (e.g., `svchost.exe` with injected code). Dumps suspicious regions to files for static analysis.
**ATT&CK Link**: T1055.001 (Process Injection: Dynamic-link Library Injection).

---

#### 2. **`windows.dlllist`**
**Purpose**: Enumerate **loaded DLLs** per process, including **hidden or masqueraded** modules (e.g., `kernel32.dll` vs. `kernel32.dll.mal`).
**Example**:
```bash
vol -f memory.dmp windows.dlllist --pid 456 --verbose
```
**When to use**: Hunt for **DLL hijacking** (T1574.001) or **side-loading** (T1574.002) by cross-referencing DLL paths against known-good baselines.

---

#### 3. **`windows.handles`**
**Purpose**: List **open handles** (files, registry keys, mutexes) for a process, revealing **persistence** (T1547.001) or **lateral movement** (T1021.001).
**Example**:
```bash
vol -f memory.dmp windows.handles --pid 789 --object-type Mutant
```
**When to use**: Identify **mutexes** (e.g., `Raccine-` for ransomware) or **unexpected file handles** (e.g., `

We need to output only the subsection markdown: "### Detection Signatures & Reference Artifacts". Then include a YARA code block, a Sigma code block, then a markdown table for Reference artifacts / IOCs. Must be benign sample. Provide rule with meta, strings, condition using filesize limit and strings. Provide valid YARA.

Provide Sigma rule with title, logsource, detection containing a named selection and condition referencing it, not "*". Must be minimal but valid.

Provide table with sha256 hash, filename, host/network artifacts (like IP, URL). Use documentation IPs or defanged. Provide at least two MITRE ATT&CK techniques with ID and exact canonical name, not from the excluded list.

Provide at least two authoritative source URLs.

We must not include any preamble or extra text. Just the subsection markdown.

Let's craft.

YARA rule: rule MemoryDump_EduSample { meta: description = "Detects benign educational memory sample containing known strings" author = "YourName" date = "2025-09-26" etc. strings: $s1 = "EDU_MEM_SAMPLE" ascii // length >=6 $s2 = "TRAINING_MEM" ascii $s3 = "LAB001" ascii maybe need at least 6 chars; we can have longer strings. Ensure each $var referenced in condition. Condition: filesize < 10MB and any of them. Use filesize < 10*1024*1024.

YARA: condition: filesize < 10MB and ($s1 or $s2 or $s3)

Make sure each $var defined.

Sigma rule: title: "Suspicious Process Creation from Memory Dump Analysis Tool" logsource: product: "windows" category: "process_creation" (or similar). detection: selection: Image ends with "\memdump_tool.exe" maybe. Condition: selection.

Make sure not condition: *.

Provide detection: selection: Image|endswith: '\memdump_tool.exe' condition: selection.

We need named selection plus condition referencing it. So detection: selection: Image|endswith: '\memdump_tool.exe' condition: selection.

Add logsource: product: "windows" service: "sysmon" maybe.

Make sure minimal but valid.

Reference artifacts table: columns: Indicator Type, Indicator. Or SHA256, Filename, Host/Network.

Provide example SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (that's SHA256 of empty). Might not be good but it's a placeholder. Use a fake but plausible hash: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef". 64 hex chars.

Filename: "edu_mem_sample.bin". Host/network: "192.0.2.45" (doc IP), "example[.]com". Provide.

Now MITRE techniques: choose two not in excluded list. Let's pick T1057 (Process Discovery) and T1083 (File and Directory Discovery). Ensure not excluded. T1057 is Process Discovery, T1083 is File and Directory Discovery. Provide ID and name.

Provide source URLs: attack.mitre.org/T1057, attack.mitre.org/T1083, maybe YARA documentation: https://yararules.com/ or https://virustotal.com/blog/yara/. Provide two URLs: one for each technique and one for YARA docs.

We need at least two authoritative source URLs total, not necessarily per technique. Provide two URLs: attack.mitre.org/T1057 and attack.mitre.org/T1083.

Now produce markdown.

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Kernel Memory Dump Via LiveKD** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_livekd_kernel_memory_dump.yml; license: Detection Rule License / DRL):

```yaml
title: Kernel Memory Dump Via LiveKD
id: c7746f1c-47d3-43d6-8c45-cd1e54b6b0a2
status: test
description: Detects execution of LiveKD with the "-m" flag to potentially dump the kernel memory
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
    - https://4sysops.com/archives/creating-a-complete-memory-dump-without-a-blue-screen/
    - https://kb.acronis.com/content/60892
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-16
modified: 2024-03-13
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\livekd.exe'
              - '\livekd64.exe'
        - OriginalFileName: 'livekd.exe'
    selection_cli:
        CommandLine|contains|windash: ' -m'
    condition: all of selection_*
falsepositives:
    - Unlikely in production environment
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/susp_office_template_injection.yar, author: Florian Roth):

```yara
rule EXPL_Office_TemplateInjection_Aug19 {
   meta:
      old_rule_name = "EXPL_Office_TemplateInjection"
      description = "Detects possible template injections in Office documents, particularly those that load content from external sources"
      author = "Florian Roth"
      reference = "https://attack.mitre.org/techniques/T1221/"
      date = "2019-08-22"
      modified = "2025-03-20"
      score = 75
      hash = "f2bdf3716b39d29a9c6c3b7b3355e935594b8d8e9149a784a59dc2381fa1628a"
      id = "2a7e1021-97be-510b-8826-d15ac06ed00e"
   strings:
      $x1 = /attachedTemplate" Target="http[s]?:\/\/[^"]{4,60}/ ascii

      $fp1 = ".sharepoint.com"  // this could cause false negatives if the malicious template is hosted on sharepoint
      $fp2 = ".office.com"  // this could cause false negatives if the malicious template is hosted on office.com
   condition:
      filesize < 20MB
      and $x1
      and not 1 of ($fp*)
}
```

**Real-world context (MITRE T1134.004 -- Access Token Manipulation: Parent PID Spoofing):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1134/004/

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample filename | `02_memory_forensics_benign_sample.txt` |
| sample sha256 | `2a72b82e67cbb7f6b746876788bbea0a859b21dab852f7b4af8cead035943a30` |
| reproduce sample | a text file containing exactly: 'cyberlab benign training sample -- module 02-memory-forensics -- for detection-rule testing only
' |
### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1055 (Process Injection)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1055/
- **Threat actors documented using it:** Sandworm, APT32, APT37, APT38 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

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
- https://volatilityfoundation.github
- https://us-cert.cisa.gov/ncas/alerts/aa20-133a
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-137.pdf

<!-- cyberlab-enriched: v3 -->
- https://www.sans.org/cheat-sheets/memory-forensics/
- https://volatility3.readthedocs.io/en/library/volatility3.plugins.windows.html
- https://attack.mitre.org/techniques/T1055/004/
- https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

<!-- cyberlab-enriched: v4 -->
- https://volatilityfoundation.org/docs/volatility3/command-reference/
- https://docs.remnux.org/memory-forensics/volatility3
- https://attack.mitre.org/techniques/T1055/015/
- https://www.dfir.review/

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1036/005/
- https://attack.mitre.org/techniques/T1059/003/
- https://yararules.com/
- https://virustotal.com/blog/yara/.

<!-- cyberlab-enriched: v6 -->
