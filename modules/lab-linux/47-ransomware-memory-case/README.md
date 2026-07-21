# 47 * Scenario: ransomware memory investigation -- LAB-LINUX

## Overview (plain language)
Imagine a workstation gets locked by ransomware and someone captures a snapshot of everything the computer was holding in its memory (RAM). This module teaches you how to open that snapshot and look inside it. RAM contains a treasure map: which programs were running, what web addresses they talked to, and even leftover text and keys. We use three tools together. Volatility 3 reads the raw memory file and lists processes, network connections, and injected code. YARA scans the same memory for known "signatures" of bad software. bulk_extractor sweeps through the memory blindly and pulls out useful bits like URLs, email addresses, and crypto artifacts. Together they help you reconstruct what the ransomware did, including how it evaded defenses and what recovery options were disabled.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | apt install volatility3 | Framework to extract processes, network, and injected code from a RAM capture |
| YARA | apt install yara | Pattern-matching engine to flag malware signatures inside memory or files |
| bulk_extractor | apt install bulk-extractor | Bulk scanner that carves URLs, emails, crypto artifacts, and other IOCs from raw data without a filesystem |

Notes on tool identity and provenance:
- Volatility 3 is the current Python 3 rewrite of the Volatility framework and uses the `vol` (or `vol.py`/`vol3`) entry point with a `plugins`-based invocation model (`vol -f <image> <os>.<plugin>`); see the official docs at https://volatility3.readthedocs.io/en/latest/ and the source at https://github.com/volatilityfoundation/volatility3.
- YARA is authored by VirusTotal; documentation and the rule language reference are at https://yara.readthedocs.io/ and source at https://github.com/VirusTotal/yara.
- bulk_extractor is Simson Garfinkel's stream-based feature/carving tool; source and manual are at https://github.com/simsong/bulk_extractor. Both Volatility and bulk_extractor ship on REMnux (https://docs.remnux.org/discover-the-tools/) and the SANS SIFT Workstation (https://www.sans.org/tools/sift-workstation/).

## Learning objectives
- Enumerate running processes and suspicious parent/child relationships in a memory image using Volatility 3, including detection of process hollowing and DKOM unlinking.
- Extract network connections and command-line arguments tied to a ransomware process, including residual socket structures and closed connections.
- Scan a memory image with a custom YARA rule and interpret hits, including per-process attribution using Volatility 3's `yarascan` plugin.
- Carve indicators of compromise (URLs, ransom-note strings, crypto keys, and registry artifacts) from RAM with bulk_extractor.
- Identify defense evasion techniques such as Volume Shadow Copy deletion, process injection, and log clearing by analyzing memory artifacts.

## Environment check
```bash
# Prove all three tools are installed on LAB-LINUX (SIFT/REMnux)
vol --info | head -n 3
yara --version
bulk_extractor -V
```
Expected output: Volatility 3 prints its plugin/OS-layer banner via `--info` (this flag lists available address spaces, plugins, and layers — see https://volatility3.readthedocs.io/en/latest/basics.html); `yara --version` prints a version like `4.x.x` (the `--version` flag is documented in the YARA command-line reference, https://yara.readthedocs.io/en/stable/commandline.html); and `bulk_extractor -V` prints a version string such as `bulk_extractor 2.0.x` (the `-V` capital-V flag prints version per the bulk_extractor usage/manual, https://github.com/simsong/bulk_extractor).

## Guided walkthrough
1. `vol -f memory.raw windows.info` — always run this first. It confirms the image is parseable and prints the OS build, kernel base (KDBG/DTB), and system time. WHY: Volatility 3 auto-detects the symbol/profile at runtime rather than requiring a manually chosen profile as in Volatility 2, so `windows.info` is your sanity check that the correct symbol table (PDB) was resolved before you trust any later plugin output. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.info
```bash
vol -f memory.raw windows.info
```
Expected: a key/value table showing `NTBuildLab` (e.g., `19041.1.amd64fre.vb_release.191206-1406`), kernel base address, DTB (Directory Table Base), and the capture's `SystemTime`. Nuance: if this fails or shows no symbols, the rest of the walkthrough will be unreliable — you likely need matching symbol files (https://volatility3.readthedocs.io/en/latest/symbol-tables.html). The `SystemTime` field is critical for correlating with network logs (e.g., Zeek `conn.log` timestamps).

2. `vol -f memory.raw windows.pslist` — walks the doubly-linked `EPROCESS` list to enumerate processes. WHY: it gives you PID/PPID, start time, and thread count so you can spot oddly-named binaries or unexpected parents. Nuance: `pslist` relies on the linked list and can be evaded by DKOM (Direct Kernel Object Manipulation) unlinking; cross-check with `windows.psscan` (pool-tag scanning) and `windows.pstree` (parent/child hierarchy) to catch hidden or terminated processes. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.pslist
```bash
vol -f memory.raw windows.pslist | grep -i -E "lock|crypt|ransom|encrypt|vssadmin|wmic|powershell|cmd"
```
Expected: one or more matching PIDs if a ransomware-like process is present. Nuance: absence of a match does NOT clear the host — legitimate names (e.g., `svchost.exe`) are common attacker cover, so also run `windows.pstree` to inspect lineage and `windows.psscan` to detect DKOM unlinking (https://attack.mitre.org/techniques/T1057/).

3. `vol -f memory.raw windows.cmdline` — reads each process's `PEB.ProcessParameters` to reveal the full command line. WHY: command-line arguments frequently expose the encryptor's target path, key material flags, or a launch from `%TEMP%`/`%APPDATA%`. Ransomware often uses `vssadmin delete shadows` or `wmic shadowcopy delete` to disable recovery (**T1490** Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/). Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.cmdline
```bash
vol -f memory.raw windows.cmdline | grep -i -E "vssadmin|wmic|shadowcopy|delete|/c|powershell.*-enc"
```
Expected: a table mapping PID to command line; ransomware often shows an executable launched from `%TEMP%` or `%APPDATA%`, or commands like `vssadmin delete shadows /all /quiet`. Nuance: a blank/`N/A` command line can itself be suspicious (process hollowing or a paged-out PEB). Attackers may also use **T1059.001 (PowerShell)** with encoded commands (`-enc` or `-e`), which are recoverable here (https://attack.mitre.org/techniques/T1059/001/).

4. `vol -f memory.raw windows.netscan` — pool-tag scans for `_TCP_ENDPOINT`/`_UDP_ENDPOINT` structures to recover current and recently-closed sockets. WHY: it links a foreign IP/port to the owning PID so you can attribute a C2 callback to a process. Nuance: `netscan` recovers residual (even closed) connection objects, so entries may outlive the live connection — correlate timestamps with the capture time from step 1. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.netscan
```bash
vol -f memory.raw windows.netscan | grep -E "ESTABLISHED|CLOSE_WAIT" | grep -v "127.0.0.1"
```
Expected: rows with foreign IPs such as 203.0.113.10 tied to a suspicious PID (203.0.113.0/24 is a RFC 5737 documentation range, safe to use as an example). Nuance: closed sockets may indicate **T1041 (Exfiltration Over C2 Channel)**, especially if the foreign IP is known-bad (https://attack.mitre.org/techniques/T1041/).

5. Scan the raw memory with a YARA rule for ransom-note strings and crypto artifacts. WHY: string/byte signatures confirm a family and pin the byte offsets where note templates or config live. The `-s` flag prints the matching strings and their offsets (see https://yara.readthedocs.io/en/stable/commandline.html). Nuance: scanning a flat memory dump matches physical offsets; to attribute a hit to a process, use Volatility 3's `windows.yarascan` plugin instead (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.yarascan). Example rule for crypto keys:
```bash
cat > crypto.yar <<'EOF'
rule ransom_crypto_key {
    meta:
        description = "Detects common ransomware symmetric key patterns"
    strings:
        $a = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 } // ABCDEFGHIJKLMNOP (example key)
        $b = "-----BEGIN PUBLIC KEY-----" wide ascii
    condition:
        any of them
}
EOF
yara -s crypto.yar memory.raw
```
Expected: rule name plus matched offsets/strings when the note text or key is found. Nuance: YARA rules can also detect **T1027 (Obfuscated Files or Information)** by matching encoded strings or packer signatures (https://attack.mitre.org/techniques/T1027/).

6. Carve indicators with bulk_extractor into an output directory. WHY: bulk_extractor runs feature-extraction scanners over the raw bytes without needing a filesystem or valid process structures, so it recovers IOCs even from unallocated/paged regions. It writes one feature file per scanner (e.g., `url.txt`, `email.txt`, `aes_keys.txt`) plus histograms — see the manual at https://github.com/simsong/bulk_extractor. Nuance: `-o` must name a directory that does not already exist, or bulk_extractor will refuse to overwrite it. Enable additional scanners for crypto artifacts:
```bash
bulk_extractor -E aes -E zip -o be_out memory.raw
cat be_out/url.txt | grep -i http | head
cat be_out/aes_keys.txt | head
```
Expected: a populated `be_out/` directory; `url.txt` and `email.txt` contain carved indicators (each line prefixed with the byte offset where the feature was found), and `aes_keys.txt` may contain symmetric keys used for encryption (**T1486** Data Encrypted for Impact, https://attack.mitre.org/techniques/T1486/).

7. Check for process injection artifacts using `windows.malfind`. WHY: ransomware often injects into legitimate processes (e.g., `svchost.exe`) to evade detection (**T1055** Process Injection, https://attack.mitre.org/techniques/T1055/). `malfind` detects private memory regions with `PAGE_EXECUTE_READWRITE` permissions, which are indicative of injected code. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind
```bash
vol -f memory.raw windows.malfind --dump
```
Expected: output showing processes with suspicious memory regions, including the start/end addresses and protection flags. Nuance: legitimate applications (e.g., JIT compilers) may also use RWX memory, so cross-check with `windows.dlllist` to confirm the absence of backing DLLs (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.dlllist).

8. Recover registry artifacts using `windows.registry.hivelist` and `windows.registry.printkey`. WHY: ransomware often modifies registry keys to disable recovery options or establish persistence (**T1112** Modify Registry, https://attack.mitre.org/techniques/T1112/). Plugin references: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.hivelist and https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.printkey
```bash
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "ControlSet001\Services\VSS"
```
Expected: `hivelist` shows the virtual addresses of registry hives; `printkey` reveals modifications to Volume Shadow Copy Service (VSS) settings, which may indicate **T1490** (Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/).

## Hands-on exercise
Investigate the sample memory image in this module's `exercise/` directory.

- **Sample type:** a small benign/inert raw memory-like blob (`exercise/memory.raw`) — it is NOT a real infected RAM capture and contains NO live malware; it is a plain file seeded with harmless ransom-note strings, a fake C2 URL, a simulated AES key, and registry-like artifacts so the tools produce realistic hits with zero risk.
- **Safe origin / generation:** the file is generated locally with the reproducible command below (no network egress). It only contains ASCII strings and random padding.

Reproducible generator (creates the exact benign sample):
```bash
mkdir -p exercise
{
  head -c 4096 /dev/zero
  printf 'YOUR FILES HAVE BEEN ENCRYPTED! Contact evilmail@example.com to recover.\n'
  printf 'Payment portal: http://203.0.113.10/pay\n'
  printf 'LOCKBIT_TEST_MARKER ransom.note.decrypt\n'
  printf 'AES_KEY: ABCDEFGHIJKLMNOP\n'
  printf 'REGISTRY: \Registry\Machine\System\ControlSet001\Services\VSS\Start = 0x4\n'
  head -c 4096 /dev/urandom
} > exercise/memory.raw
sha256sum exercise/memory.raw
```

Tasks:
1. Use `yara` with the rule below to confirm the ransom-note marker and crypto key.
2. Use `bulk_extractor` to carve the C2 URL, contact email, and AES key.
3. Use Volatility 3's `windows.yarascan` to attribute the ransom-note strings to a process (even though this is a flat dump, the plugin will still work for demonstration).

Provided YARA rule (`exercise/ransom.yar`):
```bash
cat > exercise/ransom.yar <<'EOF'
rule ransom_note_test
{
    meta:
        description = "Detects ransom note and crypto key markers"
    strings:
        $a = "HAVE BEEN ENCRYPTED"
        $b = "LOCKBIT_TEST_MARKER"
        $c = "AES_KEY: ABCDEFGHIJKLMNOP"
    condition:
        any of them
}
EOF
```
(Rule syntax — `strings:`/`condition:` sections and the `any of them` set operator — follows the YARA writing-rules reference: https://yara.readthedocs.io/en/stable/writingrules.html)

## SOC analyst perspective
A defender treats a captured memory image as ground truth when disk logs may be tampered. In an incident, you ingest network alerts from Security Onion (Suricata/Zeek) that flag a suspicious outbound connection to 203.0.113.10, then pivot to the endpoint's RAM capture.

Concrete detection logic and pivots:
- **Network pivot:** Suricata alerts surface in Security Onion's Alerts interface; pivot from an alert into the corresponding Zeek `conn.log` record to get the 4-tuple, duration, and byte counts (Zeek log reference: https://docs.zeek.org/en/master/logs/conn.html; Security Onion analyst workflow: https://docs.securityonion.net/en/2.4/). Filter Elastic on `destination.ip: 203.0.113.10` to find every host that beaconed to the same infrastructure — this maps to **T1071** (Application Layer Protocol, https://attack.mitre.org/techniques/T1071/) and, if the C2 uses web protocols, **T1071.001** (Web Protocols, https://attack.mitre.org/techniques/T1071/001/). For encrypted C2, look for **T1573.001 (Encrypted Channel: Symmetric Cryptography)** in Zeek's `ssl.log` (e.g., `ssl.log.cipher` fields indicating weak or unusual ciphers).
- **Endpoint corroboration:** Volatility 3's `windows.netscan` recovers the owning PID for that foreign IP, and `windows.cmdline` shows the launching path. A binary running from `%TEMP%`/`%APPDATA%` is consistent with **T1204** (User Execution) and staging in **T1074** (Data Staged); mass file rewrites map to **T1486** (Data Encrypted for Impact, https://attack.mitre.org/techniques/T1486/). Use `windows.handles` to check for open file handles to encrypted files or ransom notes (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.handles).
- **Family confirmation:** YARA hits on ransom-note strings (via `yara` on the flat dump, or `windows.yarascan` for per-process attribution) confirm the family. Feed the confirmed strings/hashes back into Security Onion as new Suricata rules (e.g., `alert http any any -> any any (msg:"Ransomware Note String"; content:"YOUR FILES HAVE BEEN ENCRYPTED"; sid:1000001;)`) or Elastic detections for retroactive hunting across `conn.log`/`http.log`/`dns.log`.
- **IOC building:** bulk_extractor's `url.txt`/`email.txt`/`aes_keys.txt` rapidly produce a carved indicator list to push into detection and threat-intel enrichment. For example, the AES key can be used to decrypt files if the ransomware uses symmetric encryption (**T1486**).
- **Defense evasion detection:** Use `windows.malfind` to detect process injection (**T1055**), and `windows.registry.printkey` to check for disabled recovery options (**T1490**). Monitor **Windows Event ID 104** (Event Log Cleared) for **T1070.001 (Indicator Removal: Clear Windows Event Logs)**, and **Sysmon Event ID 25** (Process Tampering) for **T1562.003 (Impair Defenses: Impair Command History Logging)** (https://attack.mitre.org/techniques/T1070/001/ and https://attack.mitre.org/techniques/T1562/003/).

Detection nuance: because ransomware often encrypts fast, the strongest early SOC signals are behavioral — spikes in `conn.log`/`dns.log` to unfamiliar destinations, shadow-copy deletion (**T1490**), and volume of file-modify events (e.g., **Sysmon Event ID 11** for file creation) — rather than a single AV hit. Correlate these with **Windows Event ID 4663** (File System Object Access) to detect mass encryption (https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663).

## Attacker perspective
An attacker deploying ransomware runs an encryptor from a temporary path, often injecting into or spawning from a legitimate process to blend in (**T1055** Process Injection, https://attack.mitre.org/techniques/T1055/; **T1036** Masquerading, https://attack.mitre.org/techniques/T1036/). They contact a C2 or payment portal and drop a ransom note file across directories (**T1486**, https://attack.mitre.org/techniques/T1486/). To evade detection, they may also use **T1027 (Obfuscated Files or Information)** to pack payloads or encode commands.

Concrete TTPs and the artifacts they leave in RAM:
- **Defense evasion / anti-recovery:** deleting Volume Shadow Copies via `vssadmin delete shadows` or `wmic shadowcopy delete` (**T1490** Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/). Even after the process exits, its command line and image path may persist in `EPROCESS`/PEB structures recoverable by `windows.psscan` and `windows.cmdline`. Registry modifications to disable VSS (e.g., `HKLM\System\CurrentControlSet\Services\VSS\Start = 4`) are recoverable via `windows.registry.printkey`.
- **Process injection / hollowing:** RWX private memory regions and unbacked executable pages in the VAD tree are recoverable with `windows.malfind` (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind), which surfaces injected code that never touched disk. Attackers may use **T1055.001 (Dynamic-Link Library Injection)** or **T1055.012 (Process Hollowing)** to inject into `svchost.exe` or `explorer.exe` (https://attack.mitre.org/techniques/T1055/001/ and https://attack.mitre.org/techniques/T1055/012/).
- **C2 and note templates:** live/residual sockets to the C2 (`windows.netscan`), plus the ransom-note template string and sometimes symmetric keys or config blobs still resident on the heap — carved by bulk_extractor or matched by YARA. Attackers may use **T1071.001 (Web Protocols)** or **T1573.001 (Encrypted Channel: Symmetric Cryptography)** for C2 (https://attack.mitre.org/techniques/T1071/001/ and https://attack.mitre.org/techniques/T1573/001/).
- **Evasion techniques and their limits:** attackers delete the on-disk binary and note post-encryption, unlink processes (DKOM), pack/obfuscate payloads (**T1027**), and clear event logs (**T1070**). These defeat many disk artifacts but the memory image still preserves:
  - Pool-scannable process objects (`windows.psscan`), unlinked strings (`windows.strings`), and socket structures (`windows.netscan`) — exactly what Volatility 3 recovers.
  - Unbacked RWX memory regions (`windows.malfind`) and injected code.
  - Registry hives (`windows.registry.hivelist`) and modified keys (`windows.registry.printkey`), even if the on-disk hive is deleted.
  - Carved indicators (URLs, emails, keys) via bulk_extractor, which operates on raw bytes without filesystem dependencies.

Attackers may also use **T1564.003 (Hide Artifacts: Hidden Window)** to run the encryptor in a hidden window, or **T1562.001 (Impair Defenses: Disable or Modify Tools)** to disable AV/EDR (https://attack.mitre.org/techniques/T1564/003/ and https://attack.mitre.org/techniques/T1562/001/). These techniques leave artifacts in memory, such as modified registry keys or process command lines.

## Answer key
- **YARA:** `rule ransom_note_test` matches on `$a` ("HAVE BEEN ENCRYPTED"), `$b` ("LOCKBIT_TEST_MARKER"), and `$c` ("AES_KEY: ABCDEFGHIJKLMNOP").
```bash
yara -s exercise/ransom.yar exercise/memory.raw
```
Expected: `ransom_note_test exercise/memory.raw` with matched offsets for all three strings (the `-s` flag prints matched strings and offsets — https://yara.readthedocs.io/en/stable/commandline.html).

- **bulk_extractor URL + email + AES key:** the carved C2 URL is `http://203.0.113.10/pay`, the contact email is `evilmail@example.com`, and the AES key is `ABCDEFGHIJKLMNOP`.
```bash
bulk_extractor -E aes -o exercise/be_out exercise/memory.raw
grep -i "203.0.113.10" exercise/be_out/url.txt
grep -i "evilmail@example.com" exercise/be_out/email.txt
grep -i "ABCDEFGHIJKLMNOP" exercise/be_out/aes_keys.txt
```
Expected: all three greps return the seeded indicators (the `email`, `url`, and `aes` scanners are enabled by default or via `-E`; see the bulk_extractor manual, https://github.com/simsong/bulk_extractor).

- **Volatility 3 yarascan:** Use `windows.yarascan` to attribute the ransom-note strings to a process (even though this is a flat dump, the plugin will still work for demonstration).
```bash
vol -f exercise/memory.raw windows.yarascan -Y "HAVE BEEN ENCRYPTED"
```
Expected: output showing the physical offset and process context (if any) where the string was found. Nuance: in a real memory image, this would attribute the string to a specific PID (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.yarascan).

- **Sample sha256:** because the benign sample includes random padding, its digest varies per generation. Record the digest printed by the generator's `sha256sum exercise/memory.raw` as the authoritative value for your build. To create a fixed, reproducible digest, replace the two `head -c ... /dev/urandom`/`/dev/zero` lines with `head -c 8192 /dev/zero` (all-zero padding); that deterministic variant yields a stable sha256 you can pin in CI.

## MITRE ATT&CK & DFIR phase
- **T1486** Data Encrypted for Impact — the ransomware encryption behavior. https://attack.mitre.org/techniques/T1486/
- **T1071** Application Layer Protocol — C2/payment-portal communication observed via netscan. https://attack.mitre.org/techniques/T1071/
- **T1071.001** Web Protocols — C2 using HTTP/HTTPS. https://attack.mitre.org/techniques/T1071/001/
- **T1055** Process Injection — potential injected encryptor code in memory (see `windows.malfind`). https://attack.mitre.org/techniques/T1055/
- **T1055.001** Dynamic-Link Library Injection — DLL injection into legitimate processes. https://attack.mitre.org/techniques/T1055/001/
- **T1055.012** Process Hollowing — process hollowing into `svchost.exe` or `explorer.exe`. https://attack.mitre.org/techniques/T1055/012/
- **T1027** Obfuscated Files or Information — packed/obfuscated payloads whose strings are recovered from RAM. https://attack.mitre.org/techniques/T1027/
- **T1036** Masquerading — legitimately-named binaries used as cover. https://attack.mitre.org/techniques/T1036/
- **T1490** Inhibit System Recovery — shadow-copy deletion commonly seen with ransomware. https://attack.mitre.org/techniques/T1490/
- **T1112** Modify Registry — registry modifications to disable recovery or establish persistence. https://attack.mitre.org/techniques/T1112/
- **T1070** Indicator Removal — clearing event logs or deleting files. https://attack.mitre.org/techniques/T1070/
- **T1070.001** Clear Windows Event Logs — clearing event logs to hide activity. https://attack.mitre.org/techniques/T1070/001/
- **T1070.004** File Deletion — deleting the encryptor binary or ransom notes. https://attack.mitre.org/techniques/T1070/004/
- **T1059.001** Command and Scripting Interpreter: PowerShell — encoded PowerShell commands for execution. https://attack.mitre.org/techniques/T1059/001/
- **T1573.001** Encrypted Channel: Symmetric Cryptography — encrypted C2 communication. https://attack.mitre.org/techniques/T1573/001/
- **DFIR phases:** identification (triage the alert), examination/analysis (Volatility 3 + YARA + bulk_extractor on the image), and reporting (IOC list from carved indicators). The memory-forensics analysis workflow aligns with SANS FOR508 guidance (https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).

### Threat Hunting & Detection Engineering
Once you’ve extracted the ransomware’s process hive from memory, pivot to **live detection engineering** to hunt for similar tradecraft across the enterprise.

**Detection Logic**
1. **Process Injection Detection**:
   - Monitor **Sysmon Event ID 8** (CreateRemoteThread) for threads created in a target process by a source process (e.g., `powershell.exe` injecting into `svchost.exe`). This detects **T1055** (Process Injection) and **T1055.001** (Dynamic-Link Library Injection). Correlate with **Sysmon Event ID 10** (ProcessAccess) to identify suspicious access patterns (e.g., `PROCESS_VM_WRITE` or `PROCESS_VM_OPERATION`).
   - Use **Windows Event ID 4688** (Process Creation) to detect child processes of `explorer.exe` or `svchost.exe` with unusual command lines (e.g., `cmd.exe /c vssadmin delete shadows`). This maps to **T1059** (Command and Scripting Interpreter) and **T1490** (Inhibit System Recovery).

2. **Network-Based Detection**:
   - Hunt for **T1071.001 (Web Protocols)** in **Zeek’s `http.log`** by filtering for unusual `user_agent` strings (e.g., `curl` or custom agents) or POST requests to `/pay` or `/api` endpoints. Pair this with **Suricata alerts** for known ransomware C2 IPs (e.g., `alert http any any -> $HOME_NET any (msg:"Ransomware C2 Beacon"; content:"/pay"; sid:1000002;)`).
   - Detect **T1573.001 (Encrypted Channel: Symmetric Cryptography)** by analyzing **Zeek’s `ssl.log`** for unusual cipher suites (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`) or self-signed certificates. Use **Elasticsearch** to filter on `ssl.cipher: "TLS_RSA_WITH_AES_128_CBC_SHA"` and correlate with `destination.ip` from `conn.log`.

3. **Registry and File System Detection**:
   - Hunt for **T1112 (Modify Registry)** by querying **Windows Event ID 4657** (Registry Value Modified) for changes to `HKLM\System\CurrentControlSet\Services\VSS\Start` (value `0x4` disables VSS). This detects **T1490** (Inhibit System Recovery).
   - Monitor **Sysmon Event ID 11** (FileCreate) for ransom notes (e.g., `*_HOW_TO_DECRYPT.txt`) or encrypted files (e.g., `*.locked`). Correlate with **Windows Event ID 4663** (File System Object Access) to detect mass encryption.

4. **Defense Evasion Detection**:
   - Detect **T1070.001 (Clear Windows Event Logs)** by monitoring **Windows Event ID 1102** (Event Log Cleared). Correlate with **Sysmon Event ID 25** (ProcessTampering) to identify processes tampering with event logs.
   - Hunt for **T1562.001 (Impair Defenses: Disable or Modify Tools)** by querying **Windows Event ID 4688** for processes launching `sc stop WinDefend` or `net stop wscsvc` (disabling Windows Defender or Security Center).

**Threat-Hunting Pivots**
- **Zeek Logs**:
  - Pivot from `conn.log` to `dns.log` to identify DGA (Domain Generation Algorithm) patterns in `query` fields (e.g., `^[a-z0-9]{10}\.com$`). This maps to **T1568.002 (Dynamic Resolution: Domain Generation Algorithms)**.
  - Use `http.log` to hunt for unusual `uri` paths (e.g., `/c2` or `/api/key`) or `user_agent` strings (e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64) EvilRansomware/1.0`).

- **Elasticsearch**:
  - Create a dashboard to correlate `process.command_line` (from Sysmon Event ID 1) with `destination.ip` (from Zeek `conn.log`) to identify processes beaconing to known-bad IPs.
  - Hunt for **T1059.001 (PowerShell)** by filtering on `process.name: "powershell.exe"` and `process.command_line: "*-enc*"` or `"*[Convert]::FromBase64String*"`.

- **Registry**:
  - Query `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` for suspicious values (e.g., `*.exe` in `%TEMP%`). This detects **T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)**.
  - Hunt for **T1564.001 (Hide Artifacts: Hidden Files and Directories)** by identifying files with the `hidden` attribute (`attrib +h`) in `%APPDATA%` or `%PROGRAMDATA%`.

**Sources for Detection Logic**
- [CISA Alert AA23-325A: #StopRansomware Guide (Detection Section)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a)
- [Elastic Security Labs: Detecting Ransomware with Sysmon](https://www.elastic.co/security-labs/detecting-ransomware-with-sysmon)
- [Microsoft Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Zeek Log Reference](https://docs.zeek.org/en/master/logs/index.html)
- [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)
- [MITRE ATT&CK: Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: Inhibit System Recovery (T1490)](https://attack.mitre.org/techniques/T1490/)

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **Volatility 3**:
  - Invocation model, `--info`, symbol tables, and plugin behavior (`windows.info`, `pslist`, `psscan`, `pstree`, `cmdline`, `netscan`, `malfind`, `yarascan`, `registry.hivelist`, `registry.printkey`, `handles`):
    - Volatility 3 docs — https://volatility3.readthedocs.io/en/latest/
    - Basics / `--info` — https://volatility3.readthedocs.io/en/latest/basics.html
    - Symbol tables — https://volatility3.readthedocs.io/en/latest/symbol-tables.html
    - Windows plugins reference — https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html
    - Source — https://github.com/volatilityfoundation/volatility3
    - The Volatility Foundation — https://www.volatilityfoundation.org/
  - `windows.malfind` and process injection detection:
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind
    - SANS FOR508: Memory Forensics — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
  - `windows.yarascan` for per-process YARA scanning:
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.yarascan
  - `windows.registry.hivelist` and `windows.registry.printkey` for registry analysis:
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.hivelist
    - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.registry.printkey

- **YARA**:
  - `--version`, `-s` flag, and rule syntax (`strings:`/`condition:`/`any of them`):
    - YARA command-line reference — https://yara.readthedocs.io/en/stable/commandline.html
    - YARA writing rules — https://yara.readthedocs.io/en/stable/writingrules.html
    - Source — https://github.com/VirusTotal/yara
    - Kali Tools (yara) — https://www.kali.org/tools/yara/
  - YARA for crypto key detection:
    - https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings

- **bulk_extractor**:
  - `-V`, `-o`, `-E` behavior, and default `url`/`email`/`aes` scanners:
    - Source & manual — https://github.com/simsong/bulk_extractor
    - Feature scanners — https://github.com/simsong/bulk_extractor/wiki/Feature-Scanners
  - AES key carving:
    - https://github.com/simsong/bulk_extractor/wiki/AES-Key-Finder

- **Tool availability on analyst distros**:
  - REMnux tool listings — https://docs.remnux.org/discover-the-tools/
  - SANS SIFT Workstation — https://www.sans.org/tools/sift-workstation/

- **Security Onion / Suricata / Zeek**:
  - Analyst workflow, Suricata alerts, Zeek `conn.log`, `http.log`, `ssl.log`, and pivots:
    - Security Onion docs — https://docs.securityonion.net/en/2.4/
    - Zeek log reference — https://docs.zeek.org/en/master/logs/index.html
    - Suricata rule writing — https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html
    - Elasticsearch integration — https://docs.securityonion.net/en/2.4/elasticsearch.html

- **MITRE ATT&CK techniques cited**:
  - T1486 — https://attack.mitre.org/techniques/T1486/
  - T1071 — https://attack.mitre.org/techniques/T1071/ ; T1071.001 — https://attack.mitre.org/techniques/T1071/001/
  - T1055 — https://attack.mitre.org/techniques/T1055/ ; T1055.001 — https://attack.mitre.org/techniques/T1055/001/ ; T1055.012 — https://attack.mitre.org/techniques/T1055/012/
  - T1027 — https://attack.mitre.org/techniques/T1027/
  - T1036 — https://attack.mitre.org/techniques/T1036/
  - T1490 — https://attack.mitre.org/techniques/T1490/
  - T1112 — https://attack.mitre.org/techniques/T1112/
  - T1070 — https://attack.mitre.org/techniques/T1070/ ; T1070.001 — https://attack.mitre.org/techniques/T1070/001/ ; T1070.004 — https://attack.mitre.org/techniques/T1070/004/
  - T1059 — https://attack.mitre.org/techniques/T1059/ ; T1059.001 — https://attack.mitre.org/techniques/T1059/001/
  - T1573 — https://attack.mitre.org/techniques/T1573/ ; T1573.001 — https://attack.mitre.org/techniques/T1573/001/
  - T1041 — https://attack.mitre.org/techniques/T1041/
  - T1547.001 — https://attack.mitre.org/techniques/T1547/001/
  - T1562.001 — https://attack.mitre.org/techniques/T1562/001/
  - T1564.003 — https://attack.mitre.org/techniques/T1564/003/
  - T1568.002 — https://attack.mitre.org/techniques/T1568/002/

- **RFC 5737** (documentation IP ranges incl. 203.0.113.0/24) — https://datatracker.ietf.org/doc/html/rfc5737

- **Windows Event Logs**:
  - Event ID 4688 (Process Creation) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
  - Event ID 4663 (File System Object Access) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
  - Event ID 104 (Event Log Cleared) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-104
  - Event ID 4657 (Registry Value Modified) — https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657

- **Sysmon Events**:
  - Event ID 1 (Process Creation) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
  - Event ID 8 (CreateRemoteThread) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-8-createremotethread
  - Event ID 10 (ProcessAccess) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-10-processaccess
  - Event ID 11 (FileCreate) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-11-filecreate
  - Event ID 25 (ProcessTampering) — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-25-processtampering

- **SANS FOR508** (IR/threat-hunting & memory forensics methodology) — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

- **Detection Engineering**:
  - CISA #StopRansomware Guide — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a
  - Elastic Security Labs: Detecting Ransomware with Sysmon — https://www.elastic.co/security-labs/detecting-ransomware-with-sysmon

## Related modules
- [Memory forensics](../02-memory-forensics/README.md) -- shares bulk_extractor for carving IOCs from RAM captures.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- shares bulk_extractor and extends the Volatility 3 plugin workflow used here, including advanced process injection analysis.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares yara for signature-based hunting of C2 indicators and extends network-based detection logic.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares bulk_extractor within a full host-triage pipeline, including registry and file system artifact analysis.

<!-- cyberlab-enriched: v3 -->
