# 02 * Memory forensics -- LAB-LINUX

## Overview (plain language)
When a computer is running, its short-term memory (RAM) holds a live snapshot of everything happening right now: running programs, open network connections, typed passwords, encryption keys, and even decrypted documents. Unlike the hard disk, this data disappears when the machine powers off. Memory forensics is the practice of capturing that RAM into a file (a "memory image") and then analyzing it to reconstruct attacker activity, malware behavior, or data exposure. The tools in this module read those raw memory dumps: **Volatility 3** lists processes, network connections, and injected code; **bulk_extractor** sweeps the dump for embedded artifacts like emails, URLs, and credit card numbers; and **aeskeyfind**/**rsakeyfind** hunt for cryptographic keys that can decrypt ransomware payloads or C2 traffic. Together, they enable an investigator to answer "what was this machine doing when it was captured?" without trusting the potentially compromised operating system.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | `apt install volatility3` | Framework to parse RAM images (processes, DLLs, network artifacts, injected code, timelines) using OS-specific plugins (`windows.*`, `linux.*`, `mac.*`). The CLI entry point is `vol` (or `vol.py`). |
| bulk_extractor | `apt install bulk-extractor` | Scans raw images/dumps for embedded features (emails, URLs, domains, credit cards, PII) and carves network packets into a `packets.pcap`. Operates on raw byte streams, not file systems. |
| aeskeyfind | `apt install aeskeyfind` | Locates AES key schedules (expanded round keys) resident in a memory dump, enabling decryption of encrypted payloads or traffic. |
| rsakeyfind | `apt install rsakeyfind` | Locates RSA private keys and certificates (BER-encoded structures) resident in a memory dump. |

**Notes on tool behavior (verified against authoritative sources):**
- **Volatility 3** is a Python framework that auto-detects the OS profile of the memory image and selects the appropriate symbol tables. It replaces the manual profile selection of Volatility 2 with automatic symbol resolution. Plugins are namespaced by OS (e.g., `windows.pslist`, `linux.lsof`). The `vol` command is the console entry point installed by the `volatility3` package ([Volatility 3 Documentation](https://volatility3.readthedocs.io/)).
- **bulk_extractor** scans any input (disk image, memory dump, raw file) for *features* using independent scanners. It writes one feature file per scanner (e.g., `url.txt`, `email.txt`, `domain.txt`) and can carve a `packets.pcap` from network-looking data. The `-V` flag prints the version banner ([simsong/bulk_extractor GitHub](https://github.com/simsong/bulk_extractor)).
- **aeskeyfind** and **rsakeyfind** originate from the Princeton "Lest We Remember" cold-boot research. `aeskeyfind` searches for AES key *schedules* (the expanded round keys, not just raw key bytes), while `rsakeyfind` searches for RSA private keys and BER-encoded certificates. Both tools require a memory-image path as their argument ([Princeton CITP Memory Research](https://citp.princeton.edu/our-work/memory/)).

## Learning objectives
- Verify the memory-forensics toolchain is installed and runnable on LAB-LINUX.
- Enumerate processes, network artifacts, and injected code from a RAM image using Volatility 3 plugins.
- Extract embedded features (URLs, emails, domains, PII) from a raw dump with bulk_extractor.
- Recover candidate AES/RSA cryptographic keys from memory with aeskeyfind and rsakeyfind.
- Map memory-forensics findings to **MITRE ATT&CK techniques** and **DFIR examination phases**, including:
  - **T1055 Process Injection** (and sub-techniques **T1055.001 DLL Injection**, **T1055.002 PE Injection**, **T1055.012 Process Hollowing**, **T1055.013 Process Herpaderping**)
  - **T1620 Reflective Code Loading**
  - **T1014 Rootkit** (DKOM/unlinking)
  - **T1134.004 Parent PID Spoofing**
  - **T1573 Encrypted Channel** (and sub-technique **T1573.001 Symmetric Cryptography**)
  - **T1071 Application Layer Protocol** (and sub-technique **T1071.001 Web Protocols**)
  - **T1059 Command and Scripting Interpreter** (and sub-technique **T1059.001 PowerShell**)
  - **T1005 Data from Local System**
  - **T1564.001 Hidden Window** (process hiding via window station manipulation)
  - **T1547.001 Registry Run Keys** (persistence via autostart)
  - **T1562 Impair Defenses** (detection of defense tampering)
  - **T1070.004 File Deletion** (detection of deleted files in memory)

## Environment check
```bash
# Prove each tool is present on the VM
vol --help | head -n 3
bulk_extractor -V
aeskeyfind 2>&1 | head -n 1
rsakeyfind 2>&1 | head -n 1
```
**Expected output:**
- `vol --help` prints the Volatility 3 usage banner (the framework's `argparse` help). The `vol` command is the console entry point installed by the `volatility3` package ([Volatility 3 Documentation](https://volatility3.readthedocs.io/)).
- `bulk_extractor -V` prints a version banner such as `bulk_extractor 2.x.x`. The `-V` flag is documented in the [simsong/bulk_extractor GitHub repo](https://github.com/simsong/bulk_extractor).
- `aeskeyfind` and `rsakeyfind` print their usage lines when invoked with no input argument, as both require a memory-image path as their argument ([Princeton CITP Memory Research](https://citp.princeton.edu/our-work/memory/)).

## Guided walkthrough
Each command below is annotated with **WHY** it is run and **what nuance to read** in the output.

---

1. **Confirm Volatility 3 can parse the memory image and report OS/kernel details.**
   ```bash
   vol -f $IMAGE windows.info
   ```
   **WHY:** This is the first sanity check. `windows.info` reads kernel structures (`KDBG`, `KUSER_SHARED_DATA`) to report the NT build number, kernel base, and other OS metadata. If this fails, downstream `windows.*` plugins will not work.
   **Nuance:**
   - A successful run confirms Volatility 3 auto-detected the correct symbol tables for the image.
   - A failure (e.g., "symbol table not found") indicates a data-quality issue: wrong OS, truncated capture, or a hibernation/crash-dump format needing conversion. This is a **data-quality signal**, not a "no findings" result ([Volatility 3 Documentation](https://volatility3.readthedocs.io/)).
   - Before analyzing a real image, list available plugins to confirm the framework is installed:
     ```bash
     vol -h | grep -i -E "pslist|netscan|windows.info" | head -n 10
     ```
     **Expected:** Plugin names such as `windows.pslist`, `windows.netscan`, `windows.info` are listed. Volatility 3 plugins are namespaced by OS (`windows.`, `linux.`, `mac.`), and their presence confirms the framework and symbol packs are installed ([Volatility 3 Documentation](https://volatility3.readthedocs.io/)).
   **NOTE:** The synthetic `sample.mem` in this module is an inert byte blob with **no** OS structures, so `windows.info`/`windows.pslist` will not return a valid Windows profile against it. These steps illustrate the workflow for a real Windows RAM capture.

---

2. **Enumerate processes from a real Windows image (workflow illustration).**
   ```bash
   vol -f $IMAGE windows.pslist | head -n 20
   ```
   **WHY:** `windows.pslist` walks the doubly-linked `EPROCESS` list (`ActiveProcessLinks`), which is the same list the OS uses to enumerate processes. This is the "live" view of running processes.
   **Expected output:** A table with columns: `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `CreateTime`, `ExitTime`.
   **Nuance:**
   - **Rootkit hiding via DKOM:** A rootkit can unlink an `EPROCESS` from `ActiveProcessLinks` to hide it from `pslist`. This is why analysts **must** follow up with `windows.psscan` (pool-tag scanning), which finds unlinked or terminated processes. A PID present in `psscan` but absent from `pslist` is a classic indicator of **T1014 Rootkit** ([SANS Memory Forensics Cheat Sheet](https://www.sans.org/posters/memory-forensics-cheat-sheet/)).
   - **Parent-child anomalies:** The `PPID` column reveals parentage. Flag processes where:
     - `lsass.exe` or `svchost.exe` is parented by anything other than `services.exe`/`wininit.exe` (parent spoofing, **T1134.004 Parent PID Spoofing**).
     - `explorer.exe` parents a process running from `%TEMP%` or `%APPDATA%` (abnormal execution path, **T1059.001 PowerShell**).
     - `cmd.exe`/`powershell.exe` is parented by `winword.exe`/`outlook.exe` (phishing delivery, **T1566 Phishing**).
   - **Terminated processes:** A populated `ExitTime` indicates the process terminated. If `ExitTime` is set but the process still has open handles, it may be a **terminated-yet-resident** artifact (e.g., a process hollowed and then exited, leaving injected code behind).

---

3. **Compare `pslist` and `psscan` to detect hidden processes.**
   ```bash
   vol -f $IMAGE windows.psscan.PsScan > psscan.txt
   vol -f $IMAGE windows.pslist > pslist.txt
   grep -v -F -f <(awk '{print $3}' pslist.txt) <(awk '{print $3}' psscan.txt) | head -n 10
   ```
   **WHY:** This command identifies PIDs present in `psscan` (pool-tag scanning) but absent from `pslist` (`ActiveProcessLinks`). These are candidates for **T1014 Rootkit** (DKOM/unlinking) or terminated processes.
   **Nuance:**
   - **Pool-tag scanning (`psscan`):** Scans kernel pool allocations for `EPROCESS` objects, regardless of their linkage in `ActiveProcessLinks`. This catches unlinked or terminated processes ([Volatility 3 Documentation](https://volatility3.readthedocs.io/)).
   - **Detection logic:** The `grep` command performs a set-difference on the `PID` column. Any PID only in `psscan` is a high-priority lead.
   - **Terminated processes:** If a PID has a populated `ExitTime` in `psscan` but still has open handles (check with `windows.handles.Handles --pid <PID>`), it may indicate a **terminated-yet-resident** artifact (e.g., injected code left behind after the parent process exited).

---

4. **Detect injected code with `malfind`.**
   ```bash
   vol -f $IMAGE windows.malfind.Malfind --dump
   ```
   **WHY:** `malfind` scans process memory for regions that are **private, committed, and executable (RWX)** with no backing file. This is the fingerprint of **T1055 Process Injection** (DLL/PE injection, reflective loading).
   **Expected output:** A table with columns: `PID`, `Process`, `Start VPN`, `End VPN`, `Tag`, `Protection`, `CommitCharge`, `PrivateMemory`, `FileOutput`, `Hits`.
   **Nuance:**
   - **RWX private memory:** The `Protection` column will show `PAGE_EXECUTE_READWRITE` for injected code. This is a **high-priority indicator** for **T1055.001 DLL Injection** or **T1055.002 PE Injection**.
   - **MZ/PE headers:** Regions beginning with an `MZ` header (check the `Hits` column or the dumped file) inside private/committed memory are **extremely suspicious**. This is a hallmark of **T1055.012 Process Hollowing** or **T1620 Reflective Code Loading**.
   - **No backing file:** The `FileOutput` column will be empty for injected code, as it has no on-disk counterpart.
   - **Corroboration:** Cross-reference with `windows.dlllist.DllList` to confirm the region is not a legitimately loaded DLL. For hollowing, compare the mapped section's on-disk image with the in-memory contents at the PE's declared base ([SANS Memory Forensics Cheat Sheet](https://www.sans.org/posters/memory-forensics-cheat-sheet/)).
   - **Detection on live systems:** On-host analogues include **Sysmon Event ID 8 (CreateRemoteThread)** and **Sysmon Event ID 10 (ProcessAccess)** where `GrantedAccess` includes `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD`. **Sysmon Event ID 25 (ProcessTampering)** flags hollowing/herpaderping ([Microsoft Learn Sysmon Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).

---

5. **Recover network artifacts with `netscan`.**
   ```bash
   vol -f $IMAGE windows.netscan.NetScan
   ```
   **WHY:** `netscan` recovers TCP/UDP endpoints, including closed connections, and maps them to owning PIDs. This exposes C2 sockets even if the live OS `netstat` was tampered with.
   **Expected output:** A table with columns: `Offset(P)`, `Proto`, `LocalAddr`, `LocalPort`, `ForeignAddr`, `ForeignPort`, `State`, `PID`, `Owner`, `Created`.
   **Nuance:**
   - **C2 channels:** Look for connections to unusual IPs/domains, especially on non-standard ports. Pivot these to **Zeek** `conn.log` (`id.orig_h`, `id.resp_h`, `resp_bytes`) or **Suricata** alerts for further analysis (**T1071 Application Layer Protocol**, **T1071.001 Web Protocols**).
   - **Beaconing:** Group connections by `ForeignAddr` and look for low-jitter, regular-interval connections with small, uniform `orig_bytes`. This is the network fingerprint of a beacon (**T1071.001 Web Protocols**).
   - **Closed connections:** Even if the connection is in `CLOSED` state, the `ForeignAddr`/`ForeignPort` may reveal historical C2 activity.
   - **Zeek/Suricata pivots:** Use the recovered IPs/domains to hunt in:
     - **Zeek** `conn.log` (`id.orig_h`, `id.resp_h`), `dns.log` (`query`, `answers`), `ssl.log` (`server_name`, `ja3`, `ja3s`), and `http.log` (`host`, `uri`, `user_agent`).
     - **Suricata** signatures using `dns.query`, `tls.sni`, or `http.host` sticky buffers ([Security Onion Documentation](https://docs.securityonion.net/)).

---

6. **Recover command lines and loaded modules.**
   ```bash
   vol -f $IMAGE windows.cmdline.CmdLine
   vol -f $IMAGE windows.dlllist.DllList --pid <PID>
   ```
   **WHY:** `windows.cmdline` recovers the full command-line arguments for each process, while `windows.dlllist` lists all DLLs loaded by a process. Both are critical for detecting **T1059 Command and Scripting Interpreter** and **T1574 Hijack Execution Flow**.
   **Nuance:**
   - **Command-line anomalies:** Flag processes with:
     - Unusual parentage (e.g., `powershell.exe` parented by `winword.exe`, **T1566 Phishing**).
     - Suspicious arguments (e.g., `-nop -ep bypass -c`, **T1059.001 PowerShell**).
     - Mismatched image path vs command line (e.g., `svchost.exe` running from `%TEMP%`, **T1134.004 Parent PID Spoofing**).
   - **DLL anomalies:** Flag processes loading:
     - Unsigned or unusual DLLs (e.g., `amsi.dll` from `%APPDATA%`, **T1574.001 DLL Search Order Hijacking**).
     - DLLs with mismatched signatures (e.g., a legitimate DLL replaced with a malicious one, **T1574.002 DLL Side-Loading**).
     - Reflective DLLs (DLLs loaded without `LoadLibrary`, visible in `windows.dlllist` but not in the module list, **T1620 Reflective Code Loading**).

---

7. **Sweep the raw dump for embedded features with bulk_extractor.**
   ```bash
   cd exercise
   mkdir -p be_out
   bulk_extractor -o be_out sample.mem
   ls be_out
   head -n 10 be_out/url.txt
   ```
   **WHY:** bulk_extractor scans the raw byte stream for features (URLs, emails, domains, credit cards, etc.) and carves network packets into a `packets.pcap`. It works on any input, including memory dumps, and does not require OS structures.
   **Expected output:** The `be_out/` directory contains feature files (`url.txt`, `email.txt`, `domain.txt`, `ccn.txt`, etc.) and reporting files (`report.xml`). `url.txt` lists recovered URLs prefixed by their byte offset.
   **Nuance:**
   - **Feature-file format:** Each line is `offset<TAB>feature<TAB>context`. The leading offset is the byte position in `sample.mem` where the feature was found. This is critical for **evidence citation** ([simsong/bulk_extractor GitHub](https://github.com/simsong/bulk_extractor)).
   - **Network carving:** The `packets.pcap` file contains carved network traffic. Re-ingest this into **Zeek** or **Suricata** to regenerate protocol logs and alerts for the in-memory traffic fragments.
   - **PII recovery:** `ccn.txt` (credit card numbers) and `telephone.txt` (phone numbers) can reveal data exfiltration or exposure (**T1005 Data from Local System**).
   - **Hunting pivots:** Use recovered URLs/domains to hunt in:
     - **Zeek** `http.log` (`host`, `uri`), `dns.log` (`query`), and `ssl.log` (`server_name`).
     - **Suricata** signatures using `http.host` or `dns.query` sticky buffers.
     - **Elastic** in Security Onion for cross-host pivots on `destination.ip` or `dns.query`.

---

8. **Search memory for cryptographic key material.**
   ```bash
   cd exercise
   aeskeyfind sample.mem
   rsakeyfind sample.mem
   ```
   **WHY:** `aeskeyfind` detects AES key schedules (expanded round keys), while `rsakeyfind` detects RSA private keys and certificates. These keys can decrypt C2 traffic, ransomware payloads, or encrypted configurations.
   **Expected output:**
   - `aeskeyfind` prints any 128/256-bit AES key schedules found (or "No keys found").
   - `rsakeyfind` prints candidate RSA keys/certificates (or none).
   **Nuance:**
   - **AES key schedules:** `aeskeyfind` does not look for raw key bytes alone. It detects the **expanded AES key schedule**, which has a statistically detectable structure in RAM even after the process context is gone. This is the technique from the Princeton cold-boot research ([Princeton CITP Memory Research](https://citp.princeton.edu/our-work/memory/)).
   - **RSA keys:** `rsakeyfind` looks for BER-encoded RSA private keys and certificates. These are often used for encrypted C2 (**T1573 Encrypted Channel**, **T1573.001 Symmetric Cryptography**).
   - **Decryption:** Recovered keys can decrypt:
     - Captured C2 traffic (e.g., Cobalt Strike beacons, Metasploit sessions).
     - Ransomware payloads (e.g., decrypting the ransom note or sample files).
     - Encrypted configurations (e.g., malware C2 domains, encryption keys).
   - **Evasion:** Attackers may minimize the time keys are resident in memory (e.g., decrypting only when needed, then zeroing memory). However, a memory capture taken during active encryption/decryption will likely contain the key schedule.

---

9. **Generate a unified timeline with `timeliner`.**
   ```bash
   vol -f $IMAGE windows.timeliner.Timeliner --output=body
   ```
   **WHY:** `timeliner` generates a unified timeline of process, file, and registry events, enabling correlation of memory artifacts with other data sources.
   **Expected output:** A bodyfile-format timeline with columns: `MD5`, `Name`, `Inode`, `Mode`, `UID`, `GID`, `Size`, `ATime`, `MTime`, `CTime`, `BTime`.
   **Nuance:**
   - **Correlation:** Use the timeline to correlate memory artifacts (e.g., process creation) with disk artifacts (e.g., file creation) or network logs (e.g., connection timestamps).
   - **Anomalies:** Look for:
     - Processes created at unusual times (e.g., outside business hours).
     - Files accessed/modified by suspicious processes (e.g., `lsass.exe` reading a `.txt` file).
     - Registry keys modified by unexpected processes (e.g., `svchost.exe` writing to `Run` keys, **T1547.001 Registry Run Keys**).
   - **DFIR integration:** The bodyfile format is compatible with **The Sleuth Kit (TSK)** and **Plaso/log2timeline**, enabling integration with disk forensics timelines ([Volatility 3 Documentation](https://volatility3.readthedocs.io/)).

---

10. **Detect hidden windows and GUI artifacts.**
    ```bash
    vol -f $IMAGE windows.gui.WindowsGUI
    ```
    **WHY:** `windows.gui` recovers window stations, desktops, and windows, including hidden ones. This can reveal **T1564.001 Hidden Window** (process hiding via window station manipulation).
    **Expected output:** A table with columns: `Session`, `Desktop`, `WindowStation`, `WindowTitle`, `ClassName`, `PID`, `TID`, `Visible`.
    **Nuance:**
    - **Hidden windows:** A window with `Visible=0` may indicate a hidden GUI process (e.g., a keylogger or RAT with a hidden interface).
    - **Window titles:** Unusual window titles (e.g., "C2 Listener") can reveal attacker activity.
    - **Class names:** Unusual class names (e.g., "ThunderRT6FormDC") may indicate custom malware GUIs.

---

## Hands-on exercise
Work inside this module's `exercise/` directory.

- **Sample artifact:** `exercise/sample.mem`
- **Type:** A small, inert raw memory-style dump — a synthetic byte blob generated on the lab host that embeds benign, planted strings (a fake URL `http://benign.lab.local/beacon`, a fake email `analyst@lab.local`, and a randomly generated 256-bit AES key schedule for detection practice). It contains **no** operating-system code and **no** live malware.
- **Safe origin:** Generated locally with `dd`/`openssl` on the LAB-LINUX VM (no network egress); it is benign and inert.
- **sha256:** `1b9ec05c29ac4719bad31dae28af7e852b700b2e2c03e80dd8553fdbdb96c5c1`

**Tasks:**
1. Use bulk_extractor to recover the planted URL and email. Record the byte offsets where they are found.
2. Use aeskeyfind to recover the planted AES key. Record the key and its offset.
3. (Optional) Confirm no RSA keys are planted by running rsakeyfind.
4. (Advanced) Use bulk_extractor to carve the `packets.pcap` and inspect it with Wireshark or Zeek.

---

## SOC analyst perspective
In a SOC, memory forensics is the **go-to technique** when disk and log evidence appear clean, but a host exhibits suspicious behavior — a classic sign of **fileless malware**, **in-memory implants**, or **living-off-the-land (LOLBin) abuse**. An analyst pulls a RAM image from a suspect endpoint and works a **repeatable Volatility 3 triage sequence** to uncover hidden artifacts:

1. **Process enumeration:**
   - `vol -f $IMAGE windows.pslist` vs `vol -f $IMAGE windows.psscan` — compare the active-list view (`ActiveProcessLinks`) against pool-tag scanning. A PID present in `psscan` but absent from `pslist` suggests **DKOM/unlinking** to hide a process (**T1014 Rootkit**).
   - `vol -f $IMAGE windows.malfind` — flags process memory that is **private, committed, and executable (RWX)** with no backing file. This is the fingerprint of **T1055 Process Injection** (DLL/PE injection, reflective loading) and **T1620 Reflective Code Loading**.
   - `vol -f $IMAGE windows.cmdline` / `windows.dlllist` — recovers command lines and loaded modules for suspicious PIDs. Look for:
     - Unusual parentage (e.g., `powershell.exe` parented by `winword.exe`, **T1566 Phishing**).
     - Suspicious arguments (e.g., `-nop -ep bypass -c`, **T1059.001 PowerShell**).
     - Unsigned or unusual DLLs (e.g., `amsi.dll` from `%APPDATA%`, **T1574.001 DLL Search Order Hijacking**).

2. **Network artifacts:**
   - `vol -f $IMAGE windows.netscan` — recovers TCP/UDP endpoints and owning PIDs, exposing C2 sockets even if the live OS `netstat` was tampered with. Pivot these to **Zeek** `conn.log` or **Suricata** alerts for further analysis (**T1071 Application Layer Protocol**, **T1071.001 Web Protocols**).
   - **Beaconing hunt:** Group connections by `ForeignAddr` and look for low-jitter, regular-interval connections with small, uniform `orig_bytes`. This is the network fingerprint of a beacon (**T1071.001 Web Protocols**).

3. **Cryptographic keys:**
   - `aeskeyfind` / `rsakeyfind` — recover AES/RSA keys to decrypt C2 traffic or ransomware payloads (**T1573 Encrypted Channel**, **T1573.001 Symmetric Cryptography**).

4. **Timeline analysis:**
   - `vol -f $IMAGE windows.timeliner.Timeliner` — generates a unified timeline of process, file, and registry events. Correlate memory artifacts with disk/network logs to reconstruct the attack chain.

5. **Defense impairment detection (T1562):**
   - `vol -f $IMAGE windows.cmdline` — look for commands disabling security tools (e.g., `net stop Sentine`, `sc config WinDefend start= disabled`). These commands are often run with elevated privileges.
   - `vol -f $IMAGE windows.registry.PrintKey` — check for registry modifications that disable monitoring (e.g., `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`). Sysmon Event ID 12/13/14 captures these tamper events ([Microsoft Learn Sysmon Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).
   - On-host detection: **Windows Event ID 4688 (Process Creation)** with command lines containing `net stop`, `sc config`, or `reg add` targeting security product keys.

6. **File deletion detection (T1070.004):**
   - `vol -f $IMAGE windows.filescan` — recovers file objects from memory, including those that have been deleted from the filesystem but still have open handles. A file with a `FileName` containing suspicious content (e.g., `malware.exe`) that is marked as deleted (`0x0` in some fields) may indicate deliberate removal.
   - `vol -f $IMAGE windows.pslist` / `windows.cmdline` — look for processes executing deletion commands (e.g., `del`, `rm`, `wevtutil cl`). Sysmon Event ID 11 (FileCreate) and Event ID 23 (FileDelete) can also flag deletion events ([Microsoft Learn Sysmon Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).

---

### **Detection-Engineering Logic (Tied to Concrete Artifacts/Fields)**
Memory forensics findings must be **actionable** in the SOC. Below are **specific detection rules** tied to **real log sources** and **MITRE ATT&CK techniques**:

---

#### **1. Process Injection (T1055, T1055.001, T1055.002, T1055.012, T1620)**
**Memory artifact:**
- `windows.malfind` output where:
  - `Protection` = `PAGE_EXECUTE_READWRITE`.
  - `PrivateMemory` = `1` (no backing file).
  - `Hits` column contains an `MZ` header (PE file signature).

**On-host detection (Sysmon):**
- **Sysmon Event ID 8 (CreateRemoteThread):**
  - `SourceImage` = suspicious process (e.g., `powershell.exe`, `rundll32.exe`).
  - `TargetImage` = legitimate process (e.g., `svchost.exe`, `explorer.exe`).
  - `StartAddress` falls within a private/committed RWX region (correlate with `windows.malfind`).
- **Sysmon Event ID 10 (ProcessAccess):**
  - `GrantedAccess` includes `PROCESS_VM_WRITE` or `PROCESS_CREATE_THREAD`.
  - `SourceImage` = suspicious process, `TargetImage` = legitimate process.
- **Sysmon Event ID 25 (ProcessTampering):**
  - Flags process hollowing/herpaderping (**T1055.012 Process Hollowing**).

**Zeek/Suricata pivots:**
- Hunt for **Zeek** `conn.log` entries where:
  - `id.orig_h` = host with injected process.
  - `id.resp_h` = known C2 IP/domain (from `windows.netscan` or bulk_extractor `url.txt`).
  - `service` = `http`, `https`, or non-standard port (e.g., 4444, 8443).
- Create **Suricata** signatures for:
  - `http.host` or `tls.sni` matching carved C2 domains.
  - `dns.query` matching carved domains (e.g., `content:"benign.lab.local";`).

**Threat-hunting query (Kibana/Elastic):**
```kql
event.dataset: "windows.sysmon_operational" and
(event.code: 8 or event.code: 10 or event.code: 25) and
process.parent.name: ("powershell.exe" or "rundll32.exe" or "regsvr32.exe")
```

**References:**
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- [MITRE ATT&CK T1055.002](https://attack.mitre.org/techniques/T1055/002/)
- [MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)
- [Microsoft Learn Sysmon Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SANS Memory Forensics Cheat Sheet](https://www.sans.org/posters/memory-forensics-cheat-sheet/)

---

#### **2. DKOM/Process Unlinking (T1014 Rootkit)**
**Memory artifact:**
- Set-difference between `windows.pslist` and `windows.psscan`:
  - Any PID present in `psscan` but absent from `pslist` is a candidate for **T1014 Rootkit**.
  - If the PID has a populated `ExitTime` but still has open handles, it may be a **terminated-yet-resident** artifact.

**On-host detection (Windows Event Logs):**
- **Windows Event ID 4688 (Process Creation):**
  - Look for processes with no corresponding `4689` (Process Termination) event, but with open handles (check `windows.handles.Handles`).
- **Windows Event ID 4656 (Handle Requested):**
  - Correlate with `windows.handles.Handles` to detect handles held by unlinked processes.

**Zeek/Suricata pivots:**
- Hunt for **Zeek** `conn.log` entries where:
  - `id.orig_p` = PID only found in `psscan` (not `pslist`).
  - `id.resp_h` = known C2 IP/domain.

**Threat-hunting query (Kibana/Elastic):**
```kql
event.code: 4688 and
not event.code: 4689 and
process.pid: (psscan_pids - pslist_pids)
```

**References:**
- [MITRE ATT&CK T1014](https://attack.mitre.org/techniques/T1014/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [SANS Memory Forensics Cheat Sheet](https://www.sans.org/posters/memory-forensics-cheat-sheet/)

---

#### **3. Parent PID Spoofing (T1134.004)**
**Memory artifact:**
- `windows.pslist` + `windows.cmdline`:
  - A process with a mismatched `PPID` vs `ParentImageFileName` (e.g., `powershell.exe` parented by `winword.exe`).
  - A process with a mismatched `ImageFileName` vs `CommandLine` (e.g., `
