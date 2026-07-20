# 47 * Scenario: ransomware memory investigation -- LAB-LINUX

## Overview (plain language)
Imagine a workstation gets locked by ransomware and someone captures a snapshot of everything the computer was holding in its memory (RAM). This module teaches you how to open that snapshot and look inside it. RAM contains a treasure map: which programs were running, what web addresses they talked to, and even leftover text and keys. We use three tools together. Volatility 3 reads the raw memory file and lists processes, network connections, and injected code. YARA scans the same memory for known "signatures" of bad software. bulk_extractor sweeps through the memory blindly and pulls out useful bits like URLs, email addresses, and crypto artifacts. Together they help you reconstruct what the ransomware did.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Volatility 3 | apt install volatility3 | Framework to extract processes, network, and injected code from a RAM capture |
| YARA | apt install yara | Pattern-matching engine to flag malware signatures inside memory or files |
| bulk_extractor | apt install bulk-extractor | Bulk scanner that carves URLs, emails, and other IOCs from raw data without a filesystem |

Notes on tool identity and provenance:
- Volatility 3 is the current Python 3 rewrite of the Volatility framework and uses the `vol` (or `vol.py`/`vol3`) entry point with a `plugins`-based invocation model (`vol -f <image> <os>.<plugin>`); see the official docs at https://volatility3.readthedocs.io/en/latest/ and the source at https://github.com/volatilityfoundation/volatility3.
- YARA is authored by VirusTotal; documentation and the rule language reference are at https://yara.readthedocs.io/ and source at https://github.com/VirusTotal/yara.
- bulk_extractor is Simson Garfinkel's stream-based feature/carving tool; source and manual are at https://github.com/simsong/bulk_extractor. Both Volatility and bulk_extractor ship on REMnux (https://docs.remnux.org/discover-the-tools/) and the SANS SIFT Workstation (https://www.sans.org/tools/sift-workstation/).

## Learning objectives
- Enumerate running processes and suspicious parent/child relationships in a memory image using Volatility 3.
- Extract network connections and command-line arguments tied to a ransomware process.
- Scan a memory image with a custom YARA rule and interpret hits.
- Carve indicators of compromise (URLs, ransom-note strings) from RAM with bulk_extractor.

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
Expected: a key/value table showing `NTBuildLab`/kernel base, DTB, and the capture's `SystemTime`. Nuance: if this fails or shows no symbols, the rest of the walkthrough will be unreliable — you likely need matching symbol files (https://volatility3.readthedocs.io/en/latest/symbol-tables.html).

2. `vol -f memory.raw windows.pslist` — walks the doubly-linked `EPROCESS` list to enumerate processes. WHY: it gives you PID/PPID, start time, and thread count so you can spot oddly-named binaries or unexpected parents. Nuance: `pslist` relies on the linked list and can be evaded by DKOM unlinking; cross-check with `windows.psscan` (pool-tag scanning) and `windows.pstree` (parent/child hierarchy) to catch hidden or terminated processes. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.pslist
```bash
vol -f memory.raw windows.pslist | grep -i -E "lock|crypt|ransom|encrypt"
```
Expected: one or more matching PIDs if a ransomware-like process is present. Nuance: absence of a match does NOT clear the host — legitimate names are common attacker cover, so also run `windows.pstree` to inspect lineage.

3. `vol -f memory.raw windows.cmdline` — reads each process's `PEB.ProcessParameters` to reveal the full command line. WHY: command-line arguments frequently expose the encryptor's target path, key material flags, or a launch from `%TEMP%`/`%APPDATA%`. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.cmdline
```bash
vol -f memory.raw windows.cmdline
```
Expected: a table mapping PID to command line; ransomware often shows an executable launched from `%TEMP%` or `%APPDATA%`. Nuance: a blank/`N/A` command line can itself be suspicious (process hollowing or a paged-out PEB).

4. `vol -f memory.raw windows.netscan` — pool-tag scans for `_TCP_ENDPOINT`/`_UDP_ENDPOINT` structures to recover current and recently-closed sockets. WHY: it links a foreign IP/port to the owning PID so you can attribute a C2 callback to a process. Nuance: `netscan` recovers residual (even closed) connection objects, so entries may outlive the live connection — correlate timestamps with the capture time from step 1. Plugin reference: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.netscan
```bash
vol -f memory.raw windows.netscan | grep ESTABLISHED
```
Expected: rows with foreign IPs such as 203.0.113.10 tied to a suspicious PID (203.0.113.0/24 is a RFC 5737 documentation range, safe to use as an example).

5. Scan the raw memory with a YARA rule for ransom-note strings. WHY: string/byte signatures confirm a family and pin the byte offsets where note templates or config live. The `-s` flag prints the matching strings and their offsets (see https://yara.readthedocs.io/en/stable/commandline.html). Nuance: scanning a flat memory dump matches physical offsets; to attribute a hit to a process, use Volatility 3's `windows.vadyarascan`/`yarascan` plugins instead (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.vadyarascan).
```bash
yara -s ransom.yar memory.raw
```
Expected: rule name plus matched offsets/strings when the note text is found.

6. Carve indicators with bulk_extractor into an output directory. WHY: bulk_extractor runs feature-extraction scanners over the raw bytes without needing a filesystem or valid process structures, so it recovers IOCs even from unallocated/paged regions. It writes one feature file per scanner (e.g., `url.txt`, `email.txt`) plus histograms — see the manual at https://github.com/simsong/bulk_extractor. Nuance: `-o` must name a directory that does not already exist, or bulk_extractor will refuse to overwrite it.
```bash
bulk_extractor -o be_out memory.raw
cat be_out/url.txt | grep -i http | head
```
Expected: a populated `be_out/` directory; `url.txt` and `email.txt` contain carved indicators (each line prefixed with the byte offset where the feature was found).

## Hands-on exercise
Investigate the sample memory image in this module's `exercise/` directory.

- **Sample type:** a small benign/inert raw memory-like blob (`exercise/memory.raw`) — it is NOT a real infected RAM capture and contains NO live malware; it is a plain file seeded with harmless ransom-note strings and a fake C2 URL so the tools produce realistic hits with zero risk.
- **Safe origin / generation:** the file is generated locally with the reproducible command below (no network egress). It only contains ASCII strings and random padding.

Reproducible generator (creates the exact benign sample):
```bash
mkdir -p exercise
{
  head -c 4096 /dev/zero
  printf 'YOUR FILES HAVE BEEN ENCRYPTED! Contact evilmail@example.com to recover.\n'
  printf 'Payment portal: http://203.0.113.10/pay\n'
  printf 'LOCKBIT_TEST_MARKER ransom.note.decrypt\n'
  head -c 4096 /dev/urandom
} > exercise/memory.raw
sha256sum exercise/memory.raw
```

Tasks:
1. Use `yara` with the rule below to confirm the ransom-note marker.
2. Use `bulk_extractor` to carve the C2 URL and the contact email.

Provided YARA rule (`exercise/ransom.yar`):
```bash
cat > exercise/ransom.yar <<'EOF'
rule ransom_note_test
{
    strings:
        $a = "HAVE BEEN ENCRYPTED"
        $b = "LOCKBIT_TEST_MARKER"
    condition:
        any of them
}
EOF
```
(Rule syntax — `strings:`/`condition:` sections and the `any of them` set operator — follows the YARA writing-rules reference: https://yara.readthedocs.io/en/stable/writingrules.html)

## SOC analyst perspective
A defender treats a captured memory image as ground truth when disk logs may be tampered. In an incident, you ingest network alerts from Security Onion (Suricata/Zeek) that flag a suspicious outbound connection to 203.0.113.10, then pivot to the endpoint's RAM capture.

Concrete detection logic and pivots:
- **Network pivot:** Suricata alerts surface in Security Onion's Alerts interface; pivot from an alert into the corresponding Zeek `conn.log` record to get the 4-tuple, duration, and byte counts (Zeek log reference: https://docs.zeek.org/en/master/logs/conn.html; Security Onion analyst workflow: https://docs.securityonion.net/en/2.4/). Filter Elastic on `destination.ip: 203.0.113.10` to find every host that beaconed to the same infrastructure — this maps to **T1071** (Application Layer Protocol, https://attack.mitre.org/techniques/T1071/) and, if the C2 uses web protocols, **T1071.001** (Web Protocols, https://attack.mitre.org/techniques/T1071/001/).
- **Endpoint corroboration:** Volatility 3's `windows.netscan` recovers the owning PID for that foreign IP, and `windows.cmdline` shows the launching path. A binary running from `%TEMP%`/`%APPDATA%` is consistent with **T1204** (User Execution) and staging in **T1074** (Data Staged); mass file rewrites map to **T1486** (Data Encrypted for Impact, https://attack.mitre.org/techniques/T1486/).
- **Family confirmation:** YARA hits on ransom-note strings (via `yara` on the flat dump, or `windows.vadyarascan` for per-process attribution) confirm the family. Feed the confirmed strings/hashes back into Security Onion as new Suricata rules or Elastic detections for retroactive hunting across `conn.log`/`http.log`/`dns.log`.
- **IOC building:** bulk_extractor's `url.txt`/`email.txt` rapidly produce a carved indicator list to push into detection and threat-intel enrichment.

Detection nuance: because ransomware often encrypts fast, the strongest early SOC signals are behavioral — spikes in `conn.log`/`dns.log` to unfamiliar destinations, shadow-copy deletion (**T1490** Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/), and volume of file-modify events — rather than a single AV hit.

## Attacker perspective
An attacker deploying ransomware runs an encryptor from a temporary path, often injecting into or spawning from a legitimate process to blend in (**T1055** Process Injection, https://attack.mitre.org/techniques/T1055/; **T1036** Masquerading, https://attack.mitre.org/techniques/T1036/). They contact a C2 or payment portal and drop a ransom note file across directories (**T1486**, https://attack.mitre.org/techniques/T1486/).

Concrete TTPs and the artifacts they leave in RAM:
- **Defense evasion / anti-recovery:** deleting Volume Shadow Copies via `vssadmin delete shadows` or `wmic shadowcopy delete` (**T1490** Inhibit System Recovery, https://attack.mitre.org/techniques/T1490/). Even after the process exits, its command line and image path may persist in `EPROCESS`/PEB structures recoverable by `windows.psscan` and `windows.cmdline`.
- **Process injection / hollowing:** RWX private memory regions and unbacked executable pages in the VAD tree are recoverable with `windows.malfind` (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind), which surfaces injected code that never touched disk.
- **C2 and note templates:** live/residual sockets to the C2 (`windows.netscan`), plus the ransom-note template string and sometimes symmetric keys or config blobs still resident on the heap — carved by bulk_extractor or matched by YARA.
- **Evasion techniques and their limits:** attackers delete the on-disk binary and note post-encryption, unlink processes (DKOM), pack/obfuscate payloads (**T1027** Obfuscated Files or Information, https://attack.mitre.org/techniques/T1027/), and clear event logs (**T1070** Indicator Removal, https://attack.mitre.org/techniques/T1070/). These defeat many disk artifacts but the memory image still preserves pool-scannable process objects, unlinked strings, and socket structures — exactly what Volatility 3, YARA, and bulk_extractor recover.

## Answer key
- **YARA:** `rule ransom_note_test` matches on `$a` ("HAVE BEEN ENCRYPTED") and `$b` ("LOCKBIT_TEST_MARKER").
```bash
yara -s exercise/ransom.yar exercise/memory.raw
```
Expected: `ransom_note_test exercise/memory.raw` with matched offsets for both strings (the `-s` flag prints matched strings and offsets — https://yara.readthedocs.io/en/stable/commandline.html).

- **bulk_extractor URL + email:** the carved C2 URL is `http://203.0.113.10/pay` and the contact email is `evilmail@example.com`.
```bash
bulk_extractor -o exercise/be_out exercise/memory.raw
grep -i "203.0.113.10" exercise/be_out/url.txt
grep -i "evilmail@example.com" exercise/be_out/email.txt
```
Expected: both greps return the seeded indicators (the `email` and `url`/net scanners are enabled by default; see the bulk_extractor manual, https://github.com/simsong/bulk_extractor).

- **Sample sha256:** because the benign sample includes random padding, its digest varies per generation. Record the digest printed by the generator's `sha256sum exercise/memory.raw` as the authoritative value for your build. To create a fixed, reproducible digest, replace the two `head -c ... /dev/urandom`/`/dev/zero` lines with `head -c 8192 /dev/zero` (all-zero padding); that deterministic variant yields a stable sha256 you can pin in CI.

## MITRE ATT&CK & DFIR phase
- **T1486** Data Encrypted for Impact — the ransomware encryption behavior. https://attack.mitre.org/techniques/T1486/
- **T1071** Application Layer Protocol — C2/payment-portal communication observed via netscan. https://attack.mitre.org/techniques/T1071/
- **T1055** Process Injection — potential injected encryptor code in memory (see `windows.malfind`). https://attack.mitre.org/techniques/T1055/
- **T1027** Obfuscated Files or Information — packed/obfuscated payloads whose strings are recovered from RAM. https://attack.mitre.org/techniques/T1027/
- **T1036** Masquerading — legitimately-named binaries used as cover. https://attack.mitre.org/techniques/T1036/
- **T1490** Inhibit System Recovery — shadow-copy deletion commonly seen with ransomware. https://attack.mitre.org/techniques/T1490/
- **DFIR phases:** identification (triage the alert), examination/analysis (Volatility 3 + YARA + bulk_extractor on the image), and reporting (IOC list from carved indicators). The memory-forensics analysis workflow aligns with SANS FOR508 guidance (https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).

## Sources
Claim → source mapping (all URLs are official/authoritative):

- Volatility 3 invocation model, `--info`, symbol tables, and plugin behavior (`windows.info`, `pslist`, `psscan`, `pstree`, `cmdline`, `netscan`, `malfind`, `vadyarascan`):
  - Volatility 3 docs — https://volatility3.readthedocs.io/en/latest/
  - Basics / `--info` — https://volatility3.readthedocs.io/en/latest/basics.html
  - Symbol tables — https://volatility3.readthedocs.io/en/latest/symbol-tables.html
  - Windows plugins reference — https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html
  - Source — https://github.com/volatilityfoundation/volatility3
  - The Volatility Foundation — https://www.volatilityfoundation.org/
- YARA `--version`, `-s` flag, and rule syntax (`strings:`/`condition:`/`any of them`):
  - YARA command-line reference — https://yara.readthedocs.io/en/stable/commandline.html
  - YARA writing rules — https://yara.readthedocs.io/en/stable/writingrules.html
  - Source — https://github.com/VirusTotal/yara
  - Kali Tools (yara) — https://www.kali.org/tools/yara/
- bulk_extractor `-V`, `-o` behavior, and default `url`/`email` scanners:
  - Source & manual — https://github.com/simsong/bulk_extractor
- Tool availability on analyst distros:
  - REMnux tool listings — https://docs.remnux.org/discover-the-tools/
  - SANS SIFT Workstation — https://www.sans.org/tools/sift-workstation/
- Security Onion analyst workflow / Suricata / Zeek pivots and `conn.log`:
  - Security Onion docs — https://docs.securityonion.net/en/2.4/
  - Zeek conn.log reference — https://docs.zeek.org/en/master/logs/conn.html
- MITRE ATT&CK techniques cited:
  - T1486 — https://attack.mitre.org/techniques/T1486/
  - T1071 — https://attack.mitre.org/techniques/T1071/ ; T1071.001 — https://attack.mitre.org/techniques/T1071/001/
  - T1055 — https://attack.mitre.org/techniques/T1055/
  - T1027 — https://attack.mitre.org/techniques/T1027/
  - T1036 — https://attack.mitre.org/techniques/T1036/
  - T1070 — https://attack.mitre.org/techniques/T1070/
  - T1074 — https://attack.mitre.org/techniques/T1074/
  - T1204 — https://attack.mitre.org/techniques/T1204/
  - T1490 — https://attack.mitre.org/techniques/T1490/
- RFC 5737 (documentation IP ranges incl. 203.0.113.0/24) — https://datatracker.ietf.org/doc/html/rfc5737
- SANS FOR508 (IR/threat-hunting & memory forensics methodology) — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/

## Related modules
- [Memory forensics](../02-memory-forensics/README.md) -- shares bulk_extractor for carving IOCs from RAM captures.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- shares bulk_extractor and extends the Volatility 3 plugin workflow used here.
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- shares yara for signature-based hunting of C2 indicators.
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares bulk_extractor within a full host-triage pipeline.

<!-- cyberlab-enriched: v1 -->
