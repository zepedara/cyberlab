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
Expected output: `vol` prints Volatility 3 usage/banner; `bulk_extractor -V` prints a version like `bulk_extractor 2.x.x`; `aeskeyfind` and `rsakeyfind` print their usage lines because they were invoked with no input argument.

## Guided walkthrough
1. `vol -f <image> windows.info` — confirms Volatility can read the dump and reports OS/build. Here we run the help to see available plugins first.
```bash
vol -h | grep -i -E "pslist|netscan|windows.info" | head -n 10
```
Expected: plugin names such as `windows.pslist`, `windows.netscan`, `windows.info` are listed.

2. Enumerate processes from the sample image (see Hands-on exercise for the sample path).
```bash
cd exercise
vol -f sample.mem windows.pslist | head -n 20
```
Expected: a table of PID, PPID, ImageFileName, and creation times for processes captured in RAM.

3. Sweep the raw dump for human-readable features with bulk_extractor.
```bash
cd exercise
mkdir -p be_out
bulk_extractor -o be_out sample.mem
ls be_out
cat be_out/url.txt | head -n 10
```
Expected: `be_out/` contains feature files (`url.txt`, `email.txt`, `domain.txt`, etc.); `url.txt` lists offsets and recovered URLs.

4. Search memory for cryptographic key material.
```bash
cd exercise
aeskeyfind sample.mem
rsakeyfind sample.mem
```
Expected: `aeskeyfind` prints any 128/256-bit AES key schedules found (or "No keys found"); `rsakeyfind` prints candidate RSA keys/certificates (or none).

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
In a SOC, memory forensics is the go-to when disk and log evidence look clean but a host is still behaving oddly — the classic sign of fileless or in-memory malware. An analyst pulls a RAM image from a suspect endpoint, runs `vol windows.pslist`/`windows.malfind`/`windows.netscan` to spot hidden processes, injected code, and hidden C2 sockets, then runs bulk_extractor to pull URLs, domains, and credentials that alerts referenced. Findings feed directly back into Security Onion: recovered C2 domains and IPs become Suricata/Zeek IOC hunts and pivot points across all monitored hosts, letting the team confirm scope. Recovered AES/RSA keys via aeskeyfind/rsakeyfind can decrypt captured traffic or ransomware payloads. This ties to ATT&CK T1055 (Process Injection) and T1620 (Reflective Loading) during the DFIR examination phase.

## Attacker perspective
Attackers deliberately avoid touching disk to evade EDR and file-based detection — living-off-the-land, process injection (T1055), reflective DLL loading (T1620), and encrypted C2 all keep the malicious logic in RAM. From the attacker's viewpoint, memory is their hiding place, but it is also the very thing these tools expose: injected regions, unlinked processes, and network sockets remain visible to Volatility even when the running OS is lied to. Encryption keys used for C2 or ransomware, plaintext credentials, and decrypted config blobs sit in memory in recoverable form, which aeskeyfind/rsakeyfind and bulk_extractor harvest. The artifacts left for defenders include anomalous private memory, orphaned handles, decrypted strings, and key schedules that never appear on disk — a strong reason attackers try to force reboots or clear RAM.

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
Expected: `url.txt` shows `http://benign.lab.local/beacon` with a byte offset; `email.txt` shows `analyst@lab.local`.

2. Recover the planted AES key:
```bash
cd exercise
aeskeyfind sample.mem
```
Expected: aeskeyfind reports at least one 256-bit AES key (hex) with the offset where the key schedule was located.

3. (Optional) confirm no RSA keys are planted:
```bash
cd exercise
rsakeyfind sample.mem
```
Expected: rsakeyfind reports no RSA private keys for this synthetic sample.

## MITRE ATT&CK & DFIR phase
- **T1055 – Process Injection** — detected via `vol windows.malfind`/`windows.pslist`.
- **T1620 – Reflective Code Loading** — in-memory-only code surfaced by Volatility.
- **T1573 – Encrypted Channel** — recovered keys (aeskeyfind/rsakeyfind) enable decryption.
- **T1005 – Data from Local System** — feature carving (bulk_extractor) of in-memory data.
- **DFIR phase:** Collection (RAM capture) → **Examination / Analysis** (this module's focus) → Reporting.

## Sources
- Volatility 3 documentation — https://volatility3.readthedocs.io/
- SANS Memory Forensics (FOR508 / cheat sheets) — https://www.sans.org/posters/memory-forensics-cheat-sheet/
- REMnux tools (Memory) — https://docs.remnux.org/discover-the-tools/investigate+memory
- bulk_extractor (Digital Corpora / project) — https://github.com/simsong/bulk_extractor
- aeskeyfind / rsakeyfind (citp / Princeton "Lest We Remember") — https://citp.princeton.edu/our-work/memory/
- Kali Tools — volatility3 — https://www.kali.org/tools/volatility3/
- Kali Tools — bulk-extractor — https://www.kali.org/tools/bulk-extractor/
- MITRE ATT&CK T1055 — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1620 — https://attack.mitre.org/techniques/T1620/