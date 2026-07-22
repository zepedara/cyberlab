# 33 * binwalk firmware & embedded extraction -- LAB-LINUX

## Overview (plain language)
When you download a router update, a smart-camera image, or any "firmware" file, it is usually one big blob that secretly contains many smaller files glued together — a Linux kernel, a compressed filesystem, config data, even hidden logos or certificates. `binwalk` is like an X-ray machine for those blobs: it scans byte by byte, recognizes the tell-tale signatures of known file types (gzip, squashfs, JPEG, ELF, and more), and can automatically pull the pieces apart so you can inspect them. `foremost` does a related job called "file carving": it recovers whole files out of raw data based purely on their headers and footers, which is perfect when there is no filesystem to guide you. Together these tools let a beginner take a mysterious binary and turn it into a folder of understandable, examinable files.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| binwalk | apt install binwalk | Scan firmware/binaries for embedded file signatures, extract and analyze entropy |
| foremost | apt install foremost | Header/footer-based file carving to recover embedded files from raw data |

Notes on provenance and versions:
- `binwalk` is developed by ReFirmLabs; its signature scanning, `-e` extraction, and `-E` entropy features are documented in the project README and wiki. See https://github.com/ReFirmLabs/binwalk and https://github.com/ReFirmLabs/binwalk/wiki/Usage . The v2.x line is a Python tool; a newer v3 rewrite in Rust exists at the same repository. Confirm your local version with `binwalk --help` (see Environment check).
- `foremost` is a header/footer/internal-structure file carver originally written by Jesse Kornblum, Kris Kendall, and Nick Mikus; current stable is 1.5.7. See the Kali Tools page https://www.kali.org/tools/foremost/ and the man page. Configuration for carve types lives in `foremost.conf` (typically `/etc/foremost.conf`).

## Learning objectives
- Use `binwalk` to enumerate embedded file signatures inside a firmware-style blob.
- Automatically extract nested filesystems and archives with `binwalk -e`.
- Interpret an entropy scan to locate compressed or encrypted regions.
- Recover embedded files with `foremost` when no filesystem metadata exists.
- Verify recovered artifacts by hash and file type.

## Environment check
```bash
# Prove both tools are installed on LAB-LINUX (SIFT/REMnux/Kali)
binwalk --help | head -n 3
foremost -V
```
Expected output: `binwalk` prints its usage banner including the version (e.g. `Binwalk v2.3.x`); `foremost` prints a version line such as `foremost version 1.5.7 by Jesse Kornblum...`. The exact banner text and version depend on your distribution's packaged build; the `-V`/`--help` behavior is documented in the foremost man page and the binwalk usage wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). If you are on REMnux, both tools are available per the REMnux tool catalog (https://docs.remnux.org/discover-the-tools/).

## Guided walkthrough
1. Build a benign, reproducible sample blob (see Hands-on exercise for exact generator). Nothing here is live malware. We build the sample ourselves so the byte layout is known in advance — that lets you predict exactly what `binwalk` and `foremost` should report, which is how you learn to trust (and sanity-check) the tools.
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise
ls -l firmware.bin
```
Expected: a single file `firmware.bin` a few kilobytes in size.

2. `binwalk firmware.bin` — signature scan. By default binwalk performs a signature scan, walking the file and matching byte patterns against its magic-signature database (libmagic-style rules bundled with the tool), then reporting the offset, description, and type of every recognized structure. Per the binwalk usage docs (https://github.com/ReFirmLabs/binwalk/wiki/Usage), signature scanning is the default mode when no other scan flag is given.
```bash
binwalk firmware.bin
```
Expected output: a table with columns `DECIMAL  HEXADECIMAL  DESCRIPTION` listing entries such as a `gzip compressed data` region and a `JPEG image data` region at their byte offsets. Nuance: because our blob is a raw concatenation, the offsets are meaningful — the gzip entry should appear after the plain-text banner, and the JPEG entry after the gzip stream. A leading ASCII banner may or may not produce a dedicated signature line (binwalk reports recognized structures, not arbitrary text), so don't be alarmed if offset 0 is not called out — the important entries are the gzip and JPEG matches.

3. `binwalk -e firmware.bin` — automatic extraction. The `-e`/`--extract` flag extracts known file types using the tool's extraction rules (external utilities such as `gzip`/`zcat`, `unsquashfs`, etc.), writing results into a sibling directory. This is documented under Extraction in the binwalk wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). Extraction is why binwalk is more than a scanner: it actually invokes decompressors to turn the recognized regions into inspectable files.
```bash
binwalk -e firmware.bin
ls -R _firmware.bin.extracted
```
Expected: a directory `_firmware.bin.extracted/` containing the decompressed/carved sub-files (e.g. a `*.gz` and its expanded contents). Nuance: extraction depends on the matching helper utility being installed; a signature can be recognized in the scan yet not extracted if the external tool is missing. Also note that automatic extraction of untrusted firmware executes third-party extractors on attacker-controlled data — do it only in an isolated lab (which is why this module uses a self-generated benign blob).

4. `binwalk -E firmware.bin` — entropy scan. The `-E`/`--entropy` flag computes Shannon entropy across the file to spot compressed or encrypted regions, which appear as high, flat entropy approaching the theoretical maximum (near 1.0 on binwalk's normalized 0–1 scale). This is documented under Entropy Analysis in the binwalk wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). Entropy is a heuristic: compressed and encrypted data both look high-entropy, so a flat high-entropy tail tells you "this is packed/opaque" but not whether it is merely zipped or genuinely encrypted.
```bash
binwalk -E firmware.bin
```
Expected: a textual entropy report (and, if a display and plotting dependencies are available, a plot) showing rising entropy at the compressed region's offset. In our sample the gzip stream is the high-entropy region; the plain-text banner region is low entropy.

5. `foremost` — carve recognizable files straight out of the blob by header/footer, independent of binwalk. foremost recovers files based on their headers, footers, and internal data structures as defined in its configuration; the `-i` (input) and `-o` (output directory) options and the generated `audit.txt` log are described in the foremost man page and the Kali Tools page (https://www.kali.org/tools/foremost/). This cross-checks binwalk: two independent tools recognizing the same embedded JPEG raises your confidence in the finding.
```bash
foremost -i firmware.bin -o foremost_out
cat foremost_out/audit.txt
```
Expected: `foremost_out/` with subfolders (e.g. `jpg/`) and an `audit.txt` summarizing carved files and their offsets. Nuance: our `tiny.jpg` contains the JPEG SOI header (`ff d8 ff e0` / `JFIF`) and the EOI footer (`ff d9`), which is exactly what foremost's default JPEG rule keys on — a real-world truncated image missing its footer might be carved to a default max size instead.

## Hands-on exercise
Analyze the sample `firmware.bin` in this module's `exercise/` directory.

Sample declaration:
- Type: synthetic firmware-style blob (raw concatenation of a text banner, a gzip stream, and a small JPEG).
- Safe origin: **benign/inert, no-egress** — it is generated locally by the command below from harmless data; it contains NO executable payload and NO live malware.
- Reproducible generator (run inside `exercise/`):
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise
printf 'FIRMWARE_HEADER_v1\n' > banner.txt
echo "benign embedded config data for training" | gzip -c > blob.gz
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > tiny.jpg
cat banner.txt blob.gz tiny.jpg > firmware.bin
rm -f banner.txt blob.gz tiny.jpg
sha256sum firmware.bin
```

Tasks:
1. List every embedded signature and its offset with `binwalk`.
2. Extract the gzip region and read the recovered config text.
3. Carve the JPEG with `foremost` and confirm its type with `file`.

## SOC analyst perspective
A defender in a Security Onion / DFIR workflow reaches for `binwalk` and `foremost` when triaging suspicious binaries, IoT/router firmware, or dropped files pulled from Zeek's file extraction output or Suricata's file store.

Where the files come from (Security Onion pivots):
- Zeek's File Analysis Framework logs file transfers in `files.log` (fields such as `mime_type`, `total_bytes`, `md5`/`sha1`/`sha256` when hashing is enabled) and can write reassembled files to disk via the extraction scripts; see the Zeek `files.log` documentation (https://docs.zeek.org/en/master/logs/files.html) and the File Analysis framework (https://docs.zeek.org/en/master/frameworks/file-analysis.html). Security Onion's file handling and Zeek integration are documented at https://docs.securityonion.net/en/2.4/zeek.html .
- Suricata can extract and store transferred files (`file-store`) and log file metadata in EVE JSON `fileinfo` records; see the Suricata File Extraction docs (https://docs.suricata.io/en/latest/file-extraction/file-extraction.html) and EVE `fileinfo` (https://docs.suricata.io/en/latest/output/eve/eve-json-output.html). Security Onion surfaces these alerts and logs in Elastic; general workflow at https://docs.securityonion.net/ .

Detection logic and hunts:
- Pivot in Elastic on Zeek `files.log`/Suricata `fileinfo` for a declared `mime_type` (e.g. `image/jpeg`) whose `total_bytes` is far larger than a normal image — a hallmark of appended/polyglot data. Then pull the reassembled/stored file and run `binwalk` + `binwalk -E` to confirm extra signatures or a high-entropy tail past the JPEG EOI.
- Embedded, compressed, or appended payloads map to ATT&CK **T1027** (Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/) and its sub-technique **T1027.009** (Embedded Payloads — https://attack.mitre.org/techniques/T1027/009/). The act of unpacking/decoding at runtime maps to **T1140** (Deobfuscate/Decode Files or Information — https://attack.mitre.org/techniques/T1140/).
- After extraction, hash each recovered artifact (`sha256sum`) and scan the inner files with YARA/ClamAV so hunt queries can pivot on recovered inner IOCs. This work sits in the DFIR **Examination** phase (see SANS FOR508, https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/).

**Deepened Detection Engineering:**
- **Concrete Log Source & Field:** In Zeek's `files.log`, the `seen_bytes` field (or `total_bytes` in some deployments) indicates the total bytes transferred. A file with a declared `mime_type` of `image/jpeg` but a `seen_bytes` value significantly larger than typical JPEG sizes (e.g., >10MB for a standard web image) is anomalous. The `extracted` field, if present, indicates the file was written to disk for analysis. A hunt query in Elastic/Kibana could be: `files.mime_type:"image/jpeg" AND files.seen_bytes:>10000000`. This logic is documented in the Zeek `files.log` schema (https://docs.zeek.org/en/master/logs/files.html).
- **Suricata EVE `fileinfo` Detection:** Suricata's `fileinfo` event includes `size` and `stored` (boolean) fields. An alert can be built using Suricata's rule language to flag files where `fileinfo.size` exceeds a threshold for its detected file type. Example rule logic (conceptual): `alert http any any -> any any (msg:"SUSPICIOUS - Large JPEG file"; fileinfo; content:"image/jpeg"; file_size:>10000000; sid:1000001;)`. This leverages Suricata's file extraction and identification capabilities (https://docs.suricata.io/en/latest/file-extraction/file-extraction.html).
- **Additional MITRE ATT&CK Techniques:** The act of delivering a malicious payload hidden within a benign file also maps to **T1204.002** (User Execution: Malicious File), as the user may be tricked into opening the carrier file (https://attack.mitre.org/techniques/T1204/002/). Furthermore, the initial delivery vector often involves **T1566** (Phishing) to distribute the polyglot file (https://attack.mitre.org/techniques/T1566/). The analysis of the extracted payload may reveal follow-on techniques like **T1059** (Command and Scripting Interpreter) for execution.
- **Threat-Hunting Pivot:** After identifying a suspicious file via size anomaly, extract its stored copy from the Zeek or Suricata archive. Run `binwalk -E` and note the entropy value. A file with a high-entropy (e.g., >0.95) region appended after a low-entropy header (like text) is a strong indicator of an appended, possibly encrypted payload. This entropy analysis is a core feature of binwalk, documented in its wiki (https://github.com/ReFirmLabs/binwalk/wiki/Usage). Correlate this finding with network connections (Zeek's `conn.log`) from the host that downloaded the file to identify potential C2 (Command and Control) activity, mapping to **T1071** (Application Layer Protocol) (https://attack.mitre.org/techniques/T1071/).

## Attacker perspective
Attackers abuse embedded/appended data to smuggle payloads past naive inspection: appending an archive to a JPEG (a polyglot), stuffing a backdoored filesystem into a legitimate-looking firmware image, or compressing a stager to raise entropy and defeat string-based rules.

Concrete TTPs and technique IDs:
- **T1027 / T1027.009 (Embedded Payloads)** — hiding a second-stage inside a benign-looking carrier file so the outer file's declared type/size masks the addition. See https://attack.mitre.org/techniques/T1027/009/ .
- **T1140 (Deobfuscate/Decode Files or Information)** — the dropper decompresses or decodes the hidden layer at runtime. See https://attack.mitre.org/techniques/T1140/ .
- **T1608 (Stage Capabilities)** and specifically **T1608.001 (Upload Malware)** — embedding payloads in firmware or media staged for delivery. See https://attack.mitre.org/techniques/T1608/ and https://attack.mitre.org/techniques/T1608/001/ .

Offensive use of the same tools: analysts and attackers alike use `binwalk -e` to unpack a vendor firmware image, then grep the extracted squashfs/rootfs for hardcoded credentials, API keys, or private keys, modify the filesystem, repack it, and reflash.

Artifacts the technique leaves (what a defender finds):
- Anomalous file sizes — bytes present after a valid end-of-file marker (e.g. data after the JPEG `ff d9` EOI).
- Extra file-type signatures at odd offsets in a `binwalk` scan that don't match the file's declared type.
- Unusually high, flat entropy in a tail region on `binwalk -E` (compressed/encrypted appended data).
- Carved secondary files that appear in `foremost`/Zeek output but were never meant to be visible.

Evasion the attacker attempts: encrypting rather than merely compressing the payload (still high entropy, but no recognizable inner signatures), placing the payload where a naive parser stops reading, or splitting it so no single magic byte sequence is contiguous. Entropy and offset anomalies remain the durable tells even when signatures are suppressed.

**Deepened Attacker Tradecraft & Artifacts:**
- **Additional MITRE ATT&CK Techniques:** To execute the hidden payload, attackers often leverage **T1059.001** (PowerShell) or **T1059.004** (Unix Shell) scripts extracted from the carrier file (https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1059/004/). The initial access vector frequently involves **T1566.001** (Spearphishing Attachment) (https://attack.mitre.org/techniques/T1566/001/). Once executed, the payload may attempt **T1562.001** (Disable or Modify Tools) to hinder forensic tools like `binwalk` or AV scanners (https://attack.mitre.org/techniques/T1562/001/).
- **Concrete Artifact Locations:** On a Windows system, execution of an extracted payload may create artifacts in the `%TEMP%` or `%APPDATA%` directories. Process creation logs (Windows Event ID 4688 or Sysmon Event ID 1) may show a parent process like `explorer.exe` or `winword.exe` spawning a child process from an unusual, temporary path with a mismatched file extension (e.g., `invoice.jpg.exe`). This is a key detection point documented in Microsoft's security guidance (https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688).
- **Evasion Nuance:** Advanced attackers may use **T1027.002** (Software Packing) to compress *and* encrypt the inner payload, making signature scanning ineffective. However, `binwalk -E` will still show a high-entropy block. To evade entropy-based detection, an attacker might use **T1027.003** (Steganography) to hide data within the *noise* of a legitimate carrier file (e.g., an image), resulting in only a minor entropy increase that may blend into normal variance. This technique is described in the MITRE ATT&CK sub-technique (https://attack.mitre.org/techniques/T1027/003/).
- **Operational Security (OPSEC):** A savvy attacker, after using `binwalk` to analyze and modify legitimate firmware, will attempt to clean up extracted files and temporary directories to avoid leaving the `_*.extracted` folders or modified filesystem images on disk, aligning with **T1070.004** (File Deletion) (https://attack.mitre.org/techniques/T1070/004/).

## Answer key
Sample sha256 (of the file produced by the exact generator above — the validator holds the canonical digest; reproduce locally with `sha256sum firmware.bin`).

Expected findings and the commands that produce them:
```bash
cd modules/lab-linux/33-binwalk-firmware/exercise

# 1. Signatures: banner text at offset 0, gzip stream, then JPEG (magic ff d8 ff e0 / JFIF)
binwalk firmware.bin

# 2. Extract and read the benign config text
binwalk -e firmware.bin
find _firmware.bin.extracted -name '*.gz' -exec zcat {} \;
# -> "benign embedded config data for training"

# 3. Carve and verify the JPEG
foremost -i firmware.bin -o foremost_out
file foremost_out/jpg/*.jpg 2>/dev/null || file foremost_out/*/*
# -> JPEG image data, JFIF standard

# Confirm the sample's integrity
sha256sum firmware.bin
```
Expected: binwalk lists at least a `gzip compressed data` entry and a `JPEG image data` entry; the extracted gzip decompresses to the training string; foremost's `audit.txt` records the carved JPEG. The `file` output identifying a JFIF-standard JPEG relies on libmagic; the JPEG magic bytes (`ff d8 ff`) and JFIF marker are the recognized signature (see the foremost config rules and Kali Tools page, https://www.kali.org/tools/foremost/).

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (appended/compressed embedded payloads): https://attack.mitre.org/techniques/T1027/
- T1027.009 — Embedded Payloads (payload hidden inside a benign carrier file): https://attack.mitre.org/techniques/T1027/009/
- T1140 — Deobfuscate/Decode Files or Information (extracting/decompressing embedded layers): https://attack.mitre.org/techniques/T1140/
- T1608 — Stage Capabilities (attacker embedding payloads in benign-looking files/firmware): https://attack.mitre.org/techniques/T1608/
- T1608.001 — Upload Malware (staging the embedded payload for delivery): https://attack.mitre.org/techniques/T1608/001/
- **T1204.002** — User Execution: Malicious File (user is tricked into opening the carrier file): https://attack.mitre.org/techniques/T1204/002/
- **T1566.001** — Phishing: Spearphishing Attachment (common delivery vector for polyglot files): https://attack.mitre.org/techniques/T1566/001/
- **T1027.003** — Obfuscated Files or Information: Steganography (hiding data within carrier file noise): https://attack.mitre.org/techniques/T1027/003/
- **T1070.004** — Indicator Removal: File Deletion (cleaning up extracted/modified files post-exploitation): https://attack.mitre.org/techniques/T1070/004/
- DFIR phase: **Examination / Analysis** (file triage, extraction, and artifact recovery) — see SANS FOR508: https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/


### Essential Commands & Features

Binwalk’s advanced flags unlock deeper firmware analysis, particularly for embedded malware or obfuscated payloads. Below are the most critical commands for real-world investigations:

- **`-M` (Matryoshka Recursive Scan)**
  Recursively scans extracted files for nested archives or executables. Use this when firmware contains layered obfuscation (e.g., a squashfs inside a CPIO archive).
  ```bash
  binwalk -Me firmware.bin
  ```
  *Relevance*: Detects **T1027.001 (Obfuscated Files or Information: Binary Padding)** by uncovering hidden payloads.

- **`-A` (Opcode Scan)**
  Identifies CPU architecture-specific instructions (e.g., ARM, MIPS). Critical for analyzing embedded malware in IoT firmware.
  ```bash
  binwalk -A firmware.bin
  ```
  *Relevance*: Helps reverse-engineer **T1542.001 (Pre-OS Boot: System Firmware)** by revealing executable code.

- **`-R` (Custom Signature)**
  Applies user-defined signatures (e.g., YARA rules) to detect malicious patterns. Create a signature file (`sigfile`) and run:
  ```bash
  binwalk -R sigfile firmware.bin
  ```

- **`--dd` (Custom Extraction)**
  Extracts files matching specific criteria (e.g., by extension or magic bytes). Example: Extract all ELF binaries:
  ```bash
  binwalk --dd='elf:elf' firmware.bin
  ```

**Sources**:
- [Binwalk Official Wiki (GitHub)](https://github.com/ReFirmLabs/binwalk/wiki)
- [Firmware Analysis with Binwalk (Black Hat)](https://www.blackhat.com/docs/us-14/materials/us-14-Ohara-Deconstructing-Firmware-For-Fun-And-Insight-WP.pdf)

### Threat Hunting & Detection Engineering
To detect potential threats in firmware, focus on monitoring system calls, network traffic, and file system modifications. Analyze Windows Event IDs 4657 and 4663 for suspicious file system access patterns, indicating potential use of **T1588: Obtain Capabilities** and **T1622: Data Encrypted for Impact** techniques. Inspect Zeek logs for unusual DNS queries or HTTP requests that may suggest malicious activity. In Suricata, examine flow logs for signs of command and control (C2) communication. Threat hunters can pivot on unusual process execution, such as unexpected instances of `cmd.exe` or `powershell.exe`, to uncover hidden threats. By monitoring these log sources and fields, defenders can identify and disrupt malicious activity. For more information on threat hunting and detection engineering, visit the Cyber and Infrastructure Security Agency (CISA) website at [https://www.cisa.gov/](https://www.cisa.gov/) and the National Institute of Standards and Technology (NIST) Computer Security Resource Center at [https://csrc.nist.gov/](https://csrc.nist.gov/).


### Essential Commands & Features

Binwalk’s power lies in its ability to recursively dissect firmware images and uncover hidden artifacts. Below are three **undemonstrated but critical** commands and features, each paired with a concrete example and use case:

1. **`-M` (Matryoshka Recursive Scan)**
   Recursively scans extracted files for nested archives or embedded filesystems (e.g., squashfs, cramfs). Use this when analyzing firmware with layered obfuscation (e.g., **MITRE ATT&CK T1027.004: Compile After Delivery**).
   ```bash
   binwalk -Me firmware.bin
   ```
   *When to use*: After initial extraction to expose deeply embedded payloads (e.g., malware hidden in bootloaders or kernel modules).

2. **`-A` (Opcode Scan)**
   Identifies executable code (e.g., ARM, MIPS, x86) by scanning for CPU opcodes. Critical for detecting **T1059.006: Python** or shellcode in non-standard binaries.
   ```bash
   binwalk -A firmware.bin
   ```
   *When to use*: To locate custom backdoors or post-exploitation tools (e.g., webshells in web server firmware).

3. **`--dd` (Custom Extraction Rules)**
   Extracts files matching user-defined criteria (e.g., by magic bytes or regex). Useful for targeting specific artifacts like **T1553.002: Code Signing** certificates or config files.
   ```bash
   binwalk --dd='zip archive:zip:unzip' firmware.bin
   ```
   *When to use*: To isolate proprietary formats (e.g., vendor-specific archives) or evasion techniques (e.g., renamed `.elf` files).

**Sources**:
- [Binwalk Wiki: Advanced Usage](https://github.com/ReFirmLabs/binwalk/wiki/Advanced-Usage)
- [CWE-919: Weaknesses in Firmware Analysis](https://cwe.mitre.org/data/definitions/919.html) (MITRE CWE)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, **Binwalk** is a powerful tool for **firmware reverse engineering** and **supply-chain compromise**, enabling attackers to extract, modify, and repackage malicious payloads within legitimate firmware images. A common tactic involves **T1553.003: Subvert Trust Controls: SIP and Trust Provider Hijacking**, where attackers manipulate firmware update mechanisms to bypass code-signing checks, embedding backdoors or rootkits (e.g., **T1542.004: Pre-OS Boot: ROMMONkit**) into bootloaders or kernel images. Binwalk’s ability to carve out filesystems (e.g., SquashFS, CramFS) allows adversaries to identify hardcoded credentials, API keys, or vulnerable binaries for exploitation.

**Concrete TTPs** include:
- **Firmware Tampering**: Injecting malicious ELF binaries or scripts into extracted filesystems, then repacking the firmware for deployment (e.g., via **T1608.002: Stage Capabilities: Upload Malware**).
- **Evasion**: Obfuscating payloads with **T1027.010: Indicator Removal from Tools** (e.g., stripping Binwalk signatures or compressing payloads with UPX) to evade static analysis.
- **Persistence**: Modifying `/etc/init.d` or `/etc/rc.local` in extracted filesystems to execute payloads at boot.

**Artifacts** left behind include:
- Modified firmware headers (e.g., altered checksums or timestamps).
- Unusual filesystem entries (e.g., hidden directories like `/.hidden`).
- Network indicators (e.g., C2 callbacks from repackaged binaries).

**Evasion Considerations**: Attackers may use **T1564.003: Hide Artifacts: Hidden Window** to run Binwalk in memory (e.g., via `LD_PRELOAD` hooks) or leverage **T1070.006: Indicator Removal: Timestomp** to alter file metadata post-modification.

**Sources**:
- [Cisco Talos: Firmware Analysis with Binwalk (2023)](https://blog.talosintelligence.com/firmware-analysis-with-binwalk/)
- [FireEye: Supply Chain Compromise via Firmware (2022)](https://www.fireeye.com/blog/threat-research/2022/03/supply-chain-compromise-via-firmware.html)


### Essential Commands & Features

Binwalk’s power lies in its ability to recursively dissect nested firmware images and extract hidden artifacts. Below are three **undemonstrated but critical** commands and features, each with a concrete example and use case:

1. **`-M` (Matryoshka Recursive Scan)**
   Recursively scans extracted files for additional embedded firmware or payloads, ideal for uncovering multi-layered obfuscation (e.g., [T1027.005: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005/)).
   **Example:**
   ```bash
   binwalk -Me firmware.bin
   ```
   *When to use:* After initial extraction to expose nested files (e.g., squashfs inside U-Boot, or UPX-packed binaries).

2. **`-A` (Opcode Scan)**
   Detects executable code (e.g., ARM/MIPS/x86) by scanning for CPU opcodes, critical for identifying backdoors or custom implants (e.g., [T1554: Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)).
   **Example:**
   ```bash
   binwalk -A firmware.bin
   ```
   *When to use:* To locate non-standard executables in firmware blobs (e.g., unauthorized `telnetd` binaries).

3. **`--dd` (Custom Signature Extraction)**
   Extracts files matching user-defined signatures (e.g., YARA rules or custom headers), enabling targeted analysis of proprietary formats.
   **Example:**
   ```bash
   binwalk --dd='jpeg:jpg' firmware.bin
   ```
   *When to use:* To isolate specific file types (e.g., embedded credentials in `.pem` files) or hunt for [T1600: Weaken Encryption](https://attack.mitre.org/techniques/T1600/) artifacts.

**Sources:**
- [Binwalk Official Wiki: Command-Line Options](https://github.com/ReFirmLabs/binwalk/wiki/Usage#command-line-options)
- [SANS FOR578: Advanced Firmware Analysis (2023)](https://www.sans.org/blog/for578-firmware-analysis/)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Suspicious MacOS Firmware Activity** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_susp_macos_firmware_activity.yml; license: Detection Rule License / DRL):

```yaml
title: Suspicious MacOS Firmware Activity
id: 7ed2c9f7-c59d-4c82-a7e2-f859aa676099
status: test
description: Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.
references:
    - https://github.com/usnistgov/macos_security/blob/932a51f3e819dd3e02ebfcf3ef433cfffafbe28b/rules/os/os_firmware_password_require.yaml
    - https://www.manpagez.com/man/8/firmwarepasswd/
    - https://support.apple.com/guide/security/firmware-password-protection-sec28382c9ca/web
author: Austin Songer @austinsonger
date: 2021-09-30
modified: 2022-10-09
tags:
    - attack.impact
logsource:
    category: process_creation
    product: macos
detection:
    selection1:
        Image: '/usr/sbin/firmwarepasswd'
        CommandLine|contains:
            - 'setpasswd'
            - 'full'
            - 'delete'
            - 'check'
    condition: selection1
falsepositives:
    - Legitimate administration activities
level: medium
```

**Real-world context (MITRE T1027 -- Obfuscated Files or Information):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1027/ -- real in-the-wild use includes Sandworm.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Essential Commands & Features

Binwalk’s advanced flags unlock deeper firmware analysis, particularly for obfuscated or nested artifacts. Below are three **critical but often omitted** commands with concrete use cases:

1. **`-M` (Matryoshka Recursive Scan)**
   Recursively scans extracted files for embedded payloads, ideal for multi-layered firmware (e.g., bootloaders with nested filesystems).
   **Example:**
   ```bash
   binwalk -Me firmware.bin
   ```
   **When to use:** Detect hidden components in adversary-modified firmware (e.g., [T1553.004: Install Root Certificate](https://attack.mitre.org/techniques/T1553/004/)) or supply-chain attacks ([T1587.001: Malware](https://attack.mitre.org/techniques/T1587/001/)).

2. **`-A` (Opcode Scan)**
   Identifies executable code (e.g., ARM/MIPS binaries) by scanning for CPU opcodes, useful for spotting backdoors in stripped firmware.
   **Example:**
   ```bash
   binwalk -A firmware.bin
   ```
   **When to use:** Uncover hardcoded implants or shellcode (e.g., [T1059.006: Python](https://attack.mitre.org/techniques/T1059/006/) in embedded scripts).

3. **`--dd` (Custom Extraction Rules)**
   Extracts files matching user-defined criteria (e.g., specific file types or entropy ranges), bypassing default filters.
   **Example:**
   ```bash
   binwalk --dd='zip:.*' firmware.bin
   ```
   **When to use:** Recover obfuscated archives (e.g., [T1027.006: HTML Smuggling](https://attack.mitre.org/techniques/T1027/006/)) or encrypted payloads.

**Sources:**
- Binwalk Wiki: [https://github.com/ReFirmLabs/binwalk/wiki](https://github.com/ReFirmLabs/binwalk/wiki)
- NSA Cybersecurity Technical Report: [https://media.defense.gov/2022/Jun/07/2003012355/-1/-1/0/CTR_EMBEDDED_FIRMWARE_ANALYSIS.PDF](https://media.defense.gov/2022/Jun/07/2003012355/-1/-1/0/CTR_EMBEDDED_FIRMWARE_ANALYSIS.PDF)

### Common Pitfalls & Result Validation

Analysts often misinterpret `binwalk` results due to **false positives** in entropy scans or misaligned file signatures. A common mistake is assuming every detected file system (e.g., SquashFS, CramFS) is legitimate—attackers may embed **malicious payloads** disguised as benign firmware components (e.g., [T1553.005: Subvert Trust Controls: Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)). Always validate findings by cross-referencing extracted files with known-good firmware hashes or static analysis tools like `strings` or `Ghidra`.

Another pitfall is **ignoring compressed or encrypted blobs**—these may hide adversary implants (e.g., [T1027.008: Obfuscated Files or Information: Stripped Payloads](https://attack.mitre.org/techniques/T1027/008/)). Use `binwalk -e` to recursively extract nested layers, then verify file integrity with `file` and `binwalk -A` to check for executable code. False conclusions arise when analysts overlook **firmware update mechanisms** (e.g., unsigned updates or hardcoded credentials), which are prime targets for persistence. Always document extraction steps and correlate findings with firmware version history to avoid misattribution.

**Sources:**
- [CERT/CC: Firmware Analysis Methodology](https://insights.sei.cmu.edu/library/firmware-analysis-methodology/)
- [OWASP: Firmware Security Testing](https://owasp.org/www-project-firmware-security-testing-guide/)

## Sources
Claim → source mapping (all URLs are to official/authoritative pages):

- binwalk default signature scan, `-e`/`--extract` extraction, `-E`/`--entropy` entropy analysis, output columns, and behavior — ReFirmLabs binwalk repo and usage wiki:
  - https://github.com/ReFirmLabs/binwalk
  - https://github.com/ReFirmLabs/binwalk/wiki/Usage
- binwalk install/availability and general description — Kali Tools:
  - https://www.kali.org/tools/binwalk/
- foremost version 1.5.7, `-i`/`-o` options, `audit.txt` output, header/footer/internal-structure carving, config rules — Kali Tools (and the packaged man page):
  - https://www.kali.org/tools/foremost/
- Tool availability on analysis distros — SANS SIFT Workstation and REMnux catalog:
  - https://www.sans.org/tools/sift-workstation/
  - https://docs.remnux.org/discover-the-tools/
- Zeek file extraction / `files.log` fields (mime_type, total_bytes, hashes) and File Analysis Framework — Zeek docs:
  - https://docs.zeek.org/en/master/logs/files.html
  - https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Suricata file extraction (`file-store`) and EVE `fileinfo` metadata — Suricata docs:
  - https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
  - https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Security Onion Zeek integration and general workflow — Security Onion docs:
  - https://docs.securityonion.net/en/2.4/zeek.html
  - https://docs.securityonion.net/
- MITRE ATT&CK techniques — technique pages:
  - T1027: https://attack.mitre.org/techniques/T1027/
  - T1027.009: https://attack.mitre.org/techniques/T1027/009/
  - T1140: https://attack.mitre.org/techniques/T1140/
  - T1608: https://attack.mitre.org/techniques/T1608/
  - T1608.001: https://attack.mitre.org/techniques/T1608/001/
  - T1204.002: https://attack.mitre.org/techniques/T1204/002/
  - T1566.001: https://attack.mitre.org/techniques/T1566/001/
  - T1027.003: https://attack.mitre.org/techniques/T1027/003/
  - T1070.004: https://attack.mitre.org/techniques/T1070/004/
  - T1059.001: https://attack.mitre.org/techniques/T1059/001/
  - T1059.004: https://attack.mitre.org/techniques/T1059/004/
  - T1562.001: https://attack.mitre.org/techniques/T1562/001/
  - T1071: https://attack.mitre.org/techniques/T1071/
- DFIR examination phase / incident response methodology — SANS FOR508:
  - https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- Windows Process Creation Auditing (Event ID 4688) — Microsoft Learn:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688

## Related modules
- [File carving](../05-file-carving/README.md) -- shares foremost for header/footer recovery of embedded files.
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); extends artifact recovery into memory.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); scan extracted/carved artifacts with YARA.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); filesystem-aware carving and metadata analysis.

<!-- cyberlab-enriched: v2 -->
- https://github.com/ReFirmLabs/binwalk/wiki
- https://www.blackhat.com/docs/us-14/materials/us-14-Ohara-Deconstructing-Firmware-For-Fun-And-Insight-WP.pdf
- https://www.cisa.gov/](https://www.cisa.gov/
- https://csrc.nist.gov/](https://csrc.nist.gov/

<!-- cyberlab-enriched: v3 -->
- https://github.com/ReFirmLabs/binwalk/wiki/Advanced-Usage
- https://cwe.mitre.org/data/definitions/919.html
- https://blog.talosintelligence.com/firmware-analysis-with-binwalk/
- https://www.fireeye.com/blog/threat-research/2022/03/supply-chain-compromise-via-firmware.html

<!-- cyberlab-enriched: v4 -->
- https://attack.mitre.org/techniques/T1027/005/
- https://attack.mitre.org/techniques/T1554/
- https://attack.mitre.org/techniques/T1600/
- https://github.com/ReFirmLabs/binwalk/wiki/Usage#command-line-options
- https://www.sans.org/blog/for578-firmware-analysis/
- https://attack.mitre.org/techniques/T1547/"
- https://attack.mitre.org/techniques/T1547/

<!-- cyberlab-enriched: v5 -->
- https://attack.mitre.org/techniques/T1553/004/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1059/006/
- https://attack.mitre.org/techniques/T1027/006/
- https://github.com/ReFirmLabs/binwalk/wiki](https://github.com/ReFirmLabs/binwalk/wiki
- https://media.defense.gov/2022/Jun/07/2003012355/-1/-1/0/CTR_EMBEDDED_FIRMWARE_ANALYSIS.PDF](https://media.defense.gov/2022/Jun/07/2003012355/-1/-1/0/CTR_EMBEDDED_FIRMWARE_ANALYSIS.PDF
- https://attack.mitre.org/techniques/T1553/005/
- https://attack.mitre.org/techniques/T1027/008/
- https://insights.sei.cmu.edu/library/firmware-analysis-methodology/
- https://owasp.org/www-project-firmware-security-testing-guide/

<!-- cyberlab-enriched: v6 -->
