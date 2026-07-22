# 57 * Forensic acquisition & imaging -- LAB-LINUX

## Overview (plain language)
Forensic acquisition is the first step of any investigation: create a verifiable, bit-for-bit copy of the evidence so all later analysis runs against the copy, never the original. This module covers write-blocked imaging, hashing for integrity, the E01/raw formats, and read-only mounting.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| guymager | apt install guymager | GUI forensic imager: acquire disks to E01/AFF/raw with live hashing and verification |
| dc3dd | apt install dc3dd | dd variant (DoD DC3) with on-the-fly hashing, progress, and error logging |
| ewfacquire | apt install ewf-tools | Acquire a device into the EnCase Expert Witness (E01) format with metadata + hashing |
| ewfverify / ewfinfo | apt install ewf-tools | Verify stored image hashes and read E01 acquisition metadata |
| ewfmount | apt install ewf-tools | Mount an E01 image read-only as a raw device for downstream tools |

## Learning objectives
- Explain why bit-for-bit imaging + hashing preserves evidence integrity and chain of custody
- Acquire a device to E01 and raw with `ewfacquire` and `dc3dd`
- Verify an image's acquisition/verification hashes and detect tampering
- Mount an acquired image read-only for analysis without altering the original

## Environment check
Run `ewfacquire -V` and `dc3dd --version` to confirm the tools are present (preinstalled on SIFT). Work only against a test image or a device attached through a hardware/software write blocker (`blockdev --setro`).

## Guided walkthrough
1. Attach the source read-only (hardware write blocker, or `blockdev --setro /dev/sdX`).
2. Acquire to E01 with metadata + hashing: `ewfacquire -t /evidence/case01 -f encase6 -c deflate -S 2G /dev/sdX` (records MD5+SHA1, case fields).
3. Alternatively image to raw with `dc3dd if=/dev/sdX of=/evidence/case01.dd hash=sha256 log=/evidence/case01.log`.
4. Read the acquisition metadata: `ewfinfo /evidence/case01.E01`.
5. Verify integrity: `ewfverify /evidence/case01.E01` (recomputes and compares stored hashes).
6. Mount read-only for analysis: `ewfmount /evidence/case01.E01 /mnt/ewf` then examine `/mnt/ewf/ewf1` with `mmls`/`fls`.

## Hands-on exercise
Image the provided 200 MB test device to E01 with `ewfacquire`, record the SHA-256, then run `ewfverify`. Modify one byte of a raw copy and show that its hash no longer matches — demonstrating tamper detection.

## SOC analyst perspective
Acquisition integrity is what makes findings defensible. Analysts record acquisition + verification hashes in the case notes, image through write blockers, and keep the original evidence untouched so results are reproducible and admissible.

## Attacker perspective
Adversaries destroy or wipe evidence (disk wiping, log clearing, timestomping) to defeat acquisition. Proper imaging preserves slack/unallocated space where deleted artifacts and wiped-file remnants survive.

## Answer key
The E01 stores MD5/SHA1 (and optional SHA-256) computed at acquisition; `ewfverify` recomputes and compares them. A single changed byte changes the hash, proving the image was altered after acquisition.

## MITRE ATT&CK & DFIR phase
- **T1070** — Indicator Removal — imaging preserves slack/unallocated evidence adversaries try to delete
- **T1485** — Data Destruction — acquisition captures remnants before/after destructive actions
- **T1561.001** — Disk Content Wipe — forensic images preserve pre-wipe artifacts in unallocated space


### Essential Commands & Features

Below are **critical but undemonstrated** `dc3dd` commands and features for forensic acquisition, including split output, error logging, and pattern wiping—each with a concrete example and use case.

#### 1. **Split Output (`split=1G`)**
   - **When to use**: When acquiring large disks (e.g., >2TB) to avoid filesystem limitations or facilitate transfer/storage. Splits output into chunks of the specified size (e.g., 1GB).
   - **Example**:
     ```bash
     dc3dd if=/dev/sda of=evidence.dd split=1G hash=sha256
     ```
   - **MITRE ATT&CK**: [T1027.001 - Obfuscated Files or Information: Binary Padding](https://attack.mitre.org/techniques/T1027/001/) (adversaries may split data to evade detection; splitting aids analysis of fragmented files).

#### 2. **Error Redirection (`errlog=file.log`)**
   - **When to use**: To log read errors (e.g., bad sectors) separately for later analysis, ensuring the main output remains intact.
   - **Example**:
     ```bash
     dc3dd if=/dev/sdb of=image.dd errlog=errors.log conv=noerror,sync
     ```
   - **MITRE ATT&CK**: [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) (adversaries may corrupt logs; separate error logging preserves forensic integrity).

#### 3. **Pattern Wiping (`pat=`)**
   - **When to use**: To overwrite a drive with a known pattern (e.g., zeros or hex values) for secure erasure or testing write-blocker functionality.
   - **Example**:
     ```bash
     dc3dd if=/dev/zero of=/dev/sdc pat=00000000 tpat=00000000
     ```
   - **Use case**: Validating write-blockers or sanitizing media before reuse (e.g., per NIST SP 800-88).

**Authoritative Sources**:
- [dc3dd Official Documentation (SourceForge)](https://sourceforge.net/projects/dc3dd/files/dc3dd/)
- [SANS FOR500: Windows Forensic Analysis (Split/Error Handling)](https://www.sans.org/blog/for500-windows-forensic-analysis/)

### Detection Signatures & Reference Artifacts

Below are defensive detection signatures and reference artifacts for identifying benign forensic acquisition activities in a lab environment.

---

```yara
rule ForensicAcquisition_Tool_DD {
    meta:
        description = "Detects benign forensic acquisition tool (e.g., FTK Imager, dd) based on file signatures"
        author = "Defensive Training Lab"
        reference = "https://www.mitre.org/techniques/T1005"
        date = "2024-05-20"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Placeholder for benign sample
    strings:
        $magic_dd = { 64 64 20 69 66 3D } // "dd if=" signature
        $magic_ftk = "FTK Imager" nocase
        $magic_raw = "raw image file" nocase
        $magic_acq = "acquisition started" nocase
        $magic_log = "forensic log" nocase
        $magic_case = "case number" nocase
    condition:
        filesize < 50MB and (
            $magic_dd or
            $magic_ftk or
            $magic_raw or
            $magic_acq or
            $magic_log or
            $magic_case
        )
}
```

---

```yaml
title: Benign Forensic Acquisition Tool Usage
id: 1a2b3c4d-5e6f-7890-g1h2-i3j4k5l6m7n8
status: experimental
description: Detects benign forensic acquisition activities (e.g., dd, FTK Imager) in lab environments
author: Defensive Training Lab
date: 2024/05/20
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\dd.exe'
            - '\FTK Imager.exe'
            - '\ewfacquire.exe'
        CommandLine|contains:
            - 'if='
            - 'of='
            - 'bs='
            - 'acquisition'
    condition: selection
falsepositives:
    - Legitimate forensic tool usage in lab environments
level: informational
```

---

**Reference artifacts / IOCs**

| **Indicator Type**       | **Value**                                                                 | **Description**                                  |
|--------------------------|---------------------------------------------------------------------------|--------------------------------------------------|
| SHA256 Hash              | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`       | Benign `dd.exe` sample (placeholder)             |
| Filename                 | `FTK_Imager_Lab_Sample.E01`                                               | Benign FTK Imager output file                    |
| Host Artifact            | `C:\Lab\Forensic\acquisition.log`                                         | Log file generated by forensic tool              |
| Network Artifact         | `hxxp://192.0.2.100/lab/forensic_tools/`                                  | Documentation IP for lab tool repository         |
| Process Name             | `dd.exe` or `FTK Imager.exe`                                              | Benign forensic acquisition processes            |

**MITRE ATT&CK Techniques Covered:**
- **T1005**: Data from Local System
- **T1074.001**: Data Staged: Local Data Staging

**Authoritative Sources:**
1. [MITRE ATT&CK - T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/)
2. [Sigma Rule Creation Guide](https://sigmahq.io/docs/guide/rule_creation.html)

## Sources
- Forensic acquisition (E01/libewf): https://github.com/libyal/libewf/wiki
- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation
- dc3dd: https://sourceforge.net/projects/dc3dd/

## Related modules
- - 01-disk-forensics — analyze the acquired image
- - 22-sleuthkit-mastery — Sleuth Kit on mounted images
- https://attack.mitre.org/techniques/T1027/001/
- https://attack.mitre.org/techniques/T1562/001/
- https://sourceforge.net/projects/dc3dd/files/dc3dd/
- https://www.sans.org/blog/for500-windows-forensic-analysis/
- https://www.mitre.org/techniques/T1005"
- https://attack.mitre.org/techniques/T1005/
- https://sigmahq.io/docs/guide/rule_creation.html
