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
1.  **Attach the source read-only.** A hardware write-blocker is the gold standard. In a lab, you can use a software write-blocker: `sudo blockdev --setro /dev/sdX`. This command sets the device to read-only mode at the kernel block device level, preventing accidental writes. Verify with `sudo blockdev --getro /dev/sdX` (should return `1`). [[SANS FOR508: Computer Forensic Investigations - Windows In-Depth]](https://www.sans.org/cyber-security-courses/computer-forensic-investigations-windows-in-depth/)
2.  **Acquire to E01 with metadata + hashing.** The `ewfacquire` command from the `libewf` (Expert Witness Format) toolkit creates a forensically sound container. The `-t` flag sets the base output name (without extension). The `-f encase6` specifies the EWF format version. The `-c deflate` enables compression to save space. The `-S 2G` splits the output into 2 GB segment files for portability. By default, it calculates and stores MD5 and SHA1 hashes. [[libewf (ewf-tools) GitHub Wiki]](https://github.com/libyal/libewf/wiki)
    ```bash
    sudo ewfacquire -t /evidence/case01 -f encase6 -c deflate -S 2G /dev/sdX
    ```
    You will be prompted for case metadata (e.g., examiner name, evidence number, description). Filling this in embeds the information into the `.E01` file header.
3.  **Alternatively, image to raw format with `dc3dd`.** This tool, developed by the DoD Cyber Crime Center (DC3), provides enhanced feedback and integrity features over classic `dd`. The `hash=sha256` option calculates a SHA-256 hash on-the-fly. The `log=` file records all output, including the final hash and any errors. [[dc3dd SourceForge Project Page]](https://sourceforge.net/projects/dc3dd/)
    ```bash
    sudo dc3dd if=/dev/sdX of=/evidence/case01.dd hash=sha256 log=/evidence/case01.log
    ```
4.  **Read the acquisition metadata.** Use `ewfinfo` to display the embedded case information, acquisition parameters, and stored hash values from the E01 file. This is crucial for chain-of-custody documentation.
    ```bash
    ewfinfo /evidence/case01.E01
    ```
5.  **Verify integrity.** The `ewfverify` command reads the entire E01 image, recalculates its hash(es), and compares them against the values stored during acquisition. Any mismatch indicates data corruption or tampering.
    ```bash
    ewfverify /evidence/case01.E01
    ```
6.  **Mount read-only for analysis.** The `ewfmount` command uses the FUSE (Filesystem in Userspace) driver to present an E01 container as a raw, read-only block device (`/mnt/ewf/ewf1`). This allows forensic tools like `mmls` (from The Sleuth Kit) to analyze the disk structure without extracting the entire image. [[The Sleuth Kit Wiki]](https://wiki.sleuthkit.org/index.php?title=Main_Page)
    ```bash
    sudo ewfmount /evidence/case01.E01 /mnt/ewf
    sudo mmls /mnt/ewf/ewf1
    ```

## Hands-on exercise
Image the provided 200 MB test device to E01 with `ewfacquire`, record the SHA-256, then run `ewfverify`. Modify one byte of a raw copy and show that its hash no longer matches — demonstrating tamper detection.

## SOC analyst perspective
Acquisition integrity is what makes findings defensible. Analysts record acquisition + verification hashes in the case notes, image through write blockers, and keep the original evidence untouched so results are reproducible and admissible. From a detection and hunting standpoint, the *absence* of reliable forensic images can be an indicator of adversary success. Adversaries employing **T1070.004 (File Deletion)** and **T1485 (Data Destruction)** aim to destroy evidence before it can be acquired. Detection engineering should focus on identifying pre-acquisition destructive actions. Monitor for mass file deletion events (Windows Event ID 4663 with specific access masks, or Sysmon Event ID 23) targeting system or log directories. In Security Onion, a Zeek `files.log` entry showing a high volume of `fuid` deletions from a single host in a short time could be a pivot point. Furthermore, the use of wiping utilities like `sdelete` or `shred` often leaves distinct command-line artifacts (e.g., `shred -fuz /dev/sdX`) that can be caught by endpoint detection and response (EDR) command-line logging. A failed acquisition due to disk encryption or physical damage should trigger an investigation into potential **T1562.001 (Disable or Modify Tools)** or **T1490 (Inhibit System Recovery)**.

## Attacker perspective
Adversaries destroy or wipe evidence (disk wiping, log clearing, timestomping) to defeat acquisition. Proper imaging preserves slack/unallocated space where deleted artifacts and wiped-file remnants survive. A sophisticated attacker understands forensic imaging and will attempt to subvert it. Techniques include:
*   **T1070.006 (Timestomp):** Modifying timestamps on key files (`touch -t`, `SetFileTime`) to disrupt timeline analysis of the acquired image.
*   **T1561.001 (Disk Content Wipe):** Using tools like `dd if=/dev/zero of=/dev/sdX` or `cipher /w:C:` to overwrite data, targeting unallocated space and file slack to erase residual evidence. [[MITRE ATT&CK T1561.001]](https://attack.mitre.org/techniques/T1561/001/)
*   **Anti-forensic live memory:** Deploying kernel-mode rootkits or using direct kernel object manipulation (DKOM) to hide processes and drivers from a live memory acquisition tool like `ftkimager` or `WinPmem`. This aligns with **T1564 (Hide Artifacts)**.
*   **Encryption:** Enabling full-disk encryption (e.g., BitLocker, LUKS) after compromise to render a powered-off disk image unreadable without the key, complicating the **T1005 (Data from Local System)** collection phase for defenders.

The attacker's goal is to increase the cost and uncertainty of analysis, making the forensic image either impossible to obtain or lacking in probative value.

## Answer key
The E01 stores MD5/SHA1 (and optional SHA-256) computed at acquisition; `ewfverify` recomputes and compares them. A single changed byte changes the hash, proving the image was altered after acquisition.

## MITRE ATT&CK & DFIR phase
- **T1070 (Indicator Removal)** — Imaging preserves slack/unallocated evidence adversaries try to delete. Sub-technique **T1070.004 (File Deletion)** is directly countered by forensic imaging of unallocated space.
- **T1485 (Data Destruction)** — Acquisition captures remnants before/after destructive actions.
- **T1561.001 (Disk Content Wipe)** — Forensic images preserve pre-wipe artifacts in unallocated space and file slack.
- **T1005 (Data from Local System)** — The forensic image is the primary source for this technique, containing all local data for analysis.
- **T1490 (Inhibit System Recovery)** — Adversaries may destroy volume shadow copies or backup catalogs; a timely forensic image preserves the system state before such inhibition completes.

## Sources
- Forensic acquisition (E01/libewf): https://github.com/libyal/libewf/wiki
- SANS SIFT Workstation: https://www.sans.org/tools/sift-workstation
- dc3dd: https://sourceforge.net/projects/dc3dd/
- MITRE ATT&CK Technique T1561.001: Disk Content Wipe: https://attack.mitre.org/techniques/T1561/001/
- The Sleuth Kit (TSK): https://wiki.sleuthkit.org/index.php?title=Main_Page
- SANS FOR508: Computer Forensic Investigations - Windows In-Depth (Write Blockers): https://www.sans.org/cyber-security-courses/computer-forensic-investigations-windows-in-depth/

## Related modules
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) — same learning path (Scenarios)
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) — same learning path (Scenarios)
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) — same learning path (Scenarios)
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) — same learning path (Scenarios)

<!-- cyberlab-enriched: v6 -->
