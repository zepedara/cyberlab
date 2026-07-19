# NN · <Tool Group> — LAB-LINUX

<!--
CANONICAL MODULE CONTRACT (12 sections). Copy this file to
modules/lab-linux/NN-slug/README.md or modules/lab-windows/NN-slug/README.md and fill it in.

Rules enforced by cyberlab_validate.py (see docs/STYLE_GUIDE.md):
  * H1 title line MUST be '# NN · <Tool Group> — LAB-LINUX' or '... — LAB-WINDOWS'
    (NN = the zero-padded 2-digit order matching the folder name).
  * The 11 H2 sections below MUST appear with these EXACT titles, in THIS EXACT order, none empty.
  * Overview / SOC analyst perspective / Attacker perspective must each be >= 200 characters.
  * Every tool named in "Tools covered" MUST exist in ../../catalog/Cyber_Lab_VM_Build_Plan.md.
  * Every fenced command block must parse (bash -n / PowerShell) and contain no angle-bracket
    placeholders, TODO, or FIXME.
  * If a sample is used it lives in this module's exercise/ dir and is declared with a sha256 +
    safe-origin note (benign/inert only — NEVER live malware).
  * Sources must carry >= 1 authoritative URL/citation.
-->

## Overview (plain language)
What these tools are, in basic, jargon-free terms — explain it to someone new to DFIR. (>= 200 chars.)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| ExampleTool | apt install example | one-line purpose (tool MUST be in the master catalog) |

## Learning objectives
- (3–5, measurable)

## Environment check
```bash
# exact command(s) proving the tools are installed on the VM
exampletool --version
```

## Guided walkthrough
1. `exampletool ...` — what it does + expected observable output.
```bash
exampletool --help
```

## Hands-on exercise
Task against the sample artifact in this module's exercise/ dir. Declare the sample: type, how it is
safely sourced/generated (benign/inert, no-egress), and its sha256.

## SOC analyst perspective
How a defender uses this in detection / incident response — tie to Security Onion and MITRE ATT&CK.
(>= 200 chars.)

## Attacker perspective
How the tool/technique is used offensively and what artifacts it leaves behind for a defender to
find. (>= 200 chars.)

## Answer key
Expected findings + the exact commands that produce them (the held-out check is kept by the
validator, not shown to the learner). Include the sample sha256.

## MITRE ATT&CK & DFIR phase
- Technique IDs (e.g. T1027) and the DFIR phase (identification / examination / ...).

## Sources
- Authoritative citation per factual claim (SANS, REMnux docs, mandiant/flare-vm, kali.org/tools, MITRE), with URLs.
