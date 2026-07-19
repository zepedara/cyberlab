# Cyber Tools Training Lab

A hands-on, public training lab for digital forensics, incident response, and malware analysis.
Operators train on the **exact tools** the team holds, across two purpose-built VMs, with every
module teaching the same tool three ways: plain-language basics, then the **SOC analyst** (defense)
view, then the **attacker** (offense) view.

## The two VMs
- **LAB-LINUX** (Ubuntu 22.04): SIFT + REMnux + a selected Kali subset — disk/memory/timeline
  forensics, malware static triage, deobfuscation, document analysis, and a training-range offensive
  toolset.
- **LAB-WINDOWS** (Windows 10): FLARE-VM (Mandiant default profile) — native Windows reverse
  engineering, debugging, and dynamic/behavioral analysis.

(A standalone Security Onion grid is referenced for the SOC-analyst perspective but is not part of
the training toolbag.)

## How to build
Reproducible provisioning automation is in [`provisioning/`](provisioning/):
- [`build-lab-linux.sh`](provisioning/build-lab-linux.sh) — SIFT then REMnux add-on then Kali cherry-pick.
- [`build-lab-windows.ps1`](provisioning/build-lab-windows.ps1) — FLARE-VM installer wrapper.

See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) for the full build + snapshot workflow.

## How to use
- [`INDEX.md`](INDEX.md) is the master table of contents (auto-generated): per-VM module tables and
  a coverage matrix. **Start here** and work modules in `NN` order.
- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) walks through building the VMs and working a
  module end to end.

## Module format
Every module is `modules/lab-{linux,windows}/NN-slug/README.md` and follows one fixed 12-section
contract — Overview (plain language), Tools covered, Learning objectives, Environment check,
Guided walkthrough, Hands-on exercise, SOC analyst perspective, Attacker perspective, Answer key,
MITRE ATT&CK & DFIR phase, Sources. The contract is defined in
[`docs/MODULE_TEMPLATE.md`](docs/MODULE_TEMPLATE.md) and enforced by a pure-Python validator; the
naming and structure rules are in [`docs/STYLE_GUIDE.md`](docs/STYLE_GUIDE.md).

## Repository layout
- `catalog/` — the authoritative ~600-tool deduped catalog + build plan (source of truth for tools).
- `docs/` — the module template, style guide, and getting-started guide.
- `modules/lab-linux/`, `modules/lab-windows/` — numbered per-tool-group training modules.
- `provisioning/` — VM build automation.
- `samples/` — shared benign practice artifacts (per-module samples live in each module's `exercise/`).

## Safety
Training content only. **Samples are benign/inert** (synthetic, EICAR, or defanged) with a recorded
sha256 and safe-origin note — this repo never contains live or weaponized malware. Offensive
modules are for isolated training ranges only.
