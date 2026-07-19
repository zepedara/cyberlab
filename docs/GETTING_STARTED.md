# Getting Started

This lab is two training VMs plus a set of hands-on modules. Build the VMs once, snapshot them, then
work the modules in order.

## 1. Build the VMs
Provisioning automation lives in [`../provisioning/`](../provisioning/).

- **LAB-LINUX** (Ubuntu 22.04 — SIFT + REMnux + selected Kali):
  run [`provisioning/build-lab-linux.sh`](../provisioning/build-lab-linux.sh) on a clean Ubuntu VM.
  Snapshot it as `clean-baseline` after the first successful run.
- **LAB-WINDOWS** (Windows 10 — FLARE-VM, Mandiant default profile):
  run [`provisioning/build-lab-windows.ps1`](../provisioning/build-lab-windows.ps1) elevated on a
  clean Win10 VM. **Snapshot before running.** Keep the network on only during install.

Networking discipline: analysis VMs stay isolated; only enable networking for installs or inside a
no-egress snapshot when a module calls for it.

## 2. Work the modules in order
Open [`../INDEX.md`](../INDEX.md) — it is the master table of contents (auto-generated). Work the
modules by `NN` order within each VM. Each module is self-contained and follows the same 12-section
format (see [`MODULE_TEMPLATE.md`](MODULE_TEMPLATE.md)):

1. Read the plain-language **Overview**.
2. Run the **Environment check** to confirm the tools are present.
3. Follow the **Guided walkthrough**, then do the **Hands-on exercise** against the sample in the
   module's `exercise/` dir.
4. Study the **SOC analyst** and **Attacker** perspectives — the same tool, defense then offense.
5. Check your work against the **Answer key**, and note the **MITRE ATT&CK & DFIR phase** mapping.

## 3. Contributing a module
Read [`STYLE_GUIDE.md`](STYLE_GUIDE.md), copy `MODULE_TEMPLATE.md` into
`modules/<vm>/NN-slug/README.md`, fill in all 12 sections, and make sure it passes the validator
before opening a PR. Regenerate `INDEX.md` (`python3 cyberlab_validate.py --build-index`) so coverage
stays in sync.
