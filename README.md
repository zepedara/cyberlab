# Cyber Tools Training Lab

Two training VMs so operators train on the exact tools we hold.

- **LAB-LINUX** (Ubuntu 22.04): SIFT + REMnux + selected Kali tools.
- **LAB-WINDOWS** (Windows 10): FLARE-VM (Mandiant 136-pkg default profile).

Built and continuously validated by the `cyberlab` night_loop project.
`catalog/` = authoritative ~600-tool deduped source of truth.
`modules/` = per-tool-group training modules (10-section contract, see MODULE_TEMPLATE.md).
`provisioning/` = reproducible VM build automation.
`samples/` = benign, legally-safe practice artifacts (no live malware).
