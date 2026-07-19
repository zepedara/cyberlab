# cyberlab — night_loop project design (golden-spec source)

Applies the LOOP_STANDARD doctrine: **I author sourced golden specs + a hard gate; the loop
transcribes, it does not derive.** The loop consumes the corpus below — it never re-researches it.

## Objective
Produce the complete build+training package for two cyber training VMs so operators can train on
the exact tools we hold:
- **LAB-LINUX** (Ubuntu 22.04): SIFT + REMnux + selected Kali tools.
- **LAB-WINDOWS** (Windows 10): FLARE-VM (136-pkg default profile).
- (LAB-SO / Security Onion = standalone reference only, not a training toolbag.)

## Corpus inputs (authoritative — the loop reads, never re-derives)
- `Cyber_Lab_VM_Build_Plan.md` — master ~600-tool deduped catalog + build recipes (already authored).
- `Cyber_Tools_Lab_Tracker.csv` — platform tracker.
- Per-distro source manifests already captured: `teamdfir/sift-saltstack`, `mandiant/flare-vm config.xml`,
  `docs.remnux.org`, `kali-linux-default`.

## ARMED scope → what the loop emits (5 categories)
| Scope tag | Deliverable per module | Gate |
|---|---|---|
| coverage | Ground-truth installed-tool manifest per VM (from live-dump cmds) | manifest non-empty, each tool has {name,pkg,category} |
| tooling | Provisioning automation (build-lab-*.sh/.ps1) fragments per tool group | script lints (bash -n / PSScriptAnalyzer), install cmd resolvable |
| curriculum | Per-tool/-group training module (see contract) | passes module contract below |
| samples | Legally-safe practice artifact for the exercise (pcap/mem/disk/doc stub) | artifact exists, hash recorded, license/safe-origin noted |
| validation | Answer key + command-check for each module | every command in module is syntactically valid; answer key present |

## Module taxonomy = the backlog (one lever per row)
Ordered by training value per effort. Grouped so a lever = one coherent tool group (not 600 singletons).

### LAB-LINUX
1. L-cov  — coverage: emit LAB-LINUX ground-truth manifest (dpkg + pip + salt) + reconcile vs catalog.
2. L-prov — tooling: build-lab-linux.sh (SIFT CLI → REMnux add-on → Kali apt cherry-pick), idempotent.
3. L-disk — curriculum+samples+validation: **Disk/Filesystem forensics** (TSK: fls/icat/mmls/fsstat, autopsy, testdisk/photorec).
4. L-mem  — **Memory forensics** (Volatility3 core plugins, bulk_extractor, aeskeyfind).
5. L-tl   — **Timeline** (Plaso/log2timeline → psort supertimeline; mactime bodyfile).
6. L-reg  — **Registry** (RegRipper + libregf; SAM/SYSTEM/SOFTWARE/NTUSER hives).
7. L-carve— **Carving** (foremost/scalpel/bulk_extractor signatures).
8. L-winart— **Windows artifact libs** (libyal: evtx/esedb/pff/vshadow/bde).
9. L-net  — **Network/PCAP** (Wireshark/tshark, ngrep, tcpflow, zeek if present).
10. L-mal — **Malware static triage on Linux** (YARA, capa, FLOSS, DIE, ssdeep, pefile, oletools).
11. L-deob— **Deobfuscation** (CyberChef, XORSearch/xortool, base64dump, Didier-Stevens suite).
12. L-doc — **Malicious documents** (oletools/oledump, pdfid/pdf-parser, XLMMacroDeobfuscator).
13. L-off — **Offensive/network (Kali subset)** (nmap, metasploit, burp, hydra/john/hashcat) — training-range only.

### LAB-WINDOWS (FLARE-VM)
14. W-cov — coverage: emit FLARE-VM manifest (choco list) + reconcile vs 136-pkg config.xml.
15. W-prov— tooling: install.ps1 wrapper + snapshot/network-isolation checklist.
16. W-disasm— **Static RE** (Ghidra, IDA Free, Cutter; capa/FLOSS; PE-bear/PEStudio).
17. W-debug— **Dynamic debugging** (x64dbg + ScyllaHide, WinDbg, TTD).
18. W-dotnet— **.NET RE** (dnSpyEx, ILSpy, de4dot).
19. W-dyn — **Behavioral/dynamic** (Sysinternals Procmon/Procexp/Autoruns, ProcDOT, Regshot, FakeNet-NG).
20. W-mem — **Process memory** (pe-sieve, HollowsHunter, ProcessDump).
21. W-shell— **Shellcode** (scdbg, BlobRunner, sclauncher).
22. W-doc — **Malicious Office/PDF on Windows** (PDFStreamDumper, Didier suite, OneNoteAnalyzer).
23. W-script— **Script malware** (js-beautify/deobfuscator, box-js-equivalents, PowerShell logging).

## Per-module GOLDEN-SPEC CONTRACT (curriculum lever must produce all)
A training module is a structured doc + assets with these required sections. This IS the gate.
1. **Title & VM** — module id, which VM, tool group.
2. **Tools covered** — each with {name, install source, one-line purpose} — must match the corpus catalog (numeric/name cross-check, per LOOP_STANDARD rule 7/9: sourced or it didn't happen).
3. **Learning objectives** — 3–5, measurable.
4. **Environment check** — the exact command(s) proving the tools are installed on the VM (from Part 5 dump cmds).
5. **Guided walkthrough** — ordered steps, each an exact runnable command + expected observable output.
6. **Hands-on exercise** — a task against the provided sample artifact.
7. **Sample artifact spec** — what sample the exercise needs (type, how it's safely sourced/generated, sha256). Malware samples: defanged/inert or reference-only; never live weaponized binaries; detonation only in no-egress snapshot.
8. **Answer key** — expected findings + the exact commands that produce them (held-out margin: 1 check the learner isn't shown).
9. **MITRE ATT&CK / DFIR-phase mapping** — where this fits (align w/ Security Onion Playbook scheme).
10. **Source citations** — file/URL for every factual claim (SANS SIFT manifest, REMnux docs, FLARE config.xml, tool docs).

## VALIDATION GATE (objective, non-self-certifying — the loop never self-certifies)
A module PASSES only if ALL hold (machine-checkable, no model judgment of its own work):
- G1 Structure: all 10 required sections present and non-empty.
- G2 Command validity: every command block parses (bash `bash -n` for sh; PSScriptAnalyzer/`[ScriptBlock]::Create` for ps1); no placeholder tokens (`<...>`, `TODO`, `FIXME`).
- G3 Corpus consistency: every tool named exists in the master catalog with matching category (cross-checked against Cyber_Lab_VM_Build_Plan.md); a tool not in the corpus fails (no hallucinated tools).
- G4 Sample integrity: declared sample artifact has a spec + sha256 + safe-origin note; if the artifact is generated, the generator command is included and safe.
- G5 Answer key present + held-out check runs.
- G6 Citations: ≥1 source per factual section; tool facts cite an authoritative manifest.
- Red on any → revert, re-spec, retry (≤4 attempts per LOOP_STANDARD); never accept red.

## Budget discipline (user directive: don't waste credits)
- Arm with a SMALL scope first (e.g. `curriculum` only) and ONE lever (L-disk) to prove the pipeline end-to-end on the Opus key before draining the full backlog.
- Watch `claude_usage.json` delta after the first iteration; set/confirm a daily token cap.
- Corpus is embedded so the model TRANSCRIBES from authoritative sources rather than researching from scratch → fewer, cheaper calls (LOOP_STANDARD rule 10).
```
