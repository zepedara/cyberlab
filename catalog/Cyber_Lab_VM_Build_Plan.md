# Cyber Tools Lab — Master Catalog & Unified Lab VM Build Plan

**Purpose:** Enumerate every tool across the team's known OSs/VMs and design a training "Lab VM" (DFIR-lab style) so operators can train on the exact tools we have.

**Sources of truth (authoritative, not guesses):**
- Kali → `kali-linux-default` metapackage / kali.org/tools
- SIFT → `teamdfir/sift-saltstack` package manifest / SANS
- FLARE-VM → `mandiant/flare-vm config.xml` (136 pkgs)
- REMnux → docs.remnux.org "Discover the Tools"
- Security Onion 2.4.190 → team-provided component list

---

## PART 1 — THE VERDICT (single-VM feasibility)

**You cannot put all of these on one VM**, because they are different operating systems that do not co-install:

| Platform | Base OS | Nature | Merge verdict |
|---|---|---|---|
| SIFT | Ubuntu | Toolbag (apt/pip) | ✅ Merge into Linux Analyst VM |
| REMnux | Ubuntu | Toolbag (apt/pip/salt) | ✅ Merge into Linux Analyst VM (officially supported alongside SIFT) |
| Kali | Debian | Toolbag (apt) | ⚠️ Merge *tools* selectively via apt; not the whole distro |
| FLARE-VM | **Windows 10/11** | Toolbag (Chocolatey) | ❌ Windows-only — separate Windows Analyst VM |
| Security Onion | Oracle Linux 9 | **Server grid** (Docker/Salt) | ❌ Dedicated appliance — never merge |
| Splunk / RITA / Velociraptor / FireEye HX | app/agent | Applications | Layer onto a VM as needed, not a distro to merge |

**Realistic target = 3 VMs, not 1:**

1. **LAB-LINUX** (Ubuntu 22.04) — SIFT + REMnux + selected Kali/forensics tools. *This is the "single VM" that genuinely works and covers the most ground.*
2. **LAB-WINDOWS** (Windows 10) — FLARE-VM. The Windows-native RE/malware/debugging set that legally and technically cannot live on Linux.
3. **LAB-SO** (optional) — Security Onion, standalone, only if you want the blue-team/detection grid in the lab. It is a monitoring platform, not a training toolbag.

> The DFIR lab you built before is the model: **LAB-LINUX is the analog** — one Ubuntu box carrying the union of the Linux DFIR/RE toolsets, snapshotted to a clean baseline.

---

## PART 2 — THE BUILD

### VM 2.1 — LAB-LINUX (primary training VM)

**Base:** Ubuntu 22.04 LTS Desktop, 4 vCPU / 8–12 GB RAM / 120 GB disk, VirtualBox or VMware.

**Fastest path — layer the official installers onto ONE Ubuntu box (this is a supported combo):**
```bash
# 1) SIFT (SANS) — installs the full DFIR toolset
wget https://raw.githubusercontent.com/teamdfir/sift-cli/master/sift-latest.pubkey
# install the sift-cli, then:
sudo sift install

# 2) REMnux — malware-analysis toolset, layers cleanly on top of SIFT
wget https://REMnux.org/remnux-cli
# verify + chmod, then:
sudo remnux install --mode=addon      # add-on mode = install onto existing Ubuntu w/ SIFT

# 3) Kali forensics/offensive tools you want, via apt (add Kali repo pinned, OR cherry-pick from Ubuntu universe)
sudo apt install -y sleuthkit autopsy volatility3 bulk-extractor binwalk foremost \
  scalpel yara radare2 wireshark tshark nmap netcat-openbsd hydra john hashcat \
   ettercap-graphical exiftool clamav ssdeep
```
- SIFT + REMnux add-on mode is the SANS-blessed way to get both on one host.
- For Kali *offensive* tools (metasploit, burpsuite, etc.), cherry-pick via apt rather than adding the whole Kali repo, to avoid dependency churn on Ubuntu. If you want the full Kali arsenal, keep Kali as its own VM instead.

**Snapshot** `LAB-LINUX @ clean-baseline` immediately after install so trainees can roll back.

### VM 2.2 — LAB-WINDOWS (FLARE-VM)

**Base:** Windows 10 22H2, 4 vCPU / 8 GB / 80 GB, **VM only, snapshot before install.**
```powershell
# From an elevated PowerShell on a clean Win10 VM (network on during install):
(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',"$env:USERPROFILE\Desktop\install.ps1")
Unblock-File .\install.ps1
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
.\install.ps1        # installs the 136-package default profile via Chocolatey
```
- REMnux can drive x64dbg on this VM remotely (see REMnux "x64dbg Automate MCP") — pairs the two lab VMs.
- After install: `choco list` to capture the real installed set for the tracker.

### Networking discipline (same as your DFIR lab)
- **Host-only lab network**; NAT only on demand for updates. Malware VMs = **no egress**.
- FakeNet-NG / INetSim (both present in FLARE + REMnux) simulate internet for detonation.
- Snapshot every VM at "clean baseline."

---

## PART 3 — MASTER TOOL INVENTORY (by platform → category)

> Full per-tool detail lives in the four source catalogs. This is the consolidated index. Tools marked ⊕ appear on 2+ distros (dedup candidates).

### 3.1 LINUX ANALYST STACK (what LAB-LINUX will contain)

**SIFT — Disk/Filesystem:** Sleuth Kit ⊕, Autopsy ⊕, testdisk, photorec, extundelete, ntfs-3g, exfat, vmfs-tools, disktype, kpartx, libfsapfs, safecopy.
**SIFT — Memory:** Volatility 2 ⊕, Volatility 3 ⊕, Rekall, aeskeyfind ⊕, rsakeyfind ⊕.
**SIFT — Timeline:** Plaso/log2timeline, dfvfs, mactime.
**SIFT — Registry:** RegRipper, libregf-tools, Parse::Win32Registry.
**SIFT — Carving:** bulk_extractor ⊕, foremost ⊕, scalpel ⊕, tcpxtract ⊕.
**SIFT — Windows artifact libs (libyal):** libewf, libevt, libevtx, libesedb, libpff, libolecf, libmsiecf, libplist, libvshadow, libbde, libfvde, libvmdk (+ python3 bindings).
**SIFT — Network/PCAP:** Wireshark ⊕, tshark ⊕, ngrep ⊕, nfdump, tcpflow ⊕, tcpick ⊕, tcpreplay ⊕, tcptrace, ssldump, dsniff ⊕, ettercap ⊕, p0f ⊕, arp-scan ⊕, nbtscan ⊕, netcat ⊕, socat, nikto ⊕, hydra ⊕.
**SIFT — Malware/AV/RE:** ClamAV ⊕, YARA ⊕, radare2 ⊕, pev ⊕, pefile ⊕, upx ⊕, ssdeep ⊕, outguess, cabextract ⊕, ent.
**SIFT — Password:** ophcrack ⊕, samdump2, cmospwd, ccrypt.
**SIFT — Imaging/Mount:** dc3dd ⊕, dcfldd, ddrescue, afflib-tools, xmount, imagemounter, qemu-utils, dislocker, cryptsetup, nbd-client, avfs, cifs-utils.
**SIFT — String/Search/Hex:** lightgrep, silversearcher-ag, grepcidr, hexedit, ghex, bless, vbindiff ⊕, hashdeep/md5deep ⊕.
**SIFT — Platform:** Docker ⊕, PowerShell ⊕, Wine ⊕, aws-cli, android platform-tools, ipython ⊕, jq, graphviz.

**REMnux — Static properties:** TrID, Magika ⊕, Detect-It-Easy ⊕, ExifTool ⊕, DroidLysis, msitools, Name-That-Hash, HashID, signsrch, ssdeep ⊕, Hachoir, LIEF, Malcat Lite, YARA-Forge rules.
**REMnux — PE:** Manalyze, PEframe, pefile ⊕, PE Tree, pedump, pev ⊕, PortEx, debloat, readpe, pecheck.
**REMnux — Deobfuscation (large set):** CyberChef ⊕, Malchive, CS Config Extractor, xortool, DC3-MWCP, Chepy, Balbuzard, FLOSS ⊕, XORSearch/XORStrings, base64dump, 1768.py, the full Didier-Stevens XOR/decode suite.
**REMnux — Static code:** Ghidra ⊕, Cutter ⊕, Qiling, Vivisect, objdump, radare2 ⊕, Speakeasy, binee, mbcscan, capa ⊕.
**REMnux — Python/Java/.NET/Android RE:** Decompyle++, pyinstxtractor, uncompyle6 ⊕, cfr, JD-GUI ⊕, Procyon, de4dot ⊕, ILSpy ⊕, JADX, apktool ⊕, androguard, baksmali, dex2jar ⊕, APKiD.
**REMnux — Dynamic/Shellcode:** Frida, Wine ⊕, scdbg ⊕, runsc, Speakeasy, Qiling, libemu, GDB ⊕, edb, ltrace ⊕, strace ⊕.
**REMnux — JavaScript:** box-js ⊕, JStillery, SpiderMonkey, Rhino, Webcrack, js_unshroud, JS Beautifier ⊕.
**REMnux — Network:** Burp Suite ⊕, NetworkMiner, PolarProxy, mitmproxy ⊕, tshark ⊕, tcpdump ⊕, ngrep ⊕, thug, tor, INetSim ⊕, FakeNet-NG ⊕, fakedns, fakemail.
**REMnux — Documents:** peepdf-3, pdfid, pdf-parser, Origamindee, oletools ⊕, oledump, pcodedmp, pcode2code, EvilClippy, XLMMacroDeobfuscator, olefile, rtfdump, msoffcrypto-tool, msg-extractor, emldump.
**REMnux — Memory:** Volatility ⊕, AESKeyFinder ⊕, RSAKeyFinder ⊕, bulk_extractor ⊕.
**REMnux — Data/IOC:** dissect, malwoverview, virustotal-search/submit, nsrllookup, ioc_parser, YARA-X, time-decode, DeXRAY.

**Kali (selected for lab) — Offensive backbone:** nmap ⊕, metasploit-framework, burpsuite ⊕, zaproxy, sqlmap, wpscan, gobuster/ffuf/feroxbuster, nikto ⊕, hydra ⊕, john ⊕, hashcat, aircrack-ng ⊕, wireshark ⊕, ettercap ⊕, bettercap, responder, mimikatz, crackmapexec/netexec, impacket, evil-winrm, setoolkit, beef-xss, ghidra ⊕, radare2 ⊕, gdb ⊕, apktool ⊕.
**Kali — Forensics (overlaps SIFT/REMnux):** autopsy ⊕, sleuthkit ⊕, volatility3 ⊕, bulk-extractor ⊕, binwalk ⊕, foremost ⊕, scalpel ⊕, guymager, exiftool ⊕, chkrootkit, rkhunter.

### 3.2 WINDOWS ANALYST STACK (LAB-WINDOWS / FLARE-VM, 136 pkgs)

**Disassemblers/Decompilers:** Ghidra ⊕, IDA Free, Binary Ninja, Cutter ⊕ (+ 12 IDA plugins: capa, diaphora, flare-emu, hashdb, hrtng, xrefer…).
**Debuggers:** x64dbg (+ScyllaHide, dbgchild, ollydumpex, x64dbgpy), WinDbg, TTD.
**.NET:** dnSpyEx, ILSpy ⊕, de4dot-cex ⊕, net-reactor-slayer, dnlib, dotdumper, extreme_dumper, garbageman, codetrack.
**Python/Java/Android RE:** pycdc/pycdas, pylingual, uncompyle6 ⊕, apktool ⊕, bytecodeviewer, dex2jar ⊕, recaf.
**Go/Delphi/VB:** GoReSym, gostringungarbler, IDR, VB-Decompiler, vbdec.
**PE/Static:** PEStudio, PE-bear, CFF Explorer, Dependency Walker, Resource Hacker, PEiD, BinDiff, DIE ⊕, ExeInfoPE, Magika ⊕, FLOSS ⊕, capa ⊕, HashMyFiles, PMA labs.
**Unpacking/Installers:** UPX ⊕, UniExtract2, asar, autoit-ripper, innoextract, innounp, ISDecompiler, Advanced Installer.
**Shellcode:** BlobRunner (32/64), scdbg ⊕, sclauncher (32/64), shellcode_launcher.
**Dynamic/Monitoring:** Sysinternals (Procmon/Procexp/Autoruns…), System Informer, API Monitor, ProcDOT ⊕, Regshot.
**Memory:** pe-sieve, HollowsHunter, ProcessDump.
**Network:** FakeNet-NG ⊕, Wireshark ⊕, Fiddler, nmap ⊕, internet_detector.
**Documents:** Didier-Stevens suite ⊕, PDFStreamDumper, Offvis, OneNoteAnalyzer, MS Office ProPlus.
**JavaScript:** js-beautify ⊕, js-deobfuscator, obfuscator-io-deobfuscator, malware-jail.
**Hex/Registry/Dev:** 010 Editor, HxD, RegCool, reg_export, Python3, IPython ⊕, NASM ⊕, Keystone, VC build tools, Cygwin.
**Utilities/Frameworks:** CyberChef ⊕, YARA ⊕, angr, cryptotester, VS Code ⊕, Notepad++, 7-Zip ⊕, Windows Terminal.

### 3.3 SECURITY ONION 2.4.190 (LAB-SO, standalone grid — do not merge)

Zeek, Suricata, Stenographer, Sensoroni, Strelka, FreqServer, DomainStats, Elastic Agent/Fleet, Osquery, Wazuh, OpenCanary, Redis, Logstash, Filebeat, Elasticsearch, Kibana, ILM, SOC, Onion AI, TheHive, CyberChef ⊕, ElastAlert2, Playbook, ATT&CK Navigator, Sigma, so-idstools, InfluxDB, Telegraf, Grafana, Nginx, Ory Kratos/Dex, so-firewall, so-apt-cacher-ng, ManagerHype. *(≈40 components; version tracks the 2.4.190 release.)*

---

## PART 4 — OVERLAP / DEDUP (why the merge works)

The three Linux/RE distros share a **common analytical backbone** — the same tool processes evidence identically on each, so merging loses nothing:

| Tool | SIFT | REMnux | Kali | FLARE |
|---|:-:|:-:|:-:|:-:|
| YARA | ✓ | ✓ | ✓ | ✓ |
| Volatility 3 | ✓ | ✓ | ✓ | (pe-sieve/MemProcFS) |
| Ghidra | — | ✓ | ✓ | ✓ |
| radare2 | ✓ | ✓ | ✓ | (Cutter) |
| CyberChef | — | ✓ | — | ✓ |
| capa / FLOSS | — | ✓ | — | ✓ |
| Detect-It-Easy | — | ✓ | — | ✓ |
| bulk_extractor | ✓ | ✓ | ✓ | — |
| Sleuth Kit/Autopsy | ✓ | ✓ | ✓ | — |
| ExifTool | ✓ | ✓ | ✓ | — |
| Wireshark/tshark | ✓ | ✓ | ✓ | ✓ |
| oletools | (libolecf) | ✓ | — | (Didier suite) |
| de4dot / ILSpy | — | ✓ | — | ✓ |
| apktool / dex2jar | — | ✓ | ✓ | ✓ |

**Ownership split (who is best at what — so nothing is redundant):**
- **SIFT** owns disk/host forensics + Windows artifact parsing (libyal, Plaso, RegRipper, TSK).
- **REMnux** owns malware static-triage, deobfuscation, network emulation, document analysis on Linux.
- **Kali** owns offense/network attack (Metasploit, Burp, cred attacks).
- **FLARE-VM** owns native Windows debugging + dynamic execution (x64dbg, WinDbg, TTD, live .NET/Office).

→ LAB-LINUX = SIFT ∪ REMnux ∪ Kali(selected). LAB-WINDOWS = FLARE. No overlap wasted; Windows debugging simply cannot move to Linux.

---

## PART 5 — GROUND-TRUTH ENUMERATION (dump the REAL installed list per image)

The catalogs above are the canonical/default sets. To capture exactly what's on YOUR images (for the tracker), run these on each live VM:

```bash
# SIFT / REMnux / Ubuntu Linux
dpkg-query -W -f='${Package}\t${Version}\n' | sort      # apt packages
pip list ; pipx list                                     # python tools (big share of REMnux)
ls /usr/local/bin /opt                                   # salt/manual installs
cat /etc/remnux-version                                  # REMnux release (REMnux only)

# Kali
apt list --installed 2>/dev/null | sort
dpkg-query -W -f='${Package}\n' 'kali-*'                 # which metapackages present
apt depends kali-linux-default                           # tools in the default set
```
```powershell
# FLARE-VM / Windows
choco list                                               # all Chocolatey packages
choco list | Select-String '\.vm'                        # FLARE .vm packages only
```
```bash
# Security Onion
sudo so-status                                           # grid component status/versions
sudo salt-call grains.items                              # platform baseline
```

---

## APPENDIX — Counts

| Platform | Cataloged tools | Notes |
|---|---|---|
| Kali (default) | ~300 | 600+ available across all metapackages |
| SIFT | ~110 primary | 180+ packages, many multi-binary toolkits |
| FLARE-VM | 136 packages | default `config.xml` profile |
| REMnux | ~240 unique | ~290 listed w/ cross-category repeats |
| Security Onion | ~40 components | server grid, not a training toolbag |
| **Union (deduped)** | **~600 unique** | after removing the shared backbone |

**Open version-pin actions (from the source .txt):** Velociraptor exact version (~0.75 unverified), REMnux release date, SIFT `x`-range tools, SO "(Active/Custom)" components track 2.4.190.
