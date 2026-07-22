# 60 * Active Directory attack paths (BloodHound / Kerberoast) -- LAB-LINUX

## Overview (plain language)
Active Directory attacks rarely rely on exploits — they abuse misconfigured permissions and Kerberos. BloodHound graphs the domain to expose attack paths; Impacket extracts crackable Kerberos hashes. This module is defensive-focused: understand the paths to defend them, run only against the provided lab domain.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| BloodHound | `sudo apt install bloodhound` on Kali/REMNUX [1] | Graph AD objects + ACLs to reveal privilege-escalation and lateral-movement attack paths |
| SharpHound (or BloodHound.py) | Download from [GitHub releases](https://github.com/BloodHoundAD/SharpHound/releases) (SharpHound.exe); `pip install bloodhound` for the Python collector (BloodHound.py) [2] | Collector that gathers AD sessions, ACLs, group memberships for BloodHound ingestion |
| Impacket (GetUserSPNs, GetNPUsers) | `pip install impacket` [3] | Request Kerberoast (SPN) and AS-REP roastable hashes for offline cracking |
| neo4j | `sudo apt install neo4j` [4] | Graph database backing BloodHound |

## Learning objectives
- Collect AD data with SharpHound (or BloodHound.py) and ingest it into BloodHound
- Identify shortest paths from a low-priv user to Domain Admin
- Perform Kerberoasting and AS-REP roasting with Impacket
- Explain the defensive detections and mitigations for each path

## Environment check
Confirm neo4j is running: `sudo systemctl start neo4j` then `sudo systemctl status neo4j` [4]. Launch BloodHound from the terminal: `bloodhound`. Test Impacket: `GetUserSPNs.py -h` should show usage. Use ONLY the provided isolated lab domain — never a production directory.

## Guided walkthrough
1. **Collect AD data** – On a Linux machine in the lab, run BloodHound.py (the Python collector) targeting a domain controller:
   ```bash
   bloodhound-python -u analyst -p 'LabPass123!' -d lab.local -dc 10.0.51.100 -c All
   ```
   *Why:* The `-c All` flag collects all available data (users, groups, computers, sessions, ACLs, trusts). Output files (`.json`) are written to the current directory. If a pre-collected SharpHound `.zip` is provided, skip this step. [2]

2. **Ingest into BloodHound** – In BloodHound GUI, click *Upload Data* and select the `.zip` (SharpHound) or the folder containing `.json` (BloodHound.py). The data is stored in neo4j.

3. **Find attack paths** – In the BloodHound search bar, type `analyst` (the low-priv user). Under *Node Info*, run the pre-built query *Shortest Paths to Domain Admins*. Examine the edges; common abusable edges include `GenericAll`, `GenericWrite`, `WriteOwner`, `AddMember`, or a Kerberoastable SPN.

4. **Kerberoasting** – Once a service account with an SPN is identified (e.g., `svc_sql`), request its TGS ticket:
   ```bash
   GetUserSPNs.py lab.local/analyst:'LabPass123!' -request -outputfile kerberoast_hashes.txt
   ```
   *Why:* The `-request` flag returns the TGS-REP encrypted with the service account’s NTLM hash. The output file contains hashes crackable with hashcat mode 13100 [3][5]. If the hash is RC4 (0x17), it’s weak; AES (0x12, 0x18) is not crackable offline.

5. **AS-REP roasting** – For accounts without Kerberos pre-authentication (e.g., `nopreauth_user`), request AS-REP hashes:
   ```bash
   GetNPUsers.py lab.local/ -usersfile users.txt -no-pass -format hashcat
   ```
   *Why:* The `-no-pass` flag skips password authentication; the AS-REP is encrypted with the user’s NTLM hash (mode 18200) [3][5].

6. **Crack the hashes** (outside the lab, if allowed):
   ```bash
   hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --show
   ```

## Hands-on exercise
Ingest the provided SharpHound data (`lab_data.zip`) into BloodHound, find the shortest path from `analyst` to `Domain Admins`, and name the abusable edge. Then Kerberoast the `svc_sql` SPN and identify the hashcat mode (13100 for Kerberos TGS, 18200 for AS-REP). Write the crack command.

## SOC analyst perspective
**Detection logic for Kerberoasting (T1558.003):**
- **Windows Event ID 4769** – A Kerberos service ticket request with *Ticket Encryption Type* `0x17` (RC4) from a non-DC host, especially in bulk or for unusual service names [6].
- **Log source:** Domain Controller Security log (`Security.evtx`). Hunt for multiple `4769` events where `Service Name` does not end in `$` (computer accounts) and `Client Address` is not the DC itself.
- **Zeek (Bro) detection:** In `kerberos.log`, look for high `request_type` (TGS) with `cipher` `rc4-hmac` and `service` not starting with `krbtgt` or `$` [7].
- **Suricata pivots:** Alert on Kerberos TGS requests with RC4 encryption (rule matches `kerberos.tgs` and `kerberos.cipher == rc4-hmac`). Example hunt: count TGS requests per client IP over 1 hour, flag outliers > 50.

**Detection logic for AS-REP roasting (T1558.004):**
- **Windows Event ID 4768** – A Kerberos authentication ticket request with *Pre-Authentication Type* `0` (none) [6].
- **Log source:** DC Security log. Hunt for `4768` where `Pre-Authentication Type` is `0` and `Account Name` is not a computer account.
- **Threat-hunting pivot:** Query for accounts that have `userAccountControl` attribute containing `DONT_REQ_PREAUTH` (flag 4194304). Use LDAP query: `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` [8].

**BloodHound enumeration detection (T1069.002, T1087.002):**
- **Windows Event ID 4662** – An operation was performed on an Active Directory object. High count of `LDAP query` events from a single source, especially using `samAccountType` or `objectClass` filters, indicates reconnaissance [6].
- **Zeek detection:** In `ldap.log`, look for high-frequency `searchRequest` operations with base DN `DC=lab,DC=local`. Pivot on `result` count > 1000 in short time.

**Mitigations:**
- Remove unnecessary SPNs from service accounts; use Group Managed Service Accounts (gMSA) with automatic password rotation.
- Enable Kerberos pre-authentication for all user accounts (default; audit for disabled).
- Monitor and restrict who can request TGS tickets (Kerberos constrained delegation).
- Tier AD administrative accounts – no service accounts in Domain Admins.

## Attacker perspective
After initial foothold (e.g., via phishing or unpatched service), an attacker enumerates AD:
1. **Reconnaissance:** Run BloodHound collector (SharpHound.exe or BloodHound.py) to map the domain and identify high-value targets. Artifacts: network connections to LDAP port 389/636, spikes in LDAP queries on the DC, and possible SharpHound binary dropped on disk (if not executed in-memory).
2. **Credential Access – Kerberoasting:** Enumerate service accounts with SPNs (e.g., via `setspn -T lab.local -Q */*`). Request TGS tickets for high-value SPNs (e.g., SQL, IIS, CIFS for file servers). Evasion: request only one SPN every few minutes to avoid triggering baselines; use RC4-only tickets by disabling AES encryption on the target account (if administrator privileges).
3. **AS-REP Roasting:** Identify accounts with `DONT_REQ_PREAUTH` using LDAP query. Request AS-REP hashes without any authentication. Evasion: use multiple source IPs, sleep between requests.
4. **Privilege Escalation – ACL abuse:** If BloodHound reveals e.g., `GenericAll` on a group that contains Domain Admins, the attacker can add their account to that group (using `net group` or PowerView). Artifacts: Windows Event ID 4728 (member added to security group) or 4732 (member added to local group) on the DC [6].
5. **Cracking:** Offline crack obtained hashes with hashcat. If successful, impersonate the service account to move laterally.

**Artifacts left:**
- Kerberos ticket files (`.kirbi`) if exported via Mimikatz.
- Network connections to port 88 (Kerberos) from non-DC hosts.
- Event logs 4769/4768 on DC with unusual patterns.
- Possible LDAP search queries (Event 4662) tied to BloodHound data gathering.

## Answer key
- **Shortest path example:** `analyst` → `GenericAll` on `IT_Support` group → `AddMember` to `Domain Admins` → `Domain Admin`. The abusable edge is `GenericAll` on the `IT_Support` group.
- **Kerberoast hashcat mode:** `-m 13100` for TGS-REP hashes (Kerberos 5 TGS) [5].
- **AS-REP hashcat mode:** `-m 18200` for AS-REP hashes (Kerberos 5 AS-REP) [5].
- **Crack command:** `hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --show`
- **Expected hash example:** `$krb5tgs$23$*svc_sql$lab.local$lab.local/svc_sql*$...`

## MITRE ATT&CK & DFIR phase
- **T1558.003** – *Kerberoasting* – Credential Access (request SPN TGS tickets for offline cracking) [9]
- **T1558.004** – *AS-REP Roasting* – Credential Access (accounts without Kerberos pre-authentication) [9]
- **T1069.002** – *Permission Groups Discovery: Domain Groups* – Discovery (BloodHound enumerating group memberships) [9]
- **T1087.002** – *Account Discovery: Domain Account* – Discovery (LDAP queries for user/computer objects) [9]
- **T1482** – *Domain Trust Discovery* – Discovery (BloodHound maps trusts) [9]
- **T1098.002** – *Account Manipulation: Exchange of Account Permission* – Privilege Escalation (ACL abuse to add user to sensitive groups) [9]
- **T1207** – *Hiding of Objects (Kerberos service accounts)* – Defense Evasion (disabling AES to force RC4) [9]
- **DFIR phases:** Reconnaissance (T1069, T1087, T1482), Credential Access (T1558.003/4), Privilege Escalation (T1098.002), Defense Evasion (T1207)

### Detection Signatures & Reference Artifacts

Real, community-maintained detection rules for this topic (defensive use only). The reference artifacts at the end are BENIGN, illustrative lab values -- not live indicators.

**Sigma rule -- Suspicious Space Characters in TypedPaths Registry Path - FileFix** (source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_typedpaths_space_characters.yml; license: Detection Rule License / DRL):

```yaml
title: Suspicious Space Characters in TypedPaths Registry Path - FileFix
id: 8f2a5c3d-9e4b-4a7c-8d1f-2e5a6b9c3d7e
related:
    - id: 3ae9974a-eb09-4044-8e70-8980a50c12c8
      type: similar
status: experimental
description: |
    Detects the occurrence of numerous space characters in TypedPaths registry paths, which may indicate execution via phishing lures using file-fix techniques to hide malicious commands.
references:
    - https://expel.com/blog/cache-smuggling-when-a-picture-isnt-a-thousand-words/
    - https://mrd0x.com/filefix-clickfix-alternative/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-11-04
tags:
    - attack.execution
    - attack.stealth
    - attack.t1204.004
    - attack.t1027.010
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|endswith: '\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\url1'
        Details|contains: '#'
    selection_space_variation:
        Details|contains:
            - '            ' # En Quad (U+2000)
            - '            ' # Em Quad (U+2001)
            - '            ' # En Space (U+2002)
            - '            ' # Em Space (U+2003)
            - '            ' # Three-Per-Em Space (U+2004)
            - '            ' # Four-Per-Em Space (U+2005)
            - '            ' # Six-Per-Em Space (U+2006)
            - '            ' # Figure Space (U+2007)
            - '            ' # Punctuation Space (U+2008)
            - '            ' # Thin Space (U+2009)
            - '            ' # Hair Space (U+200A)
            - '            ' # No-Break Space (U+00A0)
            - '            ' # Normal space
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```

**YARA rule** (source: https://github.com/Neo23x0/signature-base/blob/master/yara/mal_ransom_esxi_attacks_feb23.yar, author: Florian Roth):

```yara
rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_1 {
   meta:
      description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers - file encrypt.sh"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
      date = "2023-02-04"
      score = 85
      hash1 = "10c3b6b03a9bf105d264a8e7f30dcab0a6c59a414529b0af0a6bd9f1d2984459"
      id = "7178dbe4-f573-5279-a23e-9bab8ae8b743"
   strings:
      $x1 = "/bin/find / -name *.log -exec /bin/rm -rf {} \\;" ascii fullword
      $x2 = "/bin/touch -r /etc/vmware/rhttpproxy/config.xml /bin/hostd-probe.sh" ascii fullword
      $x3 = "grep encrypt | /bin/grep -v grep | /bin/wc -l)" ascii fullword

      $s1 = "## ENCRYPT" ascii fullword
      $s2 = "/bin/find / -name *.log -exec /bin" ascii fullword
   condition:
      uint16(0) == 0x2123 and
      filesize < 10KB and (
         1 of ($x*)
         or 2 of them
      ) or 3 of them
}
```

**Real-world context (MITRE T1558.003 -- Steal or Forge Kerberos Tickets: Kerberoasting):** see the documented Procedure Examples at https://attack.mitre.org/techniques/T1558/003/ -- real in-the-wild use includes FIN7.

**Reference artifacts (illustrative benign lab values -- generate real hashes locally):**

| Type | Value |
|---|---|
| host IOC | 192.0.2.10 (RFC5737 documentation range) |
| network IOC | hxxp://example[.]com/benign (defanged) |
| sample hash | benign lab sample -- create one and run `sha256sum` |

### Real-World Case Study
This technique is documented in **real** intrusions. Rather than a hypothetical scenario, study the authoritative case data below:
- **MITRE ATT&CK T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)** — real-world Procedure Examples with named campaigns and citations: https://attack.mitre.org/techniques/T1558/003/
- **Threat actors documented using it:** FIN7 (see each group's page on attack.mitre.org for the specific intrusions).
- **RedCanary Threat Detection Report** — how often this technique appears in real environments + detection guidance: https://redcanary.com/threat-detection-report/
- **The DFIR Report** — full real intrusion walk-throughs (timeline, TTPs, IOCs): https://thedfirreport.com/

*Exercise: pick one documented actor above, read its ATT&CK page, and map how this module's tool would surface that activity in an investigation.*

## Sources
1. BloodHound Installation – Kali Tools: https://www.kali.org/tools/bloodhound/
2. BloodHound.py – GitHub: https://github.com/BloodHoundAD/BloodHound-Tools/tree/main/BloodHound.py
3. Impacket – GitHub: https://github.com/fortra/impacket (GetUserSPNs, GetNPUsers)
4. Neo4j Installation – Official: https://neo4j.com/docs/operations-manual/current/installation/linux/
5. hashcat Kerberos modes – hashcat wiki: https://hashcat.net/wiki/doku.php?id=example_hashes (mode 13100, 18200)
6. Microsoft Windows Security Auditing – Event IDs 4769, 4768, 4662: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview
7. Zeek Kerberos Log – Zeek documentation: https://docs.zeek.org/en/current/scripts/base/protocols/kerberos/main.zeek.html
8. LDAP pre-auth query – Microsoft: https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
9. MITRE ATT&CK: https://attack.mitre.org/techniques/ (T1558.003, T1558.004, T1069.002, T1087.002, T1482, T1098.002, T1207)

## Related modules
- [Scenario: ransomware memory investigation](../47-ransomware-memory-case/README.md) -- same learning path (Scenarios)
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- same learning path (Scenarios)
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- same learning path (Scenarios)
- [Scenario: C2 network traffic hunt](../50-c2-network-hunt/README.md) -- same learning path (Scenarios)

<!-- cyberlab-enriched: v6 -->
