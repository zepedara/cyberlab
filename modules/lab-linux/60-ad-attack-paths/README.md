# 60 * Active Directory attack paths (BloodHound / Kerberoast) -- LAB-LINUX

## Overview (plain language)
Active Directory attacks rarely rely on exploits — they abuse misconfigured permissions and Kerberos. BloodHound graphs the domain to expose attack paths; Impacket extracts crackable Kerberos hashes. This module is defensive-focused: understand the paths to defend them, run only against the provided lab domain.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| BloodHound | apt install bloodhound / clone BloodHound | Graph AD objects + ACLs to reveal privilege-escalation and lateral-movement attack paths |
| SharpHound | github.com/BloodHoundAD/SharpHound | Collector that gathers AD sessions, ACLs, group membership for BloodHound ingest |
| Impacket (GetUserSPNs/GetNPUsers) | pip install impacket | Request Kerberoast (SPN) and AS-REP roastable hashes for offline cracking |
| neo4j | apt install neo4j | Graph database backing BloodHound |

## Learning objectives
- Collect AD data with SharpHound and ingest it into BloodHound
- Identify shortest paths from a low-priv user to Domain Admin
- Perform Kerberoasting and AS-REP roasting with Impacket
- Explain the defensive detections and mitigations for each path

## Environment check
Confirm `neo4j status`, BloodHound launches, and `GetUserSPNs.py -h` runs. Use ONLY the provided isolated lab domain — never a production directory.

## Guided walkthrough
1. Collect with SharpHound: `SharpHound.exe -c All` (or the Python collector) against the lab DC.
2. Import the resulting .zip into BloodHound and run the 'Shortest Paths to Domain Admins' query.
3. Identify an abusable edge (e.g. GenericAll, AddMember, or a Kerberoastable SPN).
4. Kerberoast: `GetUserSPNs.py lab.local/user:pass -request` → crack the TGS hash offline with hashcat mode 13100.
5. AS-REP roast accounts without pre-auth: `GetNPUsers.py lab.local/ -usersfile users.txt -no-pass`.

## Hands-on exercise
Ingest the provided SharpHound data into BloodHound, find the shortest path from `analyst` to `Domain Admins`, and name the abusable edge. Then Kerberoast the `svc_sql` SPN and identify the hashcat mode.

## SOC analyst perspective
Defenders use BloodHound proactively to find and cut attack paths (remove dangerous ACLs, tier admin accounts). Detections: 4769 TGS requests with RC4 (Kerberoasting), AS-REP requests, and anomalous SharpHound-like LDAP enumeration.

## Attacker perspective
After a foothold, attackers enumerate AD, roast service accounts for offline cracking, and follow ACL/session edges to Domain Admin. Weak service-account passwords and accounts without Kerberos pre-auth are the common wins.

## Answer key
BloodHound highlights the shortest path via an abusable edge (e.g. `svc_sql` GenericAll → group → DA). Kerberoast TGS hashes crack with hashcat `-m 13100`; AS-REP hashes use `-m 18200`.

## MITRE ATT&CK & DFIR phase
- **T1558.003** — Kerberoasting — request SPN TGS tickets for offline cracking
- **T1558.004** — AS-REP Roasting — accounts without Kerberos pre-auth yield crackable hashes
- **T1069.002** — Permission Groups Discovery: Domain Groups — BloodHound enumeration

## Sources
- BloodHound docs: https://bloodhound.readthedocs.io/
- Impacket: https://github.com/fortra/impacket
- MITRE Kerberoasting T1558.003: https://attack.mitre.org/techniques/T1558/003/

## Related modules
- - 11-offensive-kali — Impacket/NetExec/Responder foundations
- - 40-password-cracking — crack the roasted hashes
