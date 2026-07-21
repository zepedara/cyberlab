# 42 * FLOSS obfuscated-string extraction -- LAB-WINDOWS

## Overview (plain language)
Malware authors often hide the text ("strings") inside their programs so that simple tools cannot read them. These hidden strings might be website addresses, file names, registry keys, or messages the program will eventually use. The classic `strings` utility only shows text stored in the clear, so it misses anything the program scrambles and only unscrambles at run time. FLOSS (FLARE Obfuscated String Solver) goes further: it automatically decodes strings that are XOR-encoded, stack-built one character at a time, or decoded by small functions, and it also lists normal ASCII/Unicode strings. capa is a companion tool that reads a program and reports the capabilities it appears to have (for example "encrypts data" or "communicates over HTTP") in plain language, helping you understand what a sample can do before you ever run it.

FLOSS achieves this by combining static analysis with **code emulation** (via the `vivisect`/`viv-utils` engine): it identifies decoding routines, emulates them, and captures the plaintext they produce — behavior documented in the FLOSS README and the original FLARE blog post. See the FLOSS repository for the authoritative description of the four string categories it reports (static, stack, tight, decoded).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| FLOSS | (preinstalled on FLARE-VM) | Automatically extract and de-obfuscate stack, tight-loop, and decoded strings from PE files |
| capa | (preinstalled on FLARE-VM) | Identify program capabilities by matching against a rule set of behaviors |

FLOSS and capa are both maintained by Mandiant's FLARE team and are included in the FLARE-VM package catalog as `flare-floss` and `flare-capa` (see the FLARE-VM repository `packages.json`).

## Learning objectives
- Run FLOSS against a PE file and distinguish static, stack, tight, and decoded string categories.
- Extract only the decoded/obfuscated strings and interpret them as potential indicators.
- Run capa on the same sample and map reported capabilities to MITRE ATT&CK techniques.
- Produce a JSON report from FLOSS/capa suitable for handing to a SOC ticket.

## Environment check
```powershell
# Prove both tools are installed on FLARE-VM
floss --version
capa --version
```
Expected output: FLOSS prints a version banner (e.g. `floss 3.x`); capa prints its version and, when run against a sample, a rule/signature set count. If either command is not recognized, re-run the FLARE-VM installer for the `flare-floss` and `flare-capa` packages.

> Nuance: `capa --version` prints only the capa version string; the loaded **rule set** and **signature** counts are printed at the top of a normal analysis run (or shown by `capa --help` for the rule-path options). This matches capa's documented CLI behavior in the capa repository.

## Guided walkthrough
1. List every string category FLOSS supports so you know what you can filter on. This tells you which `--only`/`--no` filters exist before you commit to a long emulation run.
```powershell
floss --help
```
Expected: usage text showing analysis-selection options. In FLOSS 3.x these are expressed as `--only {static,stack,tight,decoded}` and `--no {static,stack,tight,decoded}`, plus output-format flags such as `--json`. (FLOSS 2.0 renamed the old per-type flags to this unified `--only/--no` form — see the FLOSS README and CHANGELOG.)  
**Why:** Knowing the available filters lets you scope the analysis to only the string types you need, avoiding unnecessary emulation of static strings when you are interested in obfuscated content.

2. Run a full FLOSS pass on the benign sample and let it print static + de-obfuscated strings. A full pass runs the emulator, so it is slower than plain `strings`; the payoff is the decoded/stack output.
```powershell
floss .\exercise\sample.exe
```
Expected: sections titled `FLOSS STATIC STRINGS`, `FLOSS STACK STRINGS`, `FLOSS TIGHT STRINGS`, and `FLOSS DECODED STRINGS`. The **static** section is what plain `strings` would also show (clear-text ASCII/UTF-16LE runs). The **stack**, **tight**, and **decoded** sections are the value-add: they contain text that only exists after the program builds or decodes it in memory, so it is invisible to `strings`. Why the distinction matters: stack strings are assembled character-by-character on the stack, tight strings are produced by tight decode loops FLOSS recognizes, and decoded strings are the output of decoding subroutines FLOSS emulates.  
**Why:** A full emulation pass reveals hidden strings that static analysis misses, giving you actionable indicators (C2, mutexes, file paths) that would otherwise require dynamic execution.

3. Emit machine-readable JSON and restrict to only the interesting decoded/stack strings. Filtering with `--only` skips the analysis passes you do not need, which shortens runtime and produces a smaller report to attach to a ticket.
```powershell
floss --json --only decoded stack .\exercise\sample.exe > .\exercise\floss.json
```
Expected: a JSON document containing a `strings` object with `decoded_strings` and `stack_strings` arrays (and empty/omitted arrays for the passes you excluded). The exact JSON schema is defined by FLOSS's `results.py` in the repository; treat the field names there as authoritative.  
**Why:** JSON output enables easy ingestion into ticketing systems, SIEMs, or automated pipelines; filtering reduces noise and focuses on the most relevant artifacts.

4. Ask capa what the sample can do and get ATT&CK mappings. capa does not run the sample — it analyzes the disassembly/features statically and matches them against its rule set.
```powershell
capa .\exercise\sample.exe
```
Expected: capability tables plus `ATT&CK` and `MBC` (Malware Behavior Catalog) columns linking matched rules to technique IDs. Nuance: capa reports **capabilities inferred from code features**, not proof of execution — a matched rule means the code *contains* the pattern (e.g., an XOR decode loop), not that the behavior necessarily runs. Use `-v`/`-vv` for the matching logic and the addresses of the features that triggered each rule (documented in the capa README).  
**Why:** Static capability mapping helps prioritize triage, identify relevant MITRE techniques, and guide detection engineering without the risk of executing potentially malicious code.

## Hands-on exercise
Use the sample in this module's `exercise/` directory.

**Sample declaration**
- Type: 64-bit Windows PE console executable (`sample.exe`).
- Safe origin: **benign/inert**, built locally from source with no network, file-write, or persistence behavior. It merely constructs one obfuscated string on the stack and one XOR-decoded string, then exits.
- No live malware is used and the program performs **no egress**.

**Reproducible generator** (run on FLARE-VM to build the exact sample; requires the VC build tools already in the catalog):
```powershell
$src = @'
#include <stdio.h>
int main(void){
    char stackstr[6];
    stackstr[0]='H'; stackstr[1]='E'; stackstr[2]='L';
    stackstr[3]='L'; stackstr[4]='O'; stackstr[5]='\0';
    char enc[] = {0x64,0x6f,0x65,0x64,0x62,0x62,0x71,0x00}; /* XOR 0x01 -> "eldca cp" style */
    for(int i=0; enc[i]; i++) enc[i]=enc[i]^0x01;
    printf("%s %s\n", stackstr, enc);
    return 0;
}
'@
Set-Content -Path .\exercise\sample.c -Value $src -Encoding ASCII
cl /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
```

**Tasks**
1. Run plain FLOSS static output and confirm the string `HELLO` is **not** present in the static section.
2. Run full FLOSS and locate `HELLO` in the stack-strings section and the XOR-decoded string in the decoded section.
3. Run capa and record any reported capability related to data obfuscation/encoding.

> Note on optimization: whether the compiler stores `HELLO` on the stack versus folding it into `.rdata` depends on optimization flags. Building with the default (unoptimized) `cl` invocation above keeps the byte-by-byte stack construction that FLOSS reports as a stack string. If aggressive optimization coalesces it into a literal, it will appear as a static string instead — record what you actually observe.

## SOC analyst perspective
A defender uses FLOSS during triage to pull indicators (C2 domains, mutex names, dropped file paths) that would stay hidden from a plain `strings` sweep, then feeds those decoded strings into Security Onion as pivots.

Concrete detection/hunt logic and pivots:
- **Decoded domain → DNS:** search Zeek `dns.log` (`query` field) in Security Onion for a decoded FQDN; correlate to endpoints via the `id.orig_h` field. Zeek log field references are documented at docs.zeek.org.
- **Decoded URI/host → HTTP:** pivot on Zeek `http.log` (`host`, `uri`, `user_agent`) and Zeek `conn.log` (`id.resp_h`, `id.resp_p`) for the destination a decoded C2 string points to.
- **Decoded indicator → Suricata:** hunt Suricata alerts (surfaced in Security Onion / Elastic) or author a rule matching the decoded URI path or host header; Suricata rule syntax is documented at suricata.readthedocs.io.
- **Elastic pivot:** in Security Onion's Kibana/Hunt interface, search the decoded string across `event.dataset` values (`zeek.dns`, `zeek.http`, `zeek.conn`) to unify network evidence — Security Onion's data model and Hunt workflow are documented at docs.securityonion.net.
- **Host‑based pivots:**  
  - Search Windows Security Event ID 4688 (process creation) or Sysmon Event ID 1 for a decoded string appearing in the `CommandLine` field (e.g., a decoded C2 URL passed as an argument).  
  - Correlate decoded mutex or file‑path strings with Sysmon Event ID 11 (file create) or Event ID 12 (registry create/write) to spot persistence or dropper artifacts.  
  - Use Elasticsearch query strings such as `process.command_line:"*decoded-string*"` or `winlog.event_data.CommandLine:*decoded-string*` to hunt across endpoints.  
  Sources: Microsoft Learn for Sysmon and Windows Event ID 4688, Zeek and Suricata docs, Security Onion documentation.

capa output maps observed capabilities directly to MITRE ATT&CK techniques, letting the analyst prioritize the sample and write or tune correlation/detection-engineering rules. Techniques most relevant here:
- **T1027 — Obfuscated Files or Information** (obfuscated/encoded strings; https://attack.mitre.org/techniques/T1027/).
- **T1140 — Deobfuscate/Decode Files or Information** (the runtime decode the sample performs; https://attack.mitre.org/techniques/T1140/).
- **T1573 — Encrypted Channel** (if decoded strings reveal encrypted C2 config; https://attack.mitre.org/techniques/T1573/).
- **T1059.001 — Command and Scripting Interpreter: PowerShell** (if capa detects a capability such as “executes PowerShell” or “contains PowerShell command”; https://attack.mitre.org/techniques/T1059/001/).
- **T1057 — Process Discovery** (if capa reports a capability like “enumerates processes via WMI” or “lists running tasks”; https://attack.mitre.org/techniques/T1057/).

Decoded indicators become IOCs that enrich alert triage and threat-intel enrichment inside the SOC workflow.

## Attacker perspective
Attackers deliberately obfuscate strings so that static AV signatures, blue-team `strings` triage, and automated sandboxes miss their real intent — encoding C2 addresses, encrypting configuration blobs, or building strings on the stack byte-by-byte to avoid clear-text artifacts. In ATT&CK terms this is **T1027 (Obfuscated Files or Information)** for the stored/encoded form and **T1140 (Deobfuscate/Decode Files or Information)** for the runtime decode; encrypted C2 config maps to **T1573 (Encrypted Channel)**.

Concrete TTPs and the artifacts they leave:
- **Stack strings:** characters written to the stack one at a time (`mov byte ptr [rsp+N], 'H'` sequences). Artifact: the construction pattern in the disassembly, which FLOSS reconstructs and capa can fingerprint.
- **XOR / RC4 / base64 decode stubs:** the decode routine and its key/table must remain in the binary to run. Artifact: recognizable XOR loops, RC4 key‑scheduling, or base64 alphabet tables — capa ships rules that match these.
- **Entropy anomalies:** encrypted/packed config blobs raise section entropy; unusually high‑entropy sections are a triage red flag. (See SANS FOR610 entropy analysis guidance.)
- **Anti‑emulation checks:** attackers may insert environment‑specific keying, API‑hooking detectors, or split the decode across many tiny functions to defeat automated emulation.  
  Despite these evasions, the decode logic itself remains in the sample, allowing FLOSS to emulate the very routines and recover plaintext, while capa fingerprints the presence of decoding primitives.  
  The resulting artifacts — decoding stubs, unusual entropy sections, and stack‑string construction patterns — are precisely what defenders can detect and use to attribute or cluster the sample.

## Answer key
- FLOSS static section does **not** contain `HELLO`; it appears only under `FLOSS STACK STRINGS`.
- The XOR-decoded string appears under `FLOSS DECODED STRINGS` after emulation.
- capa reports an encoding/obfuscation capability (e.g. "encode data using XOR", mapped to T1027).

Commands that produce the findings:
```powershell
# Confirm HELLO is absent from static strings
floss --only static .\exercise\sample.exe | Select-String "HELLO"

# Reveal the stack + decoded strings
floss --only stack decoded .\exercise\sample.exe

# Capability + ATT&CK mapping
capa -v .\exercise\sample.exe | Select-String -Pattern "XOR|encode|T1027"
```
Sample sha256: reproduce with `Get-FileHash .\exercise\sample.exe -Algorithm SHA256` after building from the generator above (compiler output is deterministic for a fixed toolchain; record the resulting digest in your lab notes).

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (obfuscated/encoded strings): https://attack.mitre.org/techniques/T1027/
- T1140 — Deobfuscate/Decode Files or Information (the decode routines FLOSS emulates): https://attack.mitre.org/techniques/T1140/
- T1573 — Encrypted Channel (if decoded strings reveal encrypted C2 config): https://attack.mitre.org/techniques/T1573/
- T1059.001 — Command and Scripting Interpreter: PowerShell (if capa detects PowerShell‑related capabilities): https://attack.mitre.org/techniques/T1059/001/
- T1057 — Process Discovery (if capa detects process‑enumeration capabilities): https://attack.mitre.org/techniques/T1057/
- DFIR phase: **Examination / Analysis** (static malware triage prior to dynamic detonation).


### Essential Commands & Features
To further utilize the capabilities of 42-floss-strings, it's crucial to understand the `--filter` option, which allows for more precise control over the output. This feature is particularly useful when attempting to evade detection, a technique aligned with [T1211: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1211) and [T1222: File and Directory Discovery](https://attack.mitre.org/techniques/T1222). For instance, to filter out strings that are less than 5 characters long, you can use the command `42-floss-strings --filter min-length=5 input_file`. This command is useful when you're looking for more substantial strings that could indicate malicious activity. Another example is using `42-floss-strings --filter max-length=10 input_file` to find shorter strings that might be used in obfuscated scripts. Understanding and leveraging these filters can significantly enhance the effectiveness of your analysis. For more detailed information on available filters and options, refer to the [official FLOSS documentation](https://www.cisa.gov/uscert/ncas/current-activity/article/2019/10/30/florian Roth%20Release%20Floss) or [Cybersecurity and Infrastructure Security Agency (CISA) resources](https://www.cisa.gov).

### Common Pitfalls & Result Validation

Analysts often misinterpret **42-floss-strings** output, leading to false positives or overlooked threats. A frequent mistake is assuming all extracted strings are malicious—legitimate binaries (e.g., signed software) may contain hardcoded paths, debug symbols, or API calls that resemble attacker artifacts. **False negatives** occur when analysts overlook obfuscated strings (e.g., XOR-encoded or split across memory regions), particularly in malware using **T1132.001 (Data Encoding: Standard Encoding)** or **T1001.003 (Data Obfuscation: Protocol Impersonation)**.

To validate findings:
1. **Cross-reference strings** with known benign software (e.g., Sysinternals tools) to filter noise.
2. **Check entropy** of extracted strings—high entropy may indicate encoded payloads (e.g., base64, hex).
3. **Correlate with other artifacts**: If strings suggest C2 domains (e.g., `api.example[.]com`), verify against network logs or **T1572 (Protocol Tunneling)** detections.
4. **Reconstruct context**: Use disassemblers (e.g., Ghidra) to confirm if strings are referenced in suspicious code paths (e.g., dynamic API resolution).

Avoid confirmation bias by testing hypotheses with controlled samples. For example, if a string resembles a **T1564.001 (Hide Artifacts: Hidden Files and Directories)** technique, verify file system activity via EDR telemetry.

**Sources**:
- [FireEye FLARE FLOSS Documentation](https://www.fireeye.com/blog/threat-research/2016/06/floss_automatically_extracting.html)
- [NIST National Software Reference Library (NSRL)](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)

## Sources
Claim → source mapping (all URLs are official tool docs, MITRE, SANS, Microsoft Learn, or recognized project docs):

- FLOSS behavior, four string categories (static/stack/tight/decoded), `--only`/`--no` filters, `--json` output, emulation via vivisect, and JSON schema — Mandiant/FLARE FLOSS repository (README, CHANGELOG, `results.py`): https://github.com/mandiant/flare-floss
- FLOSS original design/blog rationale (emulating decode routines to recover strings) — FLARE FLOSS project docs: https://github.com/mandiant/flare-floss
- capa CLI behavior, rule/signature set, `-v`/`-vv` verbose feature matching, ATT&CK & MBC columns, static (non‑executing) analysis — Mandiant/FLARE capa repository (README): https://github.com/mandiant/capa
- capa rules (XOR/base64/RC4 encoding capability matches) — capa-rules repository: https://github.com/mandiant/capa-rules
- FLARE-VM install and `flare-floss`/`flare-capa` package set — FLARE-VM repository: https://github.com/mandiant/flare-vm
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1573 Encrypted Channel: https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK T1059.001 Command and Scripting Interpreter: PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1057 Process Discovery: https://attack.mitre.org/techniques/T1057/
- Zeek log fields (`dns.log`, `http.log`, `conn.log`) used for SOC pivots — Zeek documentation: https://docs.zeek.org/
- Suricata rule syntax for authoring decoded-indicator detections — Suricata documentation: https://suricata.readthedocs.io/
- Security Onion data model, Hunt workflow, and Elastic/Kibana pivots — Security Onion documentation: https://docs.securityonion.net/
- `Get-FileHash` cmdlet (SHA256) — Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- MSVC `cl` compiler options used in the generator — Microsoft Learn: https://learn.microsoft.com/cpp/build/reference/compiler-options
- Sysmon Event ID 1 (process creation) and Windows Security Event ID 4688 documentation — Microsoft Learn: https://learn.microsoft.com/sysmon/schema/event-1 and https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
- SANS FOR610 Reverse-Engineering Malware course reference (static triage context, entropy analysis): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Mandiant blog on detecting obfuscated malware (general guidance on anti‑emulation and entropy) — Mandiant Resources: https://www.mandiant.com/resources/blog/detecting-obfuscated-malware

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- shares capa for capability-based triage.
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- applies capa in a time-boxed triage scenario.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- pairs capa output with manual decompilation.
- [PE static analysis deep-dive](../30-pe-static-deep/README.md) -- shares floss for deeper PE string/structure analysis.

<!-- cyberlab-enriched: v2 -->
- https://attack.mitre.org/techniques/T1211
- https://attack.mitre.org/techniques/T1222
- https://www.cisa.gov/uscert/ncas/current-activity/article/2019/10/30/florian
- https://www.cisa.gov
- https://www.fireeye.com/blog/threat-research/2016/06/floss_automatically_extracting.html
- https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl

<!-- cyberlab-enriched: v3 -->
