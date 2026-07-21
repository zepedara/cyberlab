# 39 * Frida dynamic instrumentation -- LAB-LINUX

## Overview (plain language)
Frida is a "dynamic instrumentation" toolkit. In plain terms, it lets you watch a running program from the inside while it is executing, and even change what it does on the fly. Instead of only reading a program's code, you can attach to a live process, print out which functions it calls, see the arguments passed to them, and read return values — all without recompiling the program. Analysts use Frida to unmask malware that decrypts strings or builds network requests only at runtime, so the interesting behavior never appears in the static file. Think of it like putting sensors and probes on machinery while it runs, rather than staring at a blueprint.

Frida works by injecting its own JavaScript engine (QuickJS) and a native agent into the target process, then exposing a scriptable API you drive from a controlling host (the CLI tools, Python, or Node.js bindings). This "agent injected into the target" design is documented on the Frida site and is exactly what makes Frida both powerful for analysis and detectable as an injection artifact (see Attacker/SOC perspectives). Source: Frida — *Modes of operation* / *Home* (https://frida.re/docs/home/).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Frida | `pip install frida-tools` (recommended; ships the `frida`, `frida-trace`, `frida-ps`, etc. CLIs and pulls in the `frida` Python bindings) | Dynamic instrumentation: attach to/spawn a process and hook functions at runtime to observe or modify behavior |

> Note on install: the Frida project's official install guidance is `pip install frida-tools` (the `frida-tools` package provides the CLI applications and depends on the `frida` core Python bindings). Source: Frida — *Installation* (https://frida.re/docs/installation/). On REMnux, Frida is preinstalled and listed under the dynamic/behavioral analysis tools. Source: REMnux — *Discover the tools* (https://docs.remnux.org/discover-the-tools/). A distro `python3-frida` apt package may lag the current release; prefer the pip package if versions must match `frida-tools`.

## Learning objectives
- Confirm Frida CLI and Python bindings are installed and usable on LAB-LINUX.
- Spawn a benign target under Frida and enumerate loaded modules and exported functions.
- Write a small JavaScript hook that intercepts a libc function and logs its arguments.
- Use `frida-trace` to auto-generate handlers for a chosen function and capture live call data.
- Explain how runtime hooking reveals behavior that static analysis misses.

## Environment check
```bash
# Prove Frida CLI + Python bindings are installed
frida --version
frida-trace --version
python3 -c "import frida; print('frida module OK', frida.__version__)"
```
Expected output: three version strings (for example `16.x.x`) on separate lines and `frida module OK 16.x.x`, confirming both the CLI tools and the Python package are present. The CLI version and the Python `frida.__version__` should match, because `frida-trace` and the `frida` module are built from the same release train; a mismatch usually means two installs (apt vs pip) are shadowing each other. Source: Frida — *Installation* (https://frida.re/docs/installation/) and the frida-tools repository (https://github.com/frida/frida-tools).

## Guided walkthrough
1. Build a tiny, inert C target that repeatedly calls `getenv` and `strlen` so we have a safe process to instrument. We use `-O0` so the compiler does **not** inline or optimize away `strlen`/`getenv`; at higher optimization levels the compiler may constant-fold `strlen("hello-frida")` to `11` and never emit a real call, which would leave nothing for Frida to hook. Source: GCC — *Optimize Options* (https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html).
```bash
mkdir -p /tmp/frida-lab && cd /tmp/frida-lab
cat > target.c <<'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    const char *msg = "hello-frida";
    for (int i = 0; i < 1000000; i++) {
        volatile size_t n = strlen(msg);
        (void)getenv("PATH");
        (void)n;
        sleep(1);
    }
    return 0;
}
EOF
gcc -O0 -o target target.c
```
Expected: a compiled binary `target` with no errors.

2. Enumerate the process's loaded modules with a one-off Frida script (spawn + resume). `frida -f` **spawns** the program in a suspended state so your script is installed before any target code runs; `--no-pause` tells Frida to resume the process automatically after the script loads (without it, the process stays paused until you type `%resume`). This spawn-then-resume flow is why hooks reliably catch early calls that an *attach* to an already-running process might miss. Source: Frida — *frida-cli tool* / *Spawning* (https://frida.re/docs/frida-cli/) and *Frida JavaScript API — Process* (https://frida.re/docs/javascript-api/#process).
```bash
cd /tmp/frida-lab
frida -f ./target -l /dev/stdin --no-pause <<'EOF'
Process.enumerateModules().slice(0, 5).forEach(function (m) {
    console.log(m.name + "  base=" + m.base);
});
EOF
```
Expected: Frida spawns `target`, then prints up to five module names such as `target`, `libc.so.6`, and `ld-linux-x86-64.so.2` with base addresses. `Process.enumerateModules()` returns the modules currently mapped into the process; the exact set and order depend on the loader and glibc version on your host, so treat the names above as representative rather than fixed. Source: Frida — *JavaScript API: Process.enumerateModules()* (https://frida.re/docs/javascript-api/#process).

3. Hook `strlen` and log its argument for each call. `Module.getExportByName(null, "strlen")` resolves the address of the exported symbol `strlen` searching **all** loaded modules (the `null` first argument means "any module"), and `Interceptor.attach` installs an inline hook whose `onEnter` callback receives the raw arguments; `args[0]` is the `const char *` pointer, which we dereference with `readCString()`. Source: Frida — *JavaScript API: Module.getExportByName / Interceptor.attach / NativePointer.readCString* (https://frida.re/docs/javascript-api/#module and https://frida.re/docs/javascript-api/#interceptor).
```bash
cd /tmp/frida-lab
frida -f ./target -l /dev/stdin --no-pause <<'EOF'
Interceptor.attach(Module.getExportByName(null, "strlen"), {
    onEnter: function (args) {
        console.log("strlen(\"" + args[0].readCString() + "\")");
    }
});
EOF
```
Expected: repeated lines `strlen("hello-frida")`, proving Frida is intercepting the live libc call and reading its argument. Note the nuance: because glibc itself calls `strlen` internally, you may occasionally see other strings interleaved — the hook observes *every* `strlen` call in the process, not only the one in `main`. That noise is itself a lesson: runtime hooks see all callers, so filtering by call site or argument is often necessary.

4. Auto-generate handlers with `frida-trace` for `getenv`. `frida-trace -i getenv` tells Frida to instrument the exported function `getenv` and scaffold an editable JavaScript handler on disk; you can then edit that handler to log arguments or return values and Frida hot-reloads it. Source: Frida — *frida-trace* (https://frida.re/docs/frida-trace/).
```bash
cd /tmp/frida-lab
timeout 8 frida-trace -f ./target -i getenv
```
Expected: `frida-trace` creates a handler stub under `__handlers__/` for the module that exports `getenv` (for example `__handlers__/libc.so.6/getenv.js`) and streams `getenv` call events to the terminal until the `timeout` kills it after 8 seconds. The exact module directory name reflects the SONAME of your glibc, so it may differ from `libc.so.6` on some systems. Source: Frida — *frida-trace* (https://frida.re/docs/frida-trace/).

## Hands-on exercise
Sample artifact: `exercise/target.c` — a **benign, inert C source file** (no network, no filesystem writes; it only calls `strlen`/`getenv` in a loop and sleeps). It is generated locally, not downloaded, so there is no live malware and no egress.

Generate and hash the sample:
```bash
mkdir -p exercise && cd exercise
cat > target.c <<'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    const char *msg = "hello-frida";
    for (int i = 0; i < 1000000; i++) {
        volatile size_t n = strlen(msg);
        (void)getenv("PATH");
        (void)n;
        sleep(1);
    }
    return 0;
}
EOF
sha256sum target.c
gcc -O0 -o target target.c
```
Task: Compile `target.c`, then use Frida (a script or `frida-trace`) to determine **the exact string value passed to `strlen`** in the running process, and **the environment variable name requested via `getenv`**. Record both answers.

## SOC analyst perspective
Defenders rarely run Frida in production, but they use its findings to build detections. When a malware analyst hooks a runtime-decrypted C2 URL or a `WinExec`/`execve` call with Frida, the resolved indicators (domains, IPs, command lines) become network and process rules.

Concrete detection logic and Security Onion pivots:
- **Extracted C2 domains/IPs → Suricata + Zeek.** Feed each resolved domain into Suricata DNS/HTTP/TLS rules and pivot in Security Onion on Zeek's `dns.log` (query field), `http.log` (host header), and `ssl.log` (SNI); the `conn.log` gives flow tuples for lateral spread hunting. Source: Security Onion docs (https://docs.securityonion.net/) and Zeek log fields (https://docs.zeek.org/en/master/logs/index.html). Specific Zeek query: `index=zeek sourcetype="zeek:dns" query="malicious.example.com"`.
- **Runtime-resolved process spawns → ATT&CK mapping.** Behavior where a decrypted payload calls `execve`/`system` maps to **T1059 — Command and Scripting Interpreter** (https://attack.mitre.org/techniques/T1059/); calls that go straight through native APIs map to **T1106 — Native API** (https://attack.mitre.org/techniques/T1106/). Pivot on process-creation telemetry (e.g., Windows Event ID 4688/Sysmon Event ID 1) with command-line arguments matching Frida-extracted values.  
- **Frida artifacts → Host-based detection.** On Linux, audit suspicious `/proc/$PID/maps` entries for `frida-agent` paths or unexpected thread creation (monitor `fork`/`clone` syscalls targeting existing processes). Windows EDRs can flag `frida-server.exe` or process injection via DLL hollowing (T1055.013). Sources: `proc(5)` man page (https://man7.org/linux/man-pages/man5/proc.5.html); MITRE ATT&CK T1055.013 (https://attack.mitre.org/techniques/T1055/013/).
- **Frida-specific network traffic.** The default `frida-server` control port 27042 leaves TCP connections in netstat/Zeek `conn.log` (uid field can link to process ancestry). Hunt for unusual process-to-port binds via Zeek: `index=zeek sourcetype="zeek:conn" id.resp_p=27042`. Source: Frida — *frida-server* (https://frida.re/docs/frida-server/).  
- **Additional MITRE mappings:**  
  - **T1574.002 — DLL Side-Loading** (when Frida agents masquerade as legitimate DLLs)  
  - **T1620 — Reflective Code Loading** (Frida’s injection mechanism)  
  - **T1055.001 — Process Injection: Dynamic-link Library Injection** (Frida agent injection)  
  - **T1562.001 — Impair Defenses: Disable or Modify Tools** (runtime patching of security checks)  
  Sources: MITRE ATT&CK T1574.002 (https://attack.mitre.org/techniques/T1574/002/), T1620 (https://attack.mitre.org/techniques/T1620/), T1055.001 (https://attack.mitre.org/techniques/T1055/001/), T1562.001 (https://attack.mitre.org/techniques/T1562/001/).

## Attacker perspective
Attackers and red teamers use Frida offensively to bypass client-side protections: hooking certificate-pinning checks, patching license or root/jailbreak detection, dumping decrypted secrets from memory, and instrumenting mobile apps to reverse proprietary protocols.

Concrete TTPs, artifacts, and evasion:
- **Injection technique.** Frida attaches by injecting its agent (a shared library plus an embedded JS runtime) and a thread into the target, mapping to **T1055.001 — Process Injection: Dynamic-link Library Injection** (https://attack.mitre.org/techniques/T1055/001/). The agent appears in `/proc/$PID/maps` as an anonymous mmap region or named library (e.g., `frida-agent-64.so`). Source: Frida — *Home* (https://frida.re/docs/home/); Linux `proc(5)` man page (https://man7.org/linux/man-pages/man5/proc.5.html).
- **Hooking native functions.** Using `Interceptor` to trap libc/OS calls at runtime is **T1106 — Native API** (https://attack.mitre.org/techniques/T1106/). Source: Frida — *JavaScript API: Interceptor* (https://frida.re/docs/javascript-api/#interceptor).
- **Patching security checks.** Overwriting return values or NOPing integrity tests maps to **T1562.001 — Impair Defenses: Disable or Modify Tools** (https://attack.mitre.org/techniques/T1562/001/). Example: hooking `strstr` to suppress detection strings in memory.
- **Artifact locations:**  
  - Linux: `/proc/$PID/maps` shows injected `frida-agent`; `/proc/$PID/task/` lists new threads  
  - Windows: Process Hacker/Process Explorer shows unsigned loaded modules  
  - Network: Default `frida-server` binds to TCP 27042; agents beacon to controller  
  Sources: Frida — *frida-server* (https://frida.re/docs/frida-server/); MITRE ATT&CK T1570 (https://attack.mitre.org/techniques/T1570/).
- **Evasion:**  
  - Rename `frida-server` binary and use non-default ports (`-l 0.0.0.0:PORT`)  
  - Embed Frida Gadget (T1574.001 — DLL Search Order Hijacking)  
  - Obfuscate agent strings (T1027)  
  Source: Frida — *Gadget* (https://frida.re/docs/gadget/); MITRE ATT&CK T1574.001 (https://attack.mitre.org/techniques/T1574/001/).

## Answer key
- The string passed to `strlen` is **`hello-frida`**, revealed by the `strlen` Interceptor hook:
```bash
cd exercise
frida -f ./target -l /dev/stdin --no-pause <<'EOF'
Interceptor.attach(Module.getExportByName(null, "strlen"), {
    onEnter: function (args) { console.log("ARG=" + args[0].readCString()); }
});
EOF
# Expected repeated lines: ARG=hello-frida
```
- The environment variable requested via `getenv` is **`PATH`**, revealed by tracing:
```bash
cd exercise
timeout 8 frida-trace -f ./target -i getenv
# Expected: getenv handler fires; the requested variable is PATH
```
- Sample: `exercise/target.c` sha256 is reproducible from the generator above — run `sha256sum target.c` after creating the file to record the digest for your build (the validator holds the reference digest for the exact bytes shown).  
  **Safe-origin note:** The sample is generated locally from the code provided in this module and is not sourced from any external repository or network location.

## MITRE ATT&CK & DFIR phase
- **T1055.001 — Process Injection: Dynamic-link Library Injection** (Frida injects an instrumentation agent into the target process). https://attack.mitre.org/techniques/T1055/001/
- **T1106 — Native API** (hooking libc / native functions to observe calls). https://attack.mitre.org/techniques/T1106/
- **T1562.001 — Impair Defenses: Disable or Modify Tools** (runtime patching of security checks). https://attack.mitre.org/techniques/T1562/001/
- **T1059 — Command and Scripting Interpreter** (Frida drives targets via JavaScript agents / observed spawns of interpreters). https://attack.mitre.org/techniques/T1059/
- **T1574.002 — DLL Side-Loading** (Frida Gadget masquerading as legitimate DLLs). https://attack.mitre.org/techniques/T1574/002/
- **T1620 — Reflective Code Loading** (Frida’s agent injection mechanism). https://attack.mitre.org/techniques/T1620/
- **T1055 — Process Injection** (Frida injects an instrumentation agent into the target process). https://attack.mitre.org/techniques/T1055/
- **T1027 — Obfuscated Files or Information** (Frida can be used to obfuscate agent strings). https://attack.mitre.org/techniques/T1027/
- **T1574.001 — DLL Search Order Hijacking** (Frida Gadget can be embedded in a target process to bypass security checks). https://attack.mitre.org/techniques/T1574/001/
- DFIR phase: **Examination / Analysis** (dynamic behavioral analysis of a live process during malware examination). Source: NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response* (Collection → Examination → Analysis → Reporting) — https://csrc.nist.gov/publications/detail/sp/800-86/final.


### Essential Commands & Features

Frida’s **Stalker** provides dynamic code coverage by tracing executed instructions, ideal for analyzing obfuscated logic or unpacking routines. Use it to track execution flow in real-time:
```javascript
Interceptor.attach(targetFunc, {
  onEnter: function(args) {
    Stalker.follow(this.threadId, {
      events: { call: true, ret: true },
      onReceive: function(events) {
        console.log(Stalker.parse(events));
      }
    });
  }
});
```
*When to use*: Unpacking malware (e.g., **T1027.002: Obfuscated Files or Information: Software Packing**) or analyzing JIT-compiled code.

For **memory scanning**, `Memory.scan` locates patterns (e.g., encryption keys, injected payloads) in process memory:
```javascript
Memory.scan(ptr("0x100000000"), 0x1000, "dead beef", {
  onMatch: function(address, size) {
    console.log(`Found at ${address}`);
  }
});
```
*When to use*: Detecting **T1622: Debugger Evasion** or extracting runtime artifacts.

For **macOS/iOS targets**, hook Objective-C/Swift APIs to intercept method calls:
```javascript
const { ObjC } = NativePointer;
const className = "NSURL";
const method = "- URLWithString:";
Interceptor.attach(ObjC.classes[className][method].implementation, {
  onEnter: function(args) {
    console.log(`URL: ${ObjC.Object(args[2])}`);
  }
});
```
*When to use*: Monitoring **T1555: Credentials from Password Stores** (e.g., Keychain access).

**Sources**:
- [Frida Stalker Docs](https://frida.re/docs/stalker/)
- [MITRE ATT&CK T1622](https://attack.mitre.org/techniques/T1622/)

### Threat Hunting & Detection Engineering
To detect and hunt threats using Frida tracing, focus on identifying suspicious behavior related to techniques such as [T1218](https://attack.mitre.org/techniques/T1218) - "Signed Binary Proxy Execution" and [T1484](https://attack.mitre.org/techniques/T1484) - "Domain Policy Modification". Monitor Windows Event IDs 4688 and 4703 for signs of executable file creation and modification, which could indicate an adversary attempting to proxy execute a binary. Analyze the `CommandLine` field in these logs to identify suspicious command-line arguments. Additionally, inspect DNS query logs for unusual domain name resolutions, which may indicate an attempt to modify domain policies. Threat hunters can pivot on these findings by examining network traffic captures using Zeek or Suricata, focusing on HTTP requests to unknown or newly registered domains. For more information on threat hunting and detection engineering, visit the [Cybersecurity and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) and [NSA Cybersecurity](https://www.nsa.gov/what-we-do/cybersecurity/) websites.


### How It Works: Internals & Mechanics

Frida’s tracing capabilities rely on **dynamic instrumentation**, where it injects a **custom agent script** into the target process to intercept and log function calls. At its core, Frida uses **Stalker**, a just-in-time (JIT) code tracing engine that dynamically recompiles executed instructions to insert hooks. Stalker operates by:
1. **Thread-aware tracing**: It tracks execution per thread, using a **shadow stack** to manage call contexts and avoid race conditions in multi-threaded environments.
2. **Dynamic recompilation**: When a function is called, Stalker recompiles its basic blocks (sequences of instructions) on-the-fly, inserting callbacks to the agent script. This allows granular tracing of **register states**, **memory accesses**, and **control flow** without static analysis.
3. **Custom agent scripts**: These scripts define hooks (e.g., `Interceptor.attach()`) and leverage Frida’s **JavaScript runtime** to manipulate or log data. For example, an agent can trace **T1003.001 (OS Credential Dumping: LSASS Memory)** by hooking `NtReadVirtualMemory` and logging buffer contents, or **T1601.001 (Modify System Image: Patch System Image)** by intercepting `WriteProcessMemory` to detect unauthorized modifications.

Frida’s flexibility stems from its **V8-based runtime**, enabling real-time interaction with traced processes. However, Stalker’s overhead can impact performance, particularly in CPU-bound or latency-sensitive applications. For advanced use cases, agents must explicitly handle **thread synchronization** (e.g., via `Mutex`) and **dynamic function resolution** (e.g., `Module.findExportByName`) to avoid crashes or missed events.

**Sources**:
- [Frida Stalker Internals (Official GitHub Wiki)](https://github.com/frida/frida-gum/wiki/Stalker)
- [MITRE ATT&CK: T1003.001 & T1601.001 (MITRE Engenuity)](https://mitre-engenuity.org/)

### Adversary Emulation & Red-Team Perspective

From an adversary’s perspective, Frida is a powerful tool for dynamic instrumentation, enabling attackers to bypass security controls, extract sensitive data, or manipulate application behavior in real time. A common tactic is **process injection (T1055.002: Portable Executable Injection)**, where Frida is used to inject malicious scripts into running processes, evading detection by operating within legitimate memory spaces. Attackers may also leverage Frida to **hook cryptographic functions (T1600: Weaken Encryption)**, intercepting plaintext data before encryption or after decryption, such as session tokens or credentials.

Concrete TTPs include:
- **Runtime manipulation**: Altering function arguments or return values to bypass authentication checks (e.g., disabling SSL pinning in mobile apps).
- **Memory scraping**: Dumping process memory to extract secrets, such as API keys or passwords, using Frida’s JavaScript API.
- **Evasion**: Frida’s dynamic nature complicates static analysis, and attackers may obfuscate scripts or use **indirect command execution (T1105: Ingress Tool Transfer)** to fetch payloads at runtime.

Artifacts left behind include:
- Frida’s server process (`frida-server`) running on the target system.
- Unusual network connections to Frida’s default port (27042) or custom ports.
- Modified memory regions in injected processes, detectable via EDR/XDR tools.

Evasion considerations:
- Use Frida’s `--no-pause` flag to avoid detection by process monitoring tools.
- Employ script obfuscation (e.g., via `frida-compile`) to evade signature-based detection.
- Limit Frida’s runtime footprint by detaching after execution or using short-lived scripts.

**Sources**:
- [MITRE ATT&CK: T1055.002](https://attack.mitre.org/techniques/T1055/002/)
- [Red Team Notes: Frida for Offensive Security](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-dll-via-fridas-dynamic-instrumentation)

## Sources
Claim → source mapping (all URLs are official/authoritative):

- Frida overview, agent-injection model, spawn/resume behavior — Frida *Home / Modes of operation*: https://frida.re/docs/home/
- Recommended install (`pip install frida-tools`); CLI vs Python bindings versioning — Frida *Installation*: https://frida.re/docs/installation/ ; frida-tools repo: https://github.com/frida/frida-tools
- REMnux ships Frida (tool listing) — REMnux *Discover the tools*: https://docs.remnux.org/discover-the-tools/
- `frida -f` spawn, `--no-pause`/`%resume` semantics — Frida *frida-cli*: https://frida.re/docs/frida-cli/
- `Process.enumerateModules`, `Module.getExportByName`, `Interceptor.attach`, `NativePointer.readCString` — Frida *JavaScript API*: https://frida.re/docs/javascript-api/
- `frida-trace -i`, `__handlers__/` scaffolding and hot-reload — Frida *frida-trace*: https://frida.re/docs/frida-trace/
- `frida-server` default control port 27042 and `-l` bind option — Frida *frida-server*: https://frida.re/docs/frida-server/
- Frida *Gadget* (evasion / no separate server) — Frida *Gadget*: https://frida.re/docs/gadget/
- `-O0` prevents inlining/constant-folding of `strlen`/`getenv` — GCC *Optimize Options*: https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
- `/proc/[pid]/maps` and `/proc/[pid]/task` injection artifacts — Linux `proc(5)` man page: https://man7.org/linux/man-pages/man5/proc.5.html
- MITRE ATT&CK T1055.001 Process Injection — https://attack.mitre.org/techniques/T1055/001/
- MITRE ATT&CK T1106 Native API — https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK T1562.001 Impair Defenses: Disable or Modify Tools — https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1574.002 DLL Side-Loading — https://attack.mitre.org/techniques/T1574/002/
- MITRE ATT&CK T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1574.001 DLL Search Order Hijacking — https://attack.mitre.org/techniques/T1574/001/
- Security Onion (Suricata/Zeek/Elastic pivots) — Security Onion Documentation: https://docs.securityonion.net/
- Zeek log reference (dns.log, http.log, ssl.log, conn.log) — https://docs.zeek.org/en/master/logs/index.html
- DFIR phase model (Examination/Analysis) — NIST SP 800-86: https://csrc.nist.gov/publications/detail/sp/800-86/final
- SANS FOR610 Reverse-Engineering Malware course overview — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- Windows Event IDs for process creation — Microsoft *4688 Event*: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- Sysmon Event ID 1 — Sysinternals *Sysmon Documentation*: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## Related modules
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); pair runtime hooking with memory-image analysis of injected agents.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); turn Frida-extracted runtime IOCs into hunting signatures.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); complement live process analysis with disk-artifact forensics.
- [Plaso super-timeline deep-dive](../23-plaso-supertimeline/README.md) -- same learning path (Deep-dives); place dynamic-analysis findings on a forensic timeline.

<!-- cyberlab-enriched: v2 -->
- https://frida.re/docs/stalker/
- https://attack.mitre.org/techniques/T1622/
- https://attack.mitre.org/techniques/T1218
- https://attack.mitre.org/techniques/T1484
- https://www.cisa.gov/
- https://www.nsa.gov/what-we-do/cybersecurity/

<!-- cyberlab-enriched: v3 -->
- https://github.com/frida/frida-gum/wiki/Stalker
- https://mitre-engenuity.org/
- https://attack.mitre.org/techniques/T1055/002/
- https://www.ired.team/offensive-security/code-injection-process-injection/injecting-dll-via-fridas-dynamic-instrumentation

<!-- cyberlab-enriched: v4 -->
