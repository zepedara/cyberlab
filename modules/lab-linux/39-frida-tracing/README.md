# 39 * Frida dynamic instrumentation -- LAB-LINUX

## Overview (plain language)
Frida is a "dynamic instrumentation" toolkit. In plain terms, it lets you watch a running program from the inside while it is executing, and even change what it does on the fly. Instead of only reading a program's code, you can attach to a live process, print out which functions it calls, see the arguments passed to them, and read return values — all without recompiling the program. Analysts use Frida to unmask malware that decrypts strings or builds network requests only at runtime, so the interesting behavior never appears in the static file. Think of it like putting sensors and probes on machinery while it runs, rather than staring at a blueprint.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Frida | apt install python3-frida (or pip install frida-tools) | Dynamic instrumentation: attach to/spawn a process and hook functions at runtime to observe or modify behavior |

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
Expected output: three version strings (for example `16.x.x`) on separate lines and `frida module OK 16.x.x`, confirming both the CLI tools and the Python package are present.

## Guided walkthrough
1. Build a tiny, inert C target that repeatedly calls `getenv` and `strlen` so we have a safe process to instrument.
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

2. Enumerate the process's loaded modules with a one-off Frida script (spawn + resume).
```bash
cd /tmp/frida-lab
frida -f ./target -l /dev/stdin --no-pause <<'EOF'
Process.enumerateModules().slice(0, 5).forEach(function (m) {
    console.log(m.name + "  base=" + m.base);
});
EOF
```
Expected: Frida spawns `target`, then prints up to five module names such as `target`, `libc.so.6`, and `ld-linux-x86-64.so.2` with base addresses.

3. Hook `strlen` and log its argument for each call.
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
Expected: repeated lines `strlen("hello-frida")`, proving Frida is intercepting the live libc call and reading its argument.

4. Auto-generate handlers with `frida-trace` for `getenv`.
```bash
cd /tmp/frida-lab
timeout 8 frida-trace -f ./target -i getenv
```
Expected: `frida-trace` creates a `__handlers__/libc.so.6/getenv.js` file and streams `getenv` call events to the terminal until the timeout.

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
Defenders rarely run Frida in production, but they use its findings to build detections. When a malware analyst hooks a runtime-decrypted C2 URL or a `WinExec`/`execve` call with Frida, the resolved indicators (domains, IPs, command lines) become network and process rules. In Security Onion those map directly: extracted C2 domains feed Suricata/Zeek DNS and HTTP alerts, while the observed process-spawn behavior aligns with MITRE ATT&CK T1059 (Command and Scripting Interpreter) and T1106 (Native API). Frida output effectively converts opaque runtime behavior into concrete, hunt-ready IOCs the SOC can pivot on across Kibana and Zeek logs.

## Attacker perspective
Attackers and red teamers use Frida offensively to bypass client-side protections: hooking certificate-pinning checks, patching license or root/jailbreak detection, dumping decrypted secrets from memory, and instrumenting mobile apps to reverse proprietary protocols. This aligns with MITRE ATT&CK T1562.001 (Impair Defenses) and T1055 (Process Injection), since Frida injects an agent thread into the target. Artifacts left behind include an injected `frida-agent` mapping in `/proc/<pid>/maps`, an unexpected listening port when using `frida-server`, spawned gadget libraries, and anomalous child threads — all detectable by a defender inspecting process memory maps and loaded modules.

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

## MITRE ATT&CK & DFIR phase
- **T1055 — Process Injection** (Frida injects an instrumentation agent into the target process).
- **T1106 — Native API** (hooking libc / native functions to observe calls).
- **T1562.001 — Impair Defenses: Disable or Modify Tools** (runtime patching of security checks).
- **T1059 — Command and Scripting Interpreter** (Frida drives targets via JavaScript agents).
- DFIR phase: **Examination / Analysis** (dynamic behavioral analysis of a live process during malware examination).

## Sources
- Frida official documentation — https://frida.re/docs/home/
- Frida JavaScript API (Interceptor, Module, Process) — https://frida.re/docs/javascript-api/
- REMnux tool listing (Frida — Dynamic/Shellcode) — https://docs.remnux.org/discover-the-tools/
- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1106 Native API — https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK T1562.001 Impair Defenses — https://attack.mitre.org/techniques/T1562/001/
- SANS FOR610 Reverse-Engineering Malware course overview — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/