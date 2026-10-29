# Process Injection — Simple Writeups

Seven process-injection techniques, solved end-to-end against MVTC, written for someone who wants to understand the concepts enough to find and exploit them on real targets.

Each writeup covers:

- **What is this attack** — in plain English
- **Why it works** — the Windows internals making it possible
- **When attackers use it** — real-world scenarios
- **Tools you need** — exact names + download links
- **Step-by-step** — code, build commands, run commands
- **How to apply to a real target** — ways this exact chain shows up outside the lab
- **How defenders fix it** — mitigations an engineer should enable

## Order of difficulty (recommended learning path)

| Order | # | Technique | Difficulty | Prerequisites |
|---|---|---|---|---|
| 1 | 19 | No anti-debug | EASY | dnSpy only, no coding |
| 2 | 13 | CreateRemoteThread + LoadLibrary | EASY | MSVC |
| 3 | 14 | APC injection | EASY | MSVC, done #13 |
| 4 | 17 | .NET Assembly.Load | MEDIUM | dnSpy + .NET SDK |
| 5 | 18 | Thread hijacking | MEDIUM | MSVC, done #13-15 |
| 6 | 15 | Process hollowing | HARD | MSVC + x64 assembly basics |
| 7 | 16 | Reflective / manual-map DLL | HARD | Done #13 + PE format knowledge |

## Mental model

All seven techniques solve the same problem: **get code execution inside another process**.

They differ in **how noisy they are** and **what defenses they bypass**:

```
            new thread?   LoadLibrary?   file on disk?   DLL in PEB?
#13 CRT       YES           YES            YES            YES
#14 APC       no            YES            YES            YES
#15 hollow    no (hijack)   YES            YES            YES
#18 hijack    no            YES            YES            YES
#17 .NET      no (CLR)      no             may            MANAGED
#16 reflect   no (RWX)      NO             NO             NO
#19 debug     n/a           n/a            n/a            n/a
```

A newer defender setup catches the earlier rows via ETW/EDR. The lower-noise rows (#16, #19) bypass most of today's standard product tooling.

## Reusable building blocks

Every injector in this folder follows the same four-step shape — only the trigger changes:

1. `OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)` — handle to victim
2. `VirtualAllocEx(hProc, …, PAGE_READWRITE)` — scratch buffer in victim
3. `WriteProcessMemory(hProc, buf, data, len, nullptr)` — plant data
4. **Trigger** — the one line that differs between techniques:
   - #13 → `CreateRemoteThread(…, LoadLibraryA, buf, …)`
   - #14 → `QueueUserAPC(LoadLibraryA, hThread, buf)` on every thread
   - #15 → `CreateProcessA(…, CREATE_SUSPENDED, …)` then stub + `ResumeThread`
   - #16 → copy mapped PE in, `CreateRemoteThread(entryExport)`
   - #17 → native stub → `ICLRRuntimeHost::ExecuteInDefaultAppDomain`
   - #18 → `SuspendThread → SetThreadContext → ResumeThread`
   - #19 → not injection; attach debugger and flip a boolean

Learn one, you've learned most of the rest.

## Flag format

Each challenge yields a flag like:

```
MVTC{v<challenge>_<technique>_<16-char random>}
```

Example: `MVTC{v13_crt_████████████████████}`

The random suffix is masked in these writeups. Your lab instance will produce different suffixes — same format.

## For your real-world testing

Each writeup's **"How to apply this to a real target"** section lists authorized scenarios where this exact technique is useful:

- Browser renderer injection (reading cookies/tokens)
- Enterprise .NET app bypasses
- Red-team pivot patterns
- Game cheating patterns

**Legal reminder:** these writeups are for authorized security testing in isolated VMs, scope-approved pentests, CTF competitions, and your own systems. Running any of this against something you don't own or lack explicit authorization for is a crime in most jurisdictions.

## Files

| File | Topic |
|---|---|
| [13-create-remote-thread.md](13-create-remote-thread.md) | CreateRemoteThread + LoadLibrary |
| [14-apc-injection.md](14-apc-injection.md) | APC injection (QueueUserAPC) |
| [15-process-hollowing.md](15-process-hollowing.md) | Process hollowing (soft variant) |
| [16-reflective-dll.md](16-reflective-dll.md) | Reflective / manual-map DLL |
| [17-dotnet-assembly-load.md](17-dotnet-assembly-load.md) | .NET Assembly.Load injection |
| [18-thread-hijacking.md](18-thread-hijacking.md) | Thread hijacking (SetThreadContext) |
| [19-no-anti-debug.md](19-no-anti-debug.md) | No anti-debug / debugger-flip |

Related: payload binaries (pop-calc, reverse-shell) at **https://github.com/m14r41/PayloadEverything/tree/main/thick-client/payload** — drop-in replacements for the `flag_reader.dll` to demonstrate real impact once you've proven the injection chain works.
