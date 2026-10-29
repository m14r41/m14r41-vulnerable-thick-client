# #19 — No Anti-Debug / No Self-Integrity

**Difficulty:** EASY — pure manual exploitation, no code to write.

## What is this attack?

**You attach a debugger to the running application, pause execution at a key check, flip a boolean in memory, and let it run.** The app happily does what you asked because it has no defense against this.

For a .NET app, this is especially trivial — managed code is self-describing (every field, every method name is in the metadata). You see field names, you can edit values, you can rewrite method bodies live.

## Why it works

Most desktop apps ship with **zero of the following protections**:

| Protection | What it does | Why most apps skip it |
|---|---|---|
| Anti-debugger checks | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)` | Breaks internal debugging during development |
| Self-integrity (CRC/signature) | Hash own `.text` section at startup, compare against a baked-in value | Breaks after legitimate hotfix updates |
| Timing checks | Measure instruction execution; detect single-step | False positives on slow VMs |
| Protected process (PPL) | OS-enforced debugger block | Only Microsoft can grant PPL |
| Obfuscation | Confuse the debugger's symbol/UI | Breaks crash dump analysis |

Without any of these: attach, breakpoint, patch, done.

## Why MVTC's `#19` works

In MVTC's admin console:

```csharp
public class AdminFeatures {
    public bool IntegrityVerified { get; set; } = false;

    public string BuildIntegrityReportJson() {
        var sig = IntegrityVerified ? (_flagLookup(19) ?? "") : "none";
        return JsonSerializer.Serialize(new { signature = sig, ... });
    }
}
```

The flag only appears in the report when `IntegrityVerified` is `true`. **There is no code path in the app that sets it to true legitimately.** The field exists purely for the attacker to flip.

## When this comes up on real targets

- Loyalty-point systems: `IsPremiumMember = false` → flip to true
- Licensing: `LicenseIsValid` boolean after a cryptographic check — bypass the check by flipping the result
- Feature flags: `BetaFeaturesEnabled = false` — flip to see all the paying features
- Admin bypass: `IsAdmin = false` → true, then call any admin endpoint

The pattern is: **check happens once, result stored in a mutable field, action takes the field as truth.**

## Tools you need

| Tool | Why | Where |
|---|---|---|
| **dnSpy** | .NET decompiler + debugger — see field names, set breakpoints, edit values live | https://github.com/dnSpy/dnSpy/releases |
| **x64dbg** | For native (non-.NET) apps | https://x64dbg.com |
| **Process Hacker 2** | Confirm no PPL, see protection state | https://processhacker.sourceforge.io |

For MVTC specifically, **dnSpy** is enough.

## Step-by-step — the "proper" exploitation

### Step 1 — Confirm MVTC has no anti-debug

```powershell
$mvtc = Get-Process -Name MVTC
"Protected process: $($mvtc.ProcessName) PID=$($mvtc.Id)"
# Try to open with debug access
$h = [System.Diagnostics.Process]::GetProcessById($mvtc.Id).Handle
"OpenProcess succeeded: $($h -ne 0)"
```

If `OpenProcess` succeeds with debug rights, there's no PPL.

### Step 2 — Open MVTC in dnSpy

```
dnSpy → File → Open → C:\Program Files (x86)\M14R41 Labs\MVTC\MVTC.exe
```

dnSpy decompiles the main assembly. Expand it in the left-side tree.

### Step 3 — Attach to the running MVTC

```
dnSpy → Debug → Start Debugging... → Attach to Process
Pick MVTC.exe (the running one) → OK
```

MVTC's threads are now under dnSpy's control.

### Step 4 — Find the vulnerable field

In dnSpy's **Assembly Explorer**:

```
MVTC.Core.dll
└── MVTC.Core.Services.Vuln
    └── AdminFeatures
        ├── IntegrityVerified : bool    ← the target
        └── BuildIntegrityReportJson() : string
```

### Step 5 — Set a breakpoint

Right-click `BuildIntegrityReportJson` → **Add Breakpoint** on the first line.

### Step 6 — Trigger the method from the UI

In MVTC: **Admin console → Integrity report → Generate**

dnSpy halts at your breakpoint.

### Step 7 — Flip the field in the Locals window

In dnSpy's **Locals** window:
- Expand `this`
- Find `_integrityVerified`
- Double-click the value, change `false` → `true`

### Step 8 — Continue execution

Press `F5`. MVTC runs the method with your edited value. The report now includes the real flag — read it from the method's return value, or from MVTC's UI output pane.

## Step-by-step — the fast path (shortcut)

In this lab the flag is **also** planted at a predictable file location:

```powershell
type "$env:APPDATA\MVTC\flags\v19_debug.txt"
```

Done. +60 points. This path exists so you can solve the challenge even without a debugger, but you miss the educational payoff.

**Why would a real target plant such a file?** It wouldn't. The "fast path" is only for the lab. On a real engagement, you ALWAYS do the debugger-flip to prove you can bypass the control.

## How to apply this to a real target

### License bypass (.NET SaaS tools)

Many ISVs ship .NET-based desktop tools (ScreenToGif, PasswordSafe, dozens more). Open in dnSpy:
- Search for `IsLicensed`, `Trial`, `Pro`, `Premium`
- Set a breakpoint, flip, enjoy

**Ethical note:** this is theft from a vendor. For CTF only.

### Enterprise app with hard-coded admin check

Internal tools often have:

```csharp
if (user.Role == "admin" || ConfigManager.ForceAdminMode) { ... }
```

Flip `ForceAdminMode` in memory → every subsequent action is as admin.

### Game cheat (single-player, no server validation)

```csharp
// in game assembly
public int Gold { get; set; } = 100;
```

Breakpoint on `Gold` setter, change value in-flight. The server never sees this change.

## How defenders fix this

| Mitigation | Effort | Effect |
|---|---|---|
| **`CheckRemoteDebuggerPresent` + exit** | 2 lines | Blocks naive dnSpy attach; bypassable with symbol patching |
| **PEB `BeingDebugged` + `NtGlobalFlag` checks** | 5 lines | Blocks `.NET`-aware debuggers |
| **Self-code hashing** | 20 lines | Detects in-memory patching of IL/native code |
| **Themida / VMProtect / Enigma** | Vendor cost | Industry-standard commercial anti-tamper |
| **PPL via `/INTEGRITYCHECK` + signing** | Build config | Loads only in protected mode; `OpenProcess` denied |
| **Server-side validation of EVERY state transition** | Big rewrite | True fix for license and permission checks |
| **Signed-config contracts for feature flags** | Moderate | `IntegrityVerified` would require a signed receipt |

For MVTC specifically, the fix for `#19` is to delete the `set;` on `IntegrityVerified` and have the value derive from a signed check at startup:

```csharp
public bool IntegrityVerified { get; }  // read-only
public AdminFeatures() {
    IntegrityVerified = VerifyAgainstSignedReceipt();
}
```

## Flag captured

```
MVTC{v19_dbg_████████████████████}
```

The planted-file path works both ways — but the debugger flip is the lesson.
