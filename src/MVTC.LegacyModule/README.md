# MVTC.LegacyModule - intentionally insecure native "legacy file converter"

**Created by Madhurendra Kumar (M14R41) · M14R41 Labs · © 2026**

Hosts challenges **#20 (stack BOF)**, **#21 (format string)**, **#22 (UAF /
double free)**, and **#23 (integer overflow)**. Every memory-safety mitigation
is deliberately off in `MVTC.LegacyModule.vcxproj`:

| Flag | Setting | Why |
|------|---------|-----|
| `/GS-` | buffer-overrun check disabled | #20 |
| `BufferSecurityCheck=false` | same | #20 |
| `/DYNAMICBASE:NO` (RandomizedBaseAddress=false) | no ASLR | #5, #20 |
| `/NXCOMPAT:NO` (DataExecutionPrevention=false) | shellcode on stack is runnable | #5, #20 |
| `/SAFESEH:NO` (ImageHasSafeExceptionHandlers=false) | SEH chain is attacker-friendly | #20 |
| `/sdl-` | relaxed SDL banned-API warnings | #20, #21 |

## Build

Requires MSVC Build Tools or Visual Studio 2022 with the Windows SDK:

```powershell
msbuild src\MVTC.LegacyModule\MVTC.LegacyModule.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `build\native\Release\MVTC.LegacyModule.dll`. Verify the mitigations
with Microsoft's `winchecksec`:

```powershell
winchecksec build\native\Release\MVTC.LegacyModule.dll
```

Expected: ASLR / DEP / SafeSEH / /GS all disabled - see writeup **#5**.

## Not part of `M14R41.MVTC.sln`

Build via `scripts\build.ps1` which runs the native build after the .NET
build if MSVC is on the PATH.
