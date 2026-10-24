# MVTC.Helper.Native (AppHelper.dll)

**Created by Madhurendra Kumar (M14R41) · M14R41 Labs · © 2026**

Benign helper DLL referenced by the managed app via a **bare name** so that
challenges **#1 (DLL hijacking)** and **#7 (PATH / SxS preload)** are
exercisable: an attacker-provided DLL on the search path hijacks the load.

## Build

Requires MSVC Build Tools (or Visual Studio 2022) with the Windows SDK:

```powershell
msbuild src\MVTC.Helper.Native\MVTC.Helper.Native.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output lands at `build\native\Release\AppHelper.dll`.

## Deliberately NOT part of `M14R41.MVTC.sln`

Because this requires MSVC rather than the .NET SDK, the .vcxproj is left out
of the top-level solution. `scripts\build.ps1` builds it as a separate step
when MSVC is detected.
