# MVTC.Installer - MSI + Burn bootstrapper

**Created by Madhurendra Kumar (M14R41) · M14R41 Labs · © 2026**

## Build

Requires the WiX Toolset v4+ (`dotnet tool install --global wix`).

```powershell
# Prepare Payload\ with the published .NET output + native DLLs:
powershell -File scripts\build.ps1 -Package

# Compile:
wix build src\MVTC.Installer\Package.wxs -o build\installer\MVTC-Setup.msi
wix build src\MVTC.Installer\Bundle.wxs  -o build\installer\MVTC-Setup.exe

# Emit SHA-256 hashes for publication:
Get-FileHash build\installer\MVTC-Setup.msi,build\installer\MVTC-Setup.exe -Algorithm SHA256
```

## Deliberately unsigned

See challenge **#5 (missing binary protections)** - the Setup.exe / .msi are
unsigned on purpose. Hashes are published alongside each release.
