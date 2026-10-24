using System.Runtime.Versioning;
using Microsoft.Win32;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #10 - CWE-250 - Privilege held in a user-writable location.
/// Reads the role from HKCU first (user-writable), then falls back to HKLM.
/// Anyone can set <c>HKCU\SOFTWARE\M14R41 Labs\MVTC\role = admin</c>.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #10): never trust a privilege-bearing value stored
///   under HKCU. The authoritative role must come from the backend (via a
///   server-signed token) or from an LSA-brokered subject lookup.
/// </remarks>
public static class RoleProvider
{
    public const string DefaultRole = "user";

    public static string CurrentRole { get; private set; } = DefaultRole;

    public static void Reload()
    {
        if (!OperatingSystem.IsWindows()) return;
        CurrentRole = ReadWindows();
    }

    [SupportedOSPlatform("windows")]
    private static string ReadWindows()
    {
        try
        {
            using var hkcu = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\M14R41 Labs\MVTC");
            var fromUser = hkcu?.GetValue("role") as string;
            if (!string.IsNullOrWhiteSpace(fromUser)) return fromUser;
        }
        catch { }
        try
        {
            using var hklm = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\M14R41 Labs\MVTC");
            var fromMachine = hklm?.GetValue("role") as string;
            if (!string.IsNullOrWhiteSpace(fromMachine)) return fromMachine;
        }
        catch { }
        return DefaultRole;
    }
}
