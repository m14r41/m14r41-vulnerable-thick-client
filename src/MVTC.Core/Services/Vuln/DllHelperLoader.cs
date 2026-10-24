using System.Runtime.InteropServices;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #1 - CWE-427 - DLL search-order hijack.<br/>
/// VULN: #7 - CWE-427 - PATH / SxS preload.<br/>
/// LoadLibrary of a bare name goes through the DLL search order: current
/// directory, system dirs, PATH. An attacker who can drop
/// <c>AppHelper.dll</c> or <c>UpdateHelper.dll</c> in any writable entry on
/// that path hijacks the helper load. If the hijacked DLL executes code in
/// <c>DllMain</c>, it runs inside the MVTC process.
/// </summary>
/// <remarks>
///   SECURE FIX (writeups #1 / #7): call <c>LoadLibraryEx</c> with
///   <c>LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR</c>,
///   use the full install path, and reject unsigned DLLs.
/// </remarks>
public static class DllHelperLoader
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr hModule);

    public static (bool Loaded, string Error) TryLoadBareName(string name)
    {
        // VULN: bare name goes through the DLL search order.
        var h = LoadLibraryW(name);
        if (h == IntPtr.Zero)
            return (false, $"LoadLibrary('{name}') failed; last error {Marshal.GetLastWin32Error()}");
        FreeLibrary(h);
        return (true, "");
    }
}
