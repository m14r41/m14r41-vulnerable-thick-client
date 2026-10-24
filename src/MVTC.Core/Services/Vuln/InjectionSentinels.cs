namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #13-#18 - Each process-injection technique reads its OWN distinct
/// in-memory sentinel string and reports that sentinel as proof-of-injection.
/// The sentinels live in long-lived static readonly fields initialized once
/// at startup from <c>progress.db</c>, so a successful DLL / shellcode /
/// managed-assembly injection into <c>MVTC.exe</c> can read the correct
/// address and exfiltrate it.
/// </summary>
/// <remarks>
///   #13 CreateRemoteThread + LoadLibrary → <see cref="FlagForCreateRemoteThread"/><br/>
///   #14 APC injection                     → <see cref="FlagForApc"/><br/>
///   #15 Process hollowing                 → <see cref="FlagForHollowing"/><br/>
///   #16 Reflective / manual-map DLL       → <see cref="FlagForReflective"/><br/>
///   #17 .NET Assembly.Load / AppDomain    → <see cref="FlagForDotNetAssembly"/><br/>
///   #18 Thread hijacking                  → <see cref="FlagForThreadHijack"/><br/>
///   The intent is NOT to make them easy to grep for; a real injection chain
///   has to find them in memory via known marker prefixes (e.g. "MVTC{v13").
/// </remarks>
public static class InjectionSentinels
{
    private static string _crt = "";
    private static string _apc = "";
    private static string _hol = "";
    private static string _ref = "";
    private static string _net = "";
    private static string _thj = "";

    public static void Initialize(Func<int, string?> flagLookup)
    {
        _crt = flagLookup(13) ?? "";
        _apc = flagLookup(14) ?? "";
        _hol = flagLookup(15) ?? "";
        _ref = flagLookup(16) ?? "";
        _net = flagLookup(17) ?? "";
        _thj = flagLookup(18) ?? "";
    }

    public static string FlagForCreateRemoteThread => _crt;
    public static string FlagForApc                => _apc;
    public static string FlagForHollowing          => _hol;
    public static string FlagForReflective         => _ref;
    public static string FlagForDotNetAssembly     => _net;
    public static string FlagForThreadHijack       => _thj;
}
