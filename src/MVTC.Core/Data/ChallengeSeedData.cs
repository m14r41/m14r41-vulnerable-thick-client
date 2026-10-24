using MVTC.Core.Models;
using MVTC.Core.Secrets;

namespace MVTC.Core.Data;

/// <summary>
/// The 40 challenges that ship pre-seeded in <c>progress.db</c>. Points total 3950.
/// Flag <i>plaintexts</i> are generated at seed time and dropped into the lab in later
/// phases; only the SHA-256 hashes live in the DB. A challenge may pin a fixed flag
/// (e.g. #26, where the flag has to live as a string literal inside the compiled binary).
/// </summary>
public static class ChallengeSeedData
{
    public sealed record Seed(
        int VulnNo,
        string Title,
        string Category,
        string Tier,
        int Points,
        string Cwe,
        string Slug,
        string PrereqIds,
        string WriteupPath,
        string? HardcodedFlag = null)
    {
        /// <summary>One-sentence hint shown in the Flag console (no spoilers).</summary>
        public string Hint =>
            VulnNo switch
            {
                1  => "A helper DLL is loaded by bare name. Drop a crafted copy where the Windows loader resolves it before the install dir.",
                2  => "The service's binary path is registered a particular way. Query it with sc or wmic.",
                3  => "icacls + sc sdshow + AccessChk. One of those three shows a DACL that shouldn't be there.",
                4  => "Who can write to C:\\Program Files\\M14R41 Labs\\MVTC\\? Replace a module and rerun.",
                5  => "Run winchecksec against the native DLLs. The flag emerges from exploiting what's not there.",
                6  => "The service exposes a verb that reads a file it alone should be able to open. Call it as a non-admin.",
                7  => "Same mechanism as #1 but the resolution falls through to a different search-order entry.",
                8  => "Autorun locations writable to a plain user. HKCU Run, Startup, scheduled tasks.",
                9  => "OleViewDotNet lists a CLSID with AccessPermission wide open.",
                10 => "A role string drives what the admin console will show you. It lives in a key you can write.",
                11 => "A client-side bool blocks the sealed vault. Flip it where it lives in memory.",
                12 => "A race between a check and an open against a path you can rename or symlink.",
                13 => "The host keeps a per-technique sentinel string in a long-lived managed field. Classic CreateRemoteThread -> LoadLibrary gets you code exec.",
                14 => "APC injection - queue your DLL via QueueUserAPC against an alertable thread.",
                15 => "Hollow the suspended MVTC.exe and resume into your own image.",
                16 => "Map a DLL without touching LoadLibrary. See Stephen Fewer's reflective loader.",
                17 => "The host has a plugin / assembly load surface. A static constructor is enough.",
                18 => "SetThreadContext on an existing worker thread to redirect Rip into your shellcode.",
                19 => "An integrity report refuses to sign when a bool is false. Flip the bool in a debugger.",
                20 => "Legacy File Converter calls into a native function that strcpy's into a 128-byte stack buffer.",
                21 => "LegacyLog passes caller text straight to printf. Pick your format spec.",
                22 => "OpenLegacyProject + CloseLegacyProject leave a dangling pointer. Reclaim the slab.",
                23 => "AllocLegacyPages multiplies a 32-bit count by sizeof(Page). Pick a count that wraps.",
                24 => "A ciphertext lives in MVTC.db Config.FlagCipher. The key is in the binary, config.xml, HKLM, process memory, and the audit log.",
                25 => "A plaintext credential section exists in a config file this app writes on disk.",
                26 => "dnSpy on MVTC.Core.dll. Look for an unusually-named constant.",
                27 => "ProcDump the running process, strings the dump, grep for the flag prefix.",
                28 => "audit.log leaks a recovery token at startup when verbose logging is on.",
                29 => "A certain file extension dropped under the Startup folder triggers the autorun scanner. Watch the audit log.",
                30 => "Zip entry name with .. escapes the extraction directory.",
                31 => "The help viewer accepts arbitrary paths. A text file renamed to .chm (or any readable file) comes back as content.",
                32 => "The report viewer concatenates a user path onto the reports root without normalization.",
                33 => "The state importer uses Newtonsoft with TypeNameHandling.All. Craft a gadget that returns a readable string.",
                34 => "Directory search is string-formatted into SQL. UNION SELECT.",
                35 => "Ping passes host straight to cmd /c. Shell separators work.",
                36 => "XML config import resolves external entities. file:/// in an entity.",
                37 => "Vault pipe accepts verbs from any caller. Export a service key - intercept the pipe traffic to read it.",
                38 => "The update manifest is served over plain HTTP. The flag is in a plausible-looking manifest field - Wireshark loopback or curl against /manifest.json.",
                39 => "Backend /login response includes a secure_token. The client UI redacts it; the HTTP body does not. Intercept with Burp or Wireshark.",
                40 => "A hidden hotkey exists. Something that looks like a diagnostic feature a developer forgot to #ifdef out.",
                41 => "The login endpoint has no throttling. Fail the admin login enough times in a row - the audit log notices.",
                42 => "This client supports a silent-login CLI mode. Discover the switch (dnSpy on MVTC.exe), then watch Task Manager or `tasklist /v` while it runs.",
                43 => "There's a 'Follow link' feature somewhere that happily opens any URL - including file:// and others.",
                44 => "Something in Assets copies to the clipboard and never clears. Paste it somewhere.",
                45 => "In Settings → Configuration there's a 'Debug telemetry endpoint'. Point it at a listener you control (nc, Burp Collaborator), then click 'Send diagnostic report' and read your inbound request body.",
                46 => "Account recovery derives the reset token from username and today's date. The audit log carries a sample. Reproduce the formula for the admin account, then redeem the token.",
                47 => "Assets panel has a 'Lookup by ID' box. User IDs enumerate 1..10 - but larger IDs with no ownership check also return rows. Scan a modest range.",
                48 => "Account → Profile POST accepts a raw JSON body. The server trusts fields it never advertised in the form. One extra key unlocks a payload intended only for role=admin.",
                49 => "Account → Generate API key is seeded from the current second. Record the key, note the timestamp - the next key is derivable without clicking again.",
                50 => "Account → Restore session accepts a JWT. The HMAC secret is a string constant in MVTC.exe (dnSpy on MVTC.Core.dll → Vault.SessionSigner). Forge sub=admin, read the response.",
                _  => "See the writeup for this challenge."
            };

        /// <summary>What tools a tester would reach for.</summary>
        public string Tools =>
            VulnNo switch
            {
                1 or 4 or 7 or 8 => "ProcMon, Autoruns, MSVC build chain",
                2 or 3           => "sc, wmic, icacls, AccessChk",
                5                => "winchecksec",
                6 or 12 or 37    => "PowerShell NamedPipeClientStream",
                9                => "OleViewDotNet",
                10               => "regedit / reg add",
                11 or 17 or 19 or 26 => "dnSpy / ILSpy",
                13 or 14 or 15 or 16 or 18 => "MSVC injector, Frida",
                20 or 21 or 22 or 23 => "x64dbg, WinDbg, Mona",
                24               => "DB Browser for SQLite, PowerShell AES",
                25               => "a text editor",
                27               => "ProcDump + strings",
                28               => "tail / Select-String",
                29               => "the Documents panel upload + audit.log",
                30               => "7-Zip / System.IO.Compression",
                31 or 32         => "the Documents panel paths",
                33               => "Newtonsoft gadget JSON",
                34               => "Comms Lab search + SQL",
                35               => "Comms Lab ping",
                36               => "a text editor + Comms Lab XML",
                38               => "Wireshark loopback, Burp, curl",
                39               => "Wireshark loopback, Burp, mitmproxy",
                40               => "the keyboard",
                41               => "Comms Lab login OR a loop over the API /login endpoint",
                42               => "Task Manager / Process Explorer / tasklist /v, plus dnSpy to find the switch",
                43               => "the About panel's 'Follow trusted link' field",
                44               => "the clipboard + any paste target (Notepad)",
                45               => "nc -lvp 9999, Burp Collaborator, requestbin.com, or the in-app Network capture tab",
                46               => "the Account panel + audit.log",
                47               => "the Account panel 'Lookup' box + a scripted range",
                48               => "the Account panel 'Profile JSON' box, or curl/Burp to the local API",
                49               => "the Account panel + a short script to replicate the seed",
                50               => "dnSpy on MVTC.Core.dll + jwt.io (or a one-liner HS256 forger)",
                _                => ""
            };
    }

    public static IReadOnlyList<Seed> All { get; } = new Seed[]
    {
        new(1,  "DLL hijacking / search-order & sideloading",     "Install/Service",  "MEDIUM", 90,  "CWE-427", "dllh",  "",    "SOLUTIONS/01-dll-hijacking.md"),
        new(2,  "Unquoted service path",                          "Install/Service",  "MEDIUM", 90,  "CWE-428", "uqp",   "",    "SOLUTIONS/02-unquoted-service-path.md"),
        new(3,  "Weak service / file / registry ACLs",            "Install/Service",  "EASY",   70,  "CWE-732", "acl",   "",    "SOLUTIONS/03-weak-acls.md"),
        new(4,  "Writable install directory",                     "Install/Service",  "EASY",   50,  "CWE-732", "wrd",   "",    "SOLUTIONS/04-writable-installdir.md"),
        new(5,  "Missing binary protections",                     "Install/Service",  "EASY",   50,  "CWE-693", "bpr",   "",    "SOLUTIONS/05-missing-binary-protections.md"),
        new(6,  "Token / privilege misuse (SYSTEM svc)",          "Install/Service",  "HARD",  150,  "CWE-269", "tok",   "37",  "SOLUTIONS/06-token-misuse.md"),
        new(7,  "DLL preloading from PATH / SxS",                 "Install/Service",  "MEDIUM",100,  "CWE-427", "sxs",   "1",   "SOLUTIONS/07-sxs-preload.md"),
        new(8,  "Writable persistence (Run key / Startup)",       "Install/Service",  "EASY",   50,  "CWE-732", "prs",   "",    "SOLUTIONS/08-persistence.md"),
        new(9,  "Insecure COM/DCOM exposure",                     "Install/Service",  "HARD",  140,  "CWE-284", "com",   "",    "SOLUTIONS/09-insecure-com.md"),
        new(10, "Privesc via registry role flip",                 "Logic Privesc",    "EASY",   60,  "CWE-250", "reg",   "",    "SOLUTIONS/10-registry-role-flip.md"),
        new(11, "Client-side authorization bypass",               "Logic Privesc",    "EASY",   60,  "CWE-602", "cli",   "",    "SOLUTIONS/11-client-side-authz.md"),
        new(12, "TOCTOU on privileged file op",                   "Logic Privesc",    "HARD",  150,  "CWE-367", "toc",   "",    "SOLUTIONS/12-toctou.md"),
        new(13, "CreateRemoteThread + LoadLibrary",               "Process Injection","MEDIUM",100,  "CWE-114", "crt",   "",    "SOLUTIONS/13-create-remote-thread.md"),
        new(14, "APC injection (QueueUserAPC)",                   "Process Injection","MEDIUM",100,  "CWE-114", "apc",   "",    "SOLUTIONS/14-apc-injection.md"),
        new(15, "Process hollowing",                              "Process Injection","HARD",  140,  "CWE-114", "hol",   "",    "SOLUTIONS/15-process-hollowing.md"),
        new(16, "Reflective / manual-map DLL",                    "Process Injection","HARD",  150,  "CWE-114", "ref",   "13",  "SOLUTIONS/16-reflective-dll.md"),
        new(17, ".NET Assembly.Load / AppDomain",                 "Process Injection","MEDIUM",100,  "CWE-470", "net",   "",    "SOLUTIONS/17-dotnet-assembly-load.md"),
        new(18, "Thread hijacking (SetThreadContext)",            "Process Injection","HARD",  140,  "CWE-114", "thj",   "",    "SOLUTIONS/18-thread-hijacking.md"),
        new(19, "No anti-debug / no self-integrity",              "Process Injection","EASY",   60,  "CWE-693", "dbg",   "",    "SOLUTIONS/19-no-anti-debug.md"),
        new(20, "Stack buffer overflow (SEH / RET)",              "Memory Safety",    "HARD",  150,  "CWE-121", "bof",   "5",   "SOLUTIONS/20-stack-bof.md"),
        new(21, "Format string vulnerability",                    "Memory Safety",    "MEDIUM",110,  "CWE-134", "fmt",   "",    "SOLUTIONS/21-format-string.md"),
        new(22, "Use-after-free / double free",                   "Memory Safety",    "HARD",  140,  "CWE-416", "uaf",   "",    "SOLUTIONS/22-use-after-free.md"),
        new(23, "Integer overflow → heap corruption",             "Memory Safety",    "HARD",  140,  "CWE-190", "int",   "",    "SOLUTIONS/23-integer-overflow.md"),
        new(24, "Hardcoded keys / weak crypto (ECB, static IV)",  "Secrets",          "EASY",   60,  "CWE-327", "crp",   "",    "SOLUTIONS/24-weak-crypto.md"),
        new(25, "Plaintext stored credentials",                   "Secrets",          "EASY",   50,  "CWE-312", "plt",   "",    "SOLUTIONS/25-plaintext-storage.md"),
        new(26, "Secrets hardcoded in binary",                    "Secrets",          "EASY",   50,  "CWE-798", "bin",   "",    "SOLUTIONS/26-secrets-in-binary.md", HardcodedSecrets.LegacyLicenseFlag),
        new(27, "Credentials from process memory",                "Secrets",          "MEDIUM", 90,  "CWE-316", "mem",   "26",  "SOLUTIONS/27-memdump-creds.md"),
        new(28, "Sensitive data in logs / temp / clipboard",      "Secrets",          "EASY",   50,  "CWE-532", "log",   "",    "SOLUTIONS/28-sensitive-leftovers.md"),
        new(29, "Insecure file import → autorun write",           "File Handling",    "HARD",  140,  "CWE-434", "imp",   "",    "SOLUTIONS/29-insecure-import.md"),
        new(30, "Zip Slip",                                       "File Handling",    "MEDIUM",100,  "CWE-22",  "zip",   "",    "SOLUTIONS/30-zip-slip.md"),
        new(31, "CHM file injection via in-app Help",             "File Handling",    "MEDIUM",110,  "CWE-74",  "chm",   "",    "SOLUTIONS/31-chm-injection.md"),
        new(32, "Path traversal / arbitrary file read-write",     "File Handling",    "EASY",   70,  "CWE-22",  "tr",    "",    "SOLUTIONS/32-path-traversal.md"),
        new(33, "Insecure deserialization",                       "File Handling",    "HARD",  150,  "CWE-502", "des",   "",    "SOLUTIONS/33-deserialization.md"),
        new(34, "SQL injection against local DB",                 "Input Handling",   "MEDIUM",110,  "CWE-89",  "sqli",  "",    "SOLUTIONS/34-sqli.md"),
        new(35, "OS command injection",                           "Input Handling",   "EASY",   70,  "CWE-78",  "cmd",   "",    "SOLUTIONS/35-command-injection.md"),
        new(36, "XXE on imported XML",                            "Input Handling",   "MEDIUM",100,  "CWE-611", "xxe",   "",    "SOLUTIONS/36-xxe.md"),
        new(37, "Insecure IPC (named pipe / WCF)",                "Comms",            "HARD",  150,  "CWE-306", "ipc",   "",    "SOLUTIONS/37-insecure-ipc.md"),
        new(38, "Insecure auto-update",                           "Comms",            "HARD",  150,  "CWE-345", "upd",   "",    "SOLUTIONS/38-insecure-update.md"),
        new(39, "Disabled TLS / cleartext",                       "Comms",            "EASY",   60,  "CWE-295", "tls",   "",    "SOLUTIONS/39-cleartext-tls.md"),
        new(40, "Debug / diagnostic backdoor",                    "Logic/Misc",       "EASY",   50,  "CWE-489", "dbg2",  "",    "SOLUTIONS/40-debug-backdoor.md"),
        // v1.2 - uncommon thick-client challenges (#41-#45)
        new(41, "No account lockout (brute force)",               "Logic/Misc",       "EASY",   70,  "CWE-307", "nolock","",    "SOLUTIONS/41-no-lockout.md"),
        new(42, "Password in command-line arguments",             "Logic/Misc",       "MEDIUM", 90,  "CWE-214", "cmd2",  "",    "SOLUTIONS/42-password-in-cmdline.md"),
        new(43, "URL opener accepts any scheme (open redirect)",  "Logic/Misc",       "EASY",   80,  "CWE-601", "redir", "",    "SOLUTIONS/43-url-opener.md"),
        new(44, "Clipboard leakage of session token",             "Secrets",          "EASY",   60,  "CWE-732", "clip",  "",    "SOLUTIONS/44-clipboard.md"),
        new(45, "Telemetry SSRF - targets attacker-chosen URL",   "Comms",            "MEDIUM",100,  "CWE-918", "ssrf",  "",    "SOLUTIONS/45-telemetry-ssrf.md"),
        // v1.4 - rounds the lab out to 50 (#46-#50)
        new(46, "Predictable account-recovery token",             "Logic/Misc",       "MEDIUM", 90,  "CWE-640", "rst",   "",    "SOLUTIONS/46-predictable-reset-token.md"),
        new(47, "IDOR on asset lookup",                           "Logic/Misc",       "EASY",   80,  "CWE-639", "idor",  "",    "SOLUTIONS/47-idor-asset-lookup.md"),
        new(48, "Mass assignment on profile update",              "Input Handling",   "MEDIUM", 90,  "CWE-915", "mas",   "",    "SOLUTIONS/48-mass-assignment.md"),
        new(49, "Weak PRNG for API key generation",               "Secrets",          "MEDIUM",100,  "CWE-338", "prng",  "",    "SOLUTIONS/49-weak-prng-api-key.md"),
        new(50, "Hardcoded JWT signing secret",                   "Secrets",          "HARD",  140,  "CWE-321", "jwt",   "26",  "SOLUTIONS/50-hardcoded-jwt-secret.md"),
    };

    public static int TotalPoints => All.Sum(c => c.Points);
}
