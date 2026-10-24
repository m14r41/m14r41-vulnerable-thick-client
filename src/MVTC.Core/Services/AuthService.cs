using MVTC.Core.Crypto;
using MVTC.Core.Data;
using MVTC.Core.Logging;

namespace MVTC.Core.Services;

public sealed class Session
{
    public required int UserId { get; init; }
    public required string Username { get; init; }
    public required string Role { get; init; }
    public required string Token { get; init; }
    public required string PlaintextPassword { get; init; }       // VULN: #27 - kept around
    public DateTime IssuedUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Login flow for the thick client. Verifies credentials against the local DB,
/// writes a leaky audit entry, and keeps the resulting session in a static
/// field for the lifetime of the process.
/// </summary>
public sealed class AuthService
{
    private readonly AppDb _appDb;
    private readonly LeakyLogger _logger;

    public AuthService(AppDb appDb, LeakyLogger logger)
    {
        _appDb = appDb;
        _logger = logger;
    }

    // VULN: #27 - CWE-316 - session + raw password live for the lifetime of the
    // process in a GC-root'd static field. ProcDump → `strings` lands the pair.
    public static Session? CurrentSession { get; private set; }

    // VULN: #27 - the "restored prior session" string is kept in a long-lived
    // static for the lifetime of the process so sysadmins can see it in
    // crash-dump telemetry. The literal appears in logs/audit.log too (#28), but
    // #27 is specifically the ProcDump + strings path: no file reads required.
    public static string? RestoredRecoveryToken { get; set; }

    /// <summary>Called at app startup to let auth helpers look up flag plaintexts.</summary>
    public static Func<int, string?>? FlagLookup { get; set; }

    public Session? Login(string username, string password)
    {
        var md5 = WeakCrypto.MdFive(password);

        // Row-by-row check so the three auth styles (MD5 / plaintext / AES-ECB)
        // all pass without a schema rework.
        var byMd5 = _appDb.FindUser(username, md5);
        if (byMd5 is null)
        {
            // Fall back to plaintext users (svc_backup - VULN: #25).
            var plain = _appDb.FindUser(username, password);
            if (plain is not null) byMd5 = plain;
        }
        if (byMd5 is null)
        {
            // Fall back to AES-ECB-wrapped users (auditor - VULN: #24).
            var ecb = _appDb.FindUser(username, Convert.ToBase64String(WeakCrypto.EncryptEcb(password)));
            if (ecb is not null) byMd5 = ecb;
        }

        if (byMd5 is null)
        {
            _logger.LogLogin(username, password, success: false);
            // VULN: #41 - count failures per user; log a warning (including the
            // incident token / flag) at the threshold. No real lockout kicks in.
            Vuln.BruteForceGuard.Record(username);
            if (FlagLookup is not null)
            {
                var warn = Vuln.BruteForceGuard.MaybeEmitWarning(username, FlagLookup);
                if (warn is not null) _logger.Write("WARN", "auth", warn);
            }
            return null;
        }

        Vuln.BruteForceGuard.OnSuccess(username);

        var token = $"SESS-{Guid.NewGuid():N}";
        var session = new Session
        {
            UserId = byMd5.Value.Id,
            Username = username,
            Role = byMd5.Value.Role,
            Token = token,
            PlaintextPassword = password
        };
        CurrentSession = session;
        _logger.LogLogin(username, password, success: true, sessionToken: token);
        return session;
    }

    public void Logout()
    {
        // VULN: #27 (continued) - nulling the reference does NOT scrub the heap;
        // the string objects stay reachable from GC roots across generations
        // until compaction, and often never get overwritten.
        CurrentSession = null;
    }
}
