namespace MVTC.Core.Logging;

/// <summary>
/// VULN: #28 - CWE-532 - logs sensitive information in plaintext.
/// Writes to logs/audit.log; includes passwords, session tokens, and sometimes
/// the flag itself when verbose mode is on.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #28): structure logs, redact credentials/tokens at the
///   logging boundary, strip secret-shaped fields (api_key, password, token,
///   flag) via an allowlist. Rotate and ACL the log directory.
/// </remarks>
public sealed class LeakyLogger
{
    private readonly string _path;
    private readonly object _gate = new();

    public LeakyLogger(string path)
    {
        _path = path;
        var dir = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    public string Path => _path;

    public void Write(string level, string action, string detail)
    {
        var line = $"[{DateTime.UtcNow:O}] [{level,-5}] {action} :: {detail}";
        lock (_gate) File.AppendAllText(_path, line + Environment.NewLine);
    }

    // VULN: logs the raw password on every login attempt. Combine with #27's
    // long-lived in-memory session and you've got the attacker's shopping list.
    public void LogLogin(string user, string password, bool success, string? sessionToken = null)
    {
        var detail = $"user={user} password={password} success={success}";
        if (success && sessionToken is not null) detail += $" session={sessionToken}";
        Write("INFO", "login", detail);
    }

    public void LogConfigRead(string key, string value)
    {
        Write("DEBUG", "config", $"key={key} value={value}");
    }
}
