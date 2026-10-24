namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #41 - CWE-307 - No account lockout.
/// Tracks failed login attempts per username but takes NO action beyond
/// counting. Once the threshold is crossed the service logs a verbose
/// warning that includes the flag - a real lockout would have refused the
/// login attempt long before this counter hit the threshold.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #41): exponential backoff on failures, soft lockout
///   after N attempts (5 typical) with a time-window, hard lockout escalated
///   to an operator channel.
/// </remarks>
public static class BruteForceGuard
{
    private const int FlagThreshold = 10;
    private static readonly Dictionary<string, int> _byUser = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> _emittedForUser = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _gate = new();

    public static int Record(string username)
    {
        lock (_gate)
        {
            _byUser.TryGetValue(username, out var n);
            n++;
            _byUser[username] = n;
            return n;
        }
    }

    public static void OnSuccess(string username)
    {
        lock (_gate) _byUser.Remove(username);
    }

    /// <summary>
    /// Returns a one-shot warning line to append to the audit log once the
    /// threshold is crossed (per username). The caller writes it; this type
    /// only decides whether to emit.
    /// </summary>
    public static string? MaybeEmitWarning(string username, Func<int, string?> flagLookup)
    {
        lock (_gate)
        {
            if (!_byUser.TryGetValue(username, out var n)) return null;
            if (n < FlagThreshold) return null;
            if (_emittedForUser.Contains(username)) return null;
            _emittedForUser.Add(username);
            var flag = flagLookup(41) ?? "";
            return $"brute-force on '{username}' not throttled after {n} attempts; incident_token={flag}";
        }
    }
}
