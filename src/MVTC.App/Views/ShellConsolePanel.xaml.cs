using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace MVTC.App.Views;

/// <summary>
/// In-app shell. Runs commands via <c>cmd.exe /c &lt;input&gt;</c> on a background
/// thread, drains stdout/stderr asynchronously, and enforces a hard timeout
/// so an interactive REPL (bare <c>powershell</c>, <c>python</c>, …) can't lock
/// the UI. Users can also cancel a running command.
/// </summary>
public partial class ShellConsolePanel : UserControl
{
    private readonly StringBuilder _buf = new();
    private readonly List<string> _history = new();
    private int _historyIdx = -1;

    private CancellationTokenSource? _cts;
    private Process? _running;
    private const int DefaultTimeoutSeconds = 20;

    public ShellConsolePanel()
    {
        InitializeComponent();
        _buf.AppendLine("mvtc shell ready (restricted mode).");
        _buf.AppendLine("Allowed (read-only, lab-relevant):");
        _buf.AppendLine("  whoami [/all /priv /groups]   dir   type   cat   hostname   ver");
        _buf.AppendLine("  ipconfig   ping   nslookup   netstat   arp   route   tracert");
        _buf.AppendLine("  systeminfo   where   findstr   tasklist   icacls   cd");
        _buf.AppendLine("  sc query|qc|sdshow|enumdepend   reg query   net user|localgroup|share|view|session|config|statistics");
        _buf.AppendLine("Interactive REPLs and destructive verbs (del, format, shutdown, reg add/delete, sc start/stop/create, net user add/delete, …) are refused.");
        _buf.AppendLine("Hard timeout: " + DefaultTimeoutSeconds + "s. Cancel with Esc or the Cancel button.");
        OutputBox.Text = _buf.ToString();
    }

    private void OnRun(object sender, RoutedEventArgs e)
    {
        if (_running is not null) CancelRunning();
        else                      _ = RunCurrentAsync();
    }

    private void OnCommandKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (_running is null) _ = RunCurrentAsync();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && _running is not null)
        {
            CancelRunning();
            e.Handled = true;
        }
        else if (e.Key == Key.Up)
        {
            if (_history.Count == 0) return;
            _historyIdx = Math.Max(0, _historyIdx - 1);
            CommandBox.Text = _history[_historyIdx];
            CommandBox.CaretIndex = CommandBox.Text.Length;
            e.Handled = true;
        }
        else if (e.Key == Key.Down)
        {
            if (_history.Count == 0) return;
            _historyIdx = Math.Min(_history.Count - 1, _historyIdx + 1);
            CommandBox.Text = _history[_historyIdx];
            CommandBox.CaretIndex = CommandBox.Text.Length;
            e.Handled = true;
        }
    }

    private void CancelRunning()
    {
        try { _cts?.Cancel(); } catch { }
        try { if (_running is not null && !_running.HasExited) _running.Kill(entireProcessTree: true); } catch { }
    }

    private async Task RunCurrentAsync()
    {
        var cmd = (CommandBox.Text ?? "").Trim();
        if (cmd.Length == 0) return;

        if (!IsAllowed(cmd, out var reason))
        {
            _buf.Append("mvtc@vault:~$ ").AppendLine(cmd);
            _buf.AppendLine("refused: " + reason);
            FlushOutput();
            CommandBox.Clear();
            return;
        }

        _history.Add(cmd);
        _historyIdx = _history.Count;
        CommandBox.Clear();
        _buf.Append("mvtc@vault:~$ ").AppendLine(cmd);
        FlushOutput();

        SetBusy(true);
        _cts = new CancellationTokenSource(TimeSpan.FromSeconds(DefaultTimeoutSeconds));
        var token = _cts.Token;

        try
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                RedirectStandardInput  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                WorkingDirectory       = App.InstallRoot,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding  = Encoding.UTF8,
            };

            var sb = new StringBuilder();
            var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
            p.OutputDataReceived += (_, args) => { if (args.Data != null) lock (sb) sb.AppendLine(args.Data); };
            p.ErrorDataReceived  += (_, args) => { if (args.Data != null) lock (sb) sb.AppendLine(args.Data); };

            if (!p.Start()) throw new Exception("Process failed to start.");
            _running = p;
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            try { p.StandardInput.Close(); } catch { }

            // Wait for exit OR cancellation (timeout or user Cancel).
            try
            {
                await p.WaitForExitAsync(token).ConfigureAwait(true);
            }
            catch (OperationCanceledException)
            {
                try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
                try { p.WaitForExit(2_000); } catch { }
                lock (sb) sb.AppendLine("[cancelled: timeout or user abort]");
            }

            string tail;
            lock (sb) tail = sb.ToString();
            _buf.Append(tail);
            _buf.Append("[exit ").Append(p.HasExited ? p.ExitCode : -1).AppendLine("]");
        }
        catch (Exception ex)
        {
            _buf.AppendLine("error: " + ex.Message);
        }
        finally
        {
            _running?.Dispose();
            _running = null;
            _cts?.Dispose();
            _cts = null;
            SetBusy(false);
            FlushOutput();
        }
    }

    private void SetBusy(bool busy)
    {
        RunButton.Content    = busy ? "Cancel" : "Run";
        RunButton.Background = busy ? System.Windows.Media.Brushes.Firebrick : null;
        BusyText.Text        = busy ? $"running… (Esc or Cancel to abort; auto-kills after {DefaultTimeoutSeconds}s)" : "";
        BusyText.Visibility  = busy ? Visibility.Visible : Visibility.Collapsed;
    }

    private void FlushOutput()
    {
        OutputBox.Text = _buf.ToString();
        OutputBox.CaretIndex = OutputBox.Text.Length;
        OutputScroll.ScrollToEnd();
    }

    // ---- Allow-list policy ----

    // Shell meta-characters that make the command string run more than one program.
    // Blocking these keeps the policy simple: one allowed binary per submission.
    private static readonly char[] _shellMeta = { '&', '|', ';', '>', '<', '`' };

    // First-token allow-list: pure read-only, lab-relevant.
    private static readonly HashSet<string> _singleTokenAllowed = new(StringComparer.OrdinalIgnoreCase)
    {
        "whoami", "hostname", "ver", "cd", "chdir",
        "dir",    "type",     "cat",
        "ipconfig", "ping", "nslookup", "netstat", "arp", "route", "tracert", "pathping", "getmac",
        "systeminfo", "where", "findstr",
        "tasklist", "icacls",
    };

    // Two-token allow-list: first token + required second subcommand.
    // Keeps "sc query" (read) while refusing "sc config"/"sc start"/"sc delete".
    private static readonly Dictionary<string, HashSet<string>> _twoTokenAllowed = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sc"]  = new(StringComparer.OrdinalIgnoreCase) { "query", "qc", "sdshow", "enumdepend", "queryex", "getdisplayname", "showsid" },
        ["reg"] = new(StringComparer.OrdinalIgnoreCase) { "query" },
        ["net"] = new(StringComparer.OrdinalIgnoreCase) { "user", "localgroup", "share", "view", "session", "config", "statistics", "accounts", "time" },
    };

    // Commands that look read-only but can take arguments that make them destructive
    // (e.g. 'tasklist' is fine, 'taskkill' is NOT in the allow-list at all).
    private static readonly HashSet<string> _hardDenyFirstToken = new(StringComparer.OrdinalIgnoreCase)
    {
        "del", "erase", "rd", "rmdir", "format", "shutdown", "logoff", "restart",
        "taskkill", "attrib", "cacls", "assoc", "ftype", "mklink", "fsutil", "diskpart",
        "bcdedit", "bootcfg", "wmic", "powercfg", "schtasks", "at",
    };

    private static bool IsAllowed(string cmd, out string reason)
    {
        reason = "";
        var trimmed = cmd.Trim();
        if (trimmed.Length == 0) { reason = "empty command."; return false; }

        if (trimmed.IndexOfAny(_shellMeta) >= 0)
        {
            reason = "shell meta-characters (& | ; > < `) are not allowed - run one command at a time.";
            return false;
        }

        // Split off first (and second) token for policy. Preserves the rest for the
        // real cmd.exe call; we don't try to re-quote anything.
        var tokens = Regex.Matches(trimmed, @"(?:""[^""]*""|\S)+")
                          .Cast<Match>().Select(m => m.Value.Trim('"'))
                          .ToArray();
        if (tokens.Length == 0) { reason = "empty command."; return false; }

        var head = System.IO.Path.GetFileNameWithoutExtension(tokens[0]).ToLowerInvariant();
        var second = tokens.Length > 1 ? tokens[1] : "";

        if (_hardDenyFirstToken.Contains(head))
        {
            reason = $"'{head}' is destructive and not permitted in the in-app shell.";
            return false;
        }

        if (_singleTokenAllowed.Contains(head)) return true;

        if (_twoTokenAllowed.TryGetValue(head, out var sub))
        {
            if (second.Length == 0)
            {
                reason = $"'{head}' needs an explicit subcommand (allowed: {string.Join(", ", sub.OrderBy(s => s))}).";
                return false;
            }
            if (sub.Contains(second)) return true;
            reason = $"'{head} {second}' is not permitted. Allowed: {string.Join(", ", sub.OrderBy(s => s))}.";
            return false;
        }

        // Interactive REPLs call out explicitly so the hint is useful.
        if (head is "powershell" or "pwsh" or "cmd" or "python" or "python3" or "py"
                 or "node" or "bash" or "sh" or "wsl" or "ssh")
        {
            reason = $"'{head}' is not allowed - the shell is restricted to a fixed read-only command set. " +
                     $"Use one of: whoami, dir, ipconfig, systeminfo, sc query, reg query, net user, tasklist, icacls, …";
            return false;
        }

        reason = $"'{head}' is not on the allow-list. Allowed: " +
                 string.Join(", ", _singleTokenAllowed.OrderBy(s => s)) +
                 ", sc query/qc/sdshow, reg query, net user/localgroup/share/view/session/config/statistics.";
        return false;
    }
}
