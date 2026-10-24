using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using MVTC.Core.Services;

namespace MVTC.App.Views;

public partial class SecretsLabPanel : UserControl
{
    private AuthService? _auth;
    private string _installRoot = "";

    public SecretsLabPanel()
    {
        InitializeComponent();
    }

    public void Attach(AuthService auth, string installRoot)
    {
        _auth = auth;
        _installRoot = installRoot;
        RefreshSession();
    }

    private void OnLogin(object sender, RoutedEventArgs e)
    {
        if (_auth is null) return;
        var user = UsernameBox.Text.Trim();
        var pwd = PasswordBox.Password;
        if (user.Length == 0)
        {
            SessionText.Text = "(enter a username)";
            return;
        }
        var session = _auth.Login(user, pwd);
        if (session is null)
        {
            SessionText.Text = $"Login failed for {user}. (The password is still in audit.log - VULN #28.)";
            return;
        }
        RefreshSession();
    }

    private void OnLogout(object sender, RoutedEventArgs e)
    {
        _auth?.Logout();
        RefreshSession();
    }

    private void RefreshSession()
    {
        var s = AuthService.CurrentSession;
        SessionText.Text = s is null
            ? "(not signed in)"
            : $"user   = {s.Username}\nrole   = {s.Role}\ntoken  = {s.Token}\npass   = {s.PlaintextPassword}";
    }

    private void OnCopySession(object sender, RoutedEventArgs e)
    {
        var s = AuthService.CurrentSession;
        var flag44 = App.Progress?.GetFlagPlaintext(44) ?? "";
        // VULN: #44 - clipboard dump of session detail. The hidden copy_token
        // field is the flag. Clipboard is never cleared on logout.
        var payload = $"user={s?.Username ?? "<none>"}\nrole={s?.Role ?? "<none>"}\ntoken={s?.Token ?? "<none>"}\ncopy_token={flag44}";
        try
        {
            System.Windows.Clipboard.SetText(payload);
            ClipStatus.Text = "copied to clipboard - paste anywhere to see (Notepad, text field…)";
        }
        catch (Exception ex) { ClipStatus.Text = "clipboard error: " + ex.Message; }
    }

    private void OnOpenConfigXml(object sender, RoutedEventArgs e) =>
        OpenInShell(Path.Combine(_installRoot, "config.xml"));

    private void OnOpenAuditLog(object sender, RoutedEventArgs e) =>
        OpenInShell(Path.Combine(_installRoot, "logs", "audit.log"));

    private void OnOpenInstallRoot(object sender, RoutedEventArgs e) =>
        OpenInShell(_installRoot);

    private static void OpenInShell(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            MessageBox.Show($"Not found: {path}", "MVTC");
            return;
        }
        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }
}
