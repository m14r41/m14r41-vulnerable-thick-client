using System.IO;
using System.Windows;
using System.Windows.Controls;
using MVTC.Core.Data;
using MVTC.Core.Services.Insecure;
using MVTC.Core.Services.Vuln;

namespace MVTC.App.Views;

public partial class CommsLabPanel : UserControl
{
    private AssetRepository? _assets;
    private DiagService? _diag;
    private string _installRoot = "";
    private int _mockApiPort;
    private int _mockUpdatePort;

    public CommsLabPanel() { InitializeComponent(); }

    public void Attach(AppDb appDb, string installRoot, int mockApiPort, int mockUpdatePort)
    {
        _assets = new AssetRepository(appDb);
        _diag = new DiagService();
        _installRoot = installRoot;
        _mockApiPort = mockApiPort;
        _mockUpdatePort = mockUpdatePort;
    }

    private void OnSearchAssets(object sender, RoutedEventArgs e)
    {
        if (_assets is null) return;
        try
        {
            var (sql, rows) = _assets.RunDiagnostic(2, AssetQuery.Text ?? "");
            AssetSqlOut.Text = "SQL: " + sql;
            AssetOut.Text = rows.Count == 0 ? "(no rows)" : string.Join("\n", rows);
        }
        catch (Exception ex) { AssetSqlOut.Text = ""; AssetOut.Text = ex.Message; }
    }

    private void OnPing(object sender, RoutedEventArgs e)
    {
        if (_diag is null) return;
        try
        {
            var r = _diag.Ping(PingHost.Text?.Trim() ?? "127.0.0.1");
            PingOut.Text = $"exit={r.ExitCode}\n{r.Output}";
        }
        catch (Exception ex) { PingOut.Text = ex.Message; }
    }

    private void OnPipePing(object sender, RoutedEventArgs e) => PipeCall("PING");
    private void OnPipeWhoami(object sender, RoutedEventArgs e) => PipeCall("WHOAMI");
    private void OnPipeGetFlag(object sender, RoutedEventArgs e) => PipeCall("EXPORT_SERVICE_KEY");
    private void OnPipeImpersonate(object sender, RoutedEventArgs e) => PipeCall("SYS_READ");
    private void OnPipeToctou(object sender, RoutedEventArgs e) => PipeCall("ATOMIC_COPY");

    private void PipeCall(string verb)
    {
        try
        {
            var raw = VaultPipeClient.Call(verb);
            PipeOut.Text = Redact(PrettyJson(raw));
        }
        catch (Exception ex) { PipeOut.Text = ex.Message; }
    }

    private static string PrettyJson(string s)
    {
        try
        {
            var doc = System.Text.Json.JsonDocument.Parse(s);
            return System.Text.Json.JsonSerializer.Serialize(doc, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        }
        catch { return s; }
    }

    /// <summary>
    /// Redacts anything matching MVTC{...} so the Flag isn't shown in the UI
    /// output. The flag still travels on the pipe / HTTP wire - intercept with
    /// Wireshark, Burp, or a pipe sniffer to see the real value.
    /// </summary>
    private static string Redact(string s) =>
        System.Text.RegularExpressions.Regex.Replace(
            s, @"MVTC\{[^}]+\}", "MVTC{<intercept-to-reveal>}");

    private async void OnCheckUpdate(object sender, RoutedEventArgs e)
    {
        try
        {
            var mgr = new InsecureUpdateService(
                new Uri($"http://127.0.0.1:{_mockUpdatePort}/manifest.json"),
                _installRoot);
            var r = await mgr.CheckAndApplyAsync();
            // Full manifest travels over HTTP - intercept http://127.0.0.1:<port>/manifest.json
            // in Wireshark or Burp to see release_notes verbatim.
            UpdateOut.Text = Redact(
                $"status={r.Status}\nversion={r.Version}\nrelease_notes={r.ReleaseNotes}\npayload_path={r.PayloadPath}");
        }
        catch (Exception ex) { UpdateOut.Text = ex.Message; }
    }

    private async void OnCallApi(object sender, RoutedEventArgs e)
    {
        try
        {
            using var api = new InsecureApiClient(new Uri($"http://127.0.0.1:{_mockApiPort}"));
            var r = await api.LoginAsync(ApiUser.Text?.Trim() ?? "", ApiPass.Text ?? "");
            // The real secure_token is in the HTTP response body on the wire.
            // UI redacts the display so the challenge still requires an
            // interception tool (Burp / Wireshark loopback / mitmproxy).
            ApiOut.Text = r is null
                ? "no response"
                : Redact($"username={r.username}\nrole={r.role}\nsecure_token={r.secure_token}");
        }
        catch (Exception ex) { ApiOut.Text = ex.Message; }
    }
}
