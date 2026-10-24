using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Xml.Linq;
using Microsoft.Win32;

namespace MVTC.App.Views;

public partial class SettingsPanel : UserControl
{
    private const string ServiceName = "MVTCVaultSvc";
    private const string DotNetDownloadUrl = "https://dotnet.microsoft.com/download/dotnet/10.0/runtime";

    public SettingsPanel()
    {
        InitializeComponent();
        Loaded += (_, _) => { Refresh(); LoadConfig(); };
    }

    private void Refresh()
    {
        StatusText.Text = QueryStatusText();
        DotNetText.Text = QueryDotNetText();
    }

    private string QueryStatusText()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"InstallRoot (dev): {App.InstallRoot}");
        try
        {
            if (OperatingSystem.IsWindows()) sb.AppendLine(QueryServiceWindows());
        }
        catch (Exception ex) { sb.AppendLine($"service query error: {ex.Message}"); }
        return sb.ToString().TrimEnd();
    }

    [SupportedOSPlatform("windows")]
    private static string QueryServiceWindows()
    {
        using var searcher = new ManagementObjectSearcher(
            $"SELECT Name, State, PathName, StartName, StartMode FROM Win32_Service WHERE Name='{ServiceName}'");
        foreach (var mo in searcher.Get())
        {
            var path = (string?)mo["PathName"] ?? "<null>";
            var quoted = path.StartsWith("\"");
            return $"Service     : {mo["Name"]}\n" +
                   $"State       : {mo["State"]} (start mode {mo["StartMode"]})\n" +
                   $"Account     : {mo["StartName"]}\n" +
                   $"ImagePath   : {path}\n" +
                   $"UnquotedOK  : {(quoted ? "NO - click 'Finalize install'" : "YES")}";
        }
        return "Service     : NOT installed";
    }

    private string QueryDotNetText()
    {
        try
        {
            var psi = new ProcessStartInfo("dotnet", "--list-runtimes")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p is null) return ".NET runtime: dotnet CLI not found";
            var runtimes = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);
            var has10 = runtimes.Contains("Microsoft.WindowsDesktop.App 10.");
            return (has10 ? ".NET 10 Desktop: PRESENT" : ".NET 10 Desktop: MISSING (self-contained MVTC does not require it)")
                + "\n\nAll runtimes:\n" + runtimes.Trim();
        }
        catch (Exception ex) { return $".NET runtime query error: {ex.Message}"; }
    }

    // ---- Configuration (config.xml) ----

    private string ConfigPath => Path.Combine(App.InstallRoot, "config.xml");

    private void LoadConfig()
    {
        try
        {
            string? apiUrl = null, updUrl = null, pingTarget = null, proxy = null;
            bool allowInsecure = true, preferHttps = false;

            if (File.Exists(ConfigPath))
            {
                try
                {
                    var doc = XDocument.Load(ConfigPath);
                    apiUrl       = doc.Root?.Element("Api")?.Element("Url")?.Value;
                    updUrl       = doc.Root?.Element("Updater")?.Element("Url")?.Value;
                    pingTarget   = doc.Root?.Element("Network")?.Element("DefaultPingTarget")?.Value;
                    proxy        = doc.Root?.Element("Network")?.Element("Proxy")?.Value;
                    var ai       = doc.Root?.Element("Network")?.Element("TrustAllCerts")?.Value;
                    var ph       = doc.Root?.Element("Network")?.Element("PreferHttps")?.Value;
                    if (!string.IsNullOrEmpty(ai)) allowInsecure = ai == "true";
                    if (!string.IsNullOrEmpty(ph)) preferHttps   = ph == "true";
                }
                catch { }
            }

            // Default to the running mock services if the config has no entries.
            if (string.IsNullOrEmpty(apiUrl) && App.MockApiStarted is not null)
                apiUrl = $"http://127.0.0.1:{App.MockApiStarted.Port}";
            if (string.IsNullOrEmpty(updUrl) && App.MockUpdateStarted is not null)
                updUrl = $"http://127.0.0.1:{App.MockUpdateStarted.Port}/manifest.json";

            ApiUrlBox.Text        = apiUrl        ?? "";
            UpdateUrlBox.Text     = updUrl        ?? "";
            PingTargetBox.Text    = pingTarget    ?? "127.0.0.1";
            ProxyBox.Text         = proxy         ?? "";
            AllowInsecureBox.IsChecked = allowInsecure;
            PreferHttpsBox.IsChecked   = preferHttps;
        }
        catch (Exception ex) { ConfigStatus.Text = ex.Message; }
    }

    private void OnAutoDetect(object sender, RoutedEventArgs e)
    {
        var api = App.MockApiStarted?.Port;
        var upd = App.MockUpdateStarted?.Port;
        if (api is not null) ApiUrlBox.Text = $"http://127.0.0.1:{api}";
        if (upd is not null) UpdateUrlBox.Text = $"http://127.0.0.1:{upd}/manifest.json";
        PingTargetBox.Text = string.IsNullOrWhiteSpace(PingTargetBox.Text) ? "127.0.0.1" : PingTargetBox.Text;
        ConfigStatus.Text = "Auto-detected from live services. Click Apply + save to persist.";
    }

    private void OnSaveConfig(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
            XDocument doc;
            if (File.Exists(ConfigPath))
            {
                doc = XDocument.Load(ConfigPath);
            }
            else
            {
                doc = new XDocument(new XElement("Config"));
            }
            var root = doc.Root ?? new XElement("Config");

            Set(root, "Api",     "Url", ApiUrlBox.Text.Trim());
            Set(root, "Updater", "Url", UpdateUrlBox.Text.Trim());
            Set(root, "Network", "DefaultPingTarget", PingTargetBox.Text.Trim());
            Set(root, "Network", "Proxy",             ProxyBox.Text.Trim());
            Set(root, "Network", "TrustAllCerts",     (AllowInsecureBox.IsChecked == true).ToString().ToLower());
            Set(root, "Network", "PreferHttps",       (PreferHttpsBox.IsChecked   == true).ToString().ToLower());

            doc.Save(ConfigPath);
            ConfigStatus.Text = $"Saved: {ConfigPath}";

            // Apply proxy to WinHTTP so the mock backend calls flow through it
            // (users can point MVTC at Burp this way without touching Windows settings).
            if (!string.IsNullOrWhiteSpace(ProxyBox.Text))
                ApplyProxy(ProxyBox.Text.Trim());
        }
        catch (Exception ex) { ConfigStatus.Text = "Error: " + ex.Message; }
    }

    private static void Set(XElement root, string section, string key, string value)
    {
        var sec = root.Element(section);
        if (sec is null) { sec = new XElement(section); root.Add(sec); }
        var el = sec.Element(key);
        if (el is null) { el = new XElement(key); sec.Add(el); }
        el.Value = value ?? "";
    }

    private void ApplyProxy(string proxy)
    {
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", $"/c netsh winhttp set proxy proxy-server=\"{proxy}\" bypass-list=\"<local>\"")
            {
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            };
            Process.Start(psi);
        }
        catch (Exception ex) { ConfigStatus.Text += $"\nProxy apply error: {ex.Message}"; }
    }

    // ---- Post-install actions ----

    private void OnFinalizeUnquotePath(object sender, RoutedEventArgs e) =>
        RunElevated("sc.exe",
            "config MVTCVaultSvc binPath= \"C:\\Program Files (x86)\\M14R41 Labs\\MVTC\\MVTCVaultSvc.exe\"",
            "Service ImagePath unquoted.");

    private void OnStartService(object sender, RoutedEventArgs e) =>
        RunElevated("sc.exe", "start MVTCVaultSvc", "Service start requested.");

    private void OnStopService(object sender, RoutedEventArgs e) =>
        RunElevated("sc.exe", "stop MVTCVaultSvc", "Service stop requested.");

    private void RunElevated(string file, string args, string onSuccess)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                Verb = "runas",
                UseShellExecute = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var p = Process.Start(psi);
            if (p is null) { Toast("elevation declined", error: true); return; }
            p.WaitForExit(10_000);
            if (p.ExitCode == 0) { Toast(onSuccess); Refresh(); }
            else Toast($"command exited {p.ExitCode}", error: true);
        }
        catch (Exception ex)
        {
            Toast(ex.Message, error: true);
        }
    }

    // ---- Dependencies + path helpers ----

    private void OnDownloadDotNet(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo(DotNetDownloadUrl) { UseShellExecute = true });

    private void OnOpenInstallDir(object sender, RoutedEventArgs e)
    {
        var candidates = new[]
        {
            @"C:\Program Files (x86)\M14R41 Labs\MVTC",
            @"C:\Program Files\M14R41 Labs\MVTC",
            AppContext.BaseDirectory
        };
        foreach (var p in candidates)
            if (Directory.Exists(p)) { OpenPath(p); return; }
        Toast("install dir not found", error: true);
    }

    private void OnOpenAppData(object sender, RoutedEventArgs e) => OpenPath(App.InstallRoot);
    private void OnOpenAuditLog(object sender, RoutedEventArgs e) => OpenPath(Path.Combine(App.InstallRoot, "logs", "audit.log"));
    private void OnOpenConfigXml(object sender, RoutedEventArgs e) => OpenPath(Path.Combine(App.InstallRoot, "config.xml"));

    private static void OpenPath(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Refresh();

    private async void OnSendTelemetry(object sender, RoutedEventArgs e)
    {
        try
        {
            var url = TelemetryUrlBox.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(url)) { TelemetryOut.Text = "enter a telemetry endpoint"; return; }
            var client = new MVTC.Core.Services.Vuln.TelemetryClient();
            var s = MVTC.Core.Services.AuthService.CurrentSession;
            var flag45 = App.Progress?.GetFlagPlaintext(45);
            var result = await client.SendAsync(url, flag45, s?.Username, s?.Role);
            TelemetryOut.Text = result + "\n(POST body includes a trace_token field - see the body on your listener.)";
        }
        catch (Exception ex) { TelemetryOut.Text = "telemetry error: " + ex.Message; }
    }

    private async void OnSoftReset(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show("Clear progress (points, solved state)?", "MVTC - soft reset",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        try
        {
            var port = App.ScoreboardStarted?.Port ?? 0;
            if (port == 0) { Toast("scoreboard not running", error: true); return; }
            using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
            await http.PostAsync("/reset/soft", null);
            Toast("progress cleared");
        }
        catch (Exception ex) { Toast(ex.Message, error: true); }
    }

    private void Toast(string msg, bool error = false)
    {
        OutText.Text = msg;
        OutText.Foreground = error
            ? System.Windows.Media.Brushes.OrangeRed
            : System.Windows.Media.Brushes.LightGreen;
    }
}
