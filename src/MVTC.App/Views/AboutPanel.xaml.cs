using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace MVTC.App.Views;

public partial class AboutPanel : UserControl
{
    public AboutPanel()
    {
        InitializeComponent();
    }

    private void OnOpenLink(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.Tag is string url) Open(url);
    }

    private void OnNav(object sender, RequestNavigateEventArgs e)
    {
        Open(e.Uri.AbsoluteUri);
        e.Handled = true;
    }

    private void OnOpenLocalDocs(object sender, RequestNavigateEventArgs e)
    {
        // Try a few plausible docs/SOLUTIONS locations shipped alongside the app.
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "docs", "SOLUTIONS"),
            @"C:\Program Files (x86)\M14R41 Labs\MVTC\docs\SOLUTIONS",
            @"C:\Program Files\M14R41 Labs\MVTC\docs\SOLUTIONS"
        };
        foreach (var c in candidates)
            if (Directory.Exists(c)) { Open(c); break; }
        e.Handled = true;
    }

    private static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); } catch { }
    }

    private void OnFollowLink(object sender, RoutedEventArgs e)
    {
        // VULN: #43 - CWE-601 - no scheme / origin validation; happily opens
        // http(s)://, file://, and anything else ShellExecute will handle.
        var raw = LinkBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(raw)) { LinkOut.Text = "enter a URL"; return; }
        try
        {
            if (raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
            {
                var local = new Uri(raw).LocalPath;
                if (File.Exists(local))
                {
                    LinkOut.Text = File.ReadAllText(local);
                    return;
                }
            }
            Process.Start(new ProcessStartInfo(raw) { UseShellExecute = true });
            LinkOut.Text = "opened: " + raw;
        }
        catch (Exception ex) { LinkOut.Text = ex.Message; }
    }
}
