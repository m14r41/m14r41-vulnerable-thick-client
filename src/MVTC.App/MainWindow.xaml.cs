using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Animation;
using MVTC.App.Views;
using MVTC.Challenges;
using MVTC.Core.Services;

namespace MVTC.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        KeyDown += OnKeyDown;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        var s = AuthService.CurrentSession;
        if (s is not null)
        {
            SessionBadge.Text = $"{s.Username} ({s.Role})";
            // Hide the orange lock glyph next to "Admin console" when the
            // session is already admin. For non-admin sessions the sidebar
            // still shows the entry (so #10/#11 can be exploited to flip it)
            // but renders it as locked.
            var isAdmin = string.Equals(s.Role, "admin", StringComparison.OrdinalIgnoreCase);
            AdminLockIcon.Visibility = isAdmin ? Visibility.Collapsed : Visibility.Visible;
        }

        var started = App.ScoreboardStarted;
        if (started is not null)
        {
            var client = new ScoreboardClient(started.Port);
            await ChallengesView.AttachAsync(client);
        }
        if (App.Auth is not null) AssetsView.Attach(App.Auth, App.InstallRoot);
        DocumentsView.Attach(App.InstallRoot);
        if (App.AppDatabase is not null && App.MockApiStarted is not null && App.MockUpdateStarted is not null)
        {
            NetworkView.Attach(App.AppDatabase, App.InstallRoot, App.MockApiStarted.Port, App.MockUpdateStarted.Port);
            UpdatesView.Attach(App.AppDatabase, App.InstallRoot, App.MockApiStarted.Port, App.MockUpdateStarted.Port);
        }
        if (App.Progress is not null) AdminView.Attach(App.Progress.GetFlagPlaintext);
        DashboardView.LoadFromState();

        ThemeBtn.ToolTip = $"Theme: {MVTC.App.Services.ThemeService.Current.Name}";
    }

    private void StartTitleSweep()
    {
        // No longer used; the animated accent was removed in favour of the
        // clean static separator.
    }

    public void NavTo(string tag)
    {
        var rb = tag switch
        {
            "Dashboard"  => NavDashboard,
            "Assets"     => NavAssets,
            "Documents"  => NavDocs,
            "Network"    => NavNetwork,
            "Updates"    => NavUpdates,
            "Shell"      => NavShell,
            "Admin"      => NavAdmin,
            "Account"    => NavAccount,
            "Settings"   => NavSettings,
            "Capture"    => NavCapture,
            "Challenges" => NavChallenges,
            "About"      => NavAbout,
            _ => (RadioButton?)null
        };
        if (rb is not null) rb.IsChecked = true;
    }

    private void OnNavChecked(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton rb || rb.Tag is not string tag) return;
        DashboardView.Visibility      = tag == "Dashboard"  ? Visibility.Visible : Visibility.Collapsed;
        AssetsView.Visibility         = tag == "Assets"     ? Visibility.Visible : Visibility.Collapsed;
        DocumentsView.Visibility      = tag == "Documents"  ? Visibility.Visible : Visibility.Collapsed;
        NetworkView.Visibility        = tag == "Network"    ? Visibility.Visible : Visibility.Collapsed;
        UpdatesHostGrid.Visibility    = tag == "Updates"    ? Visibility.Visible : Visibility.Collapsed;
        ShellView.Visibility          = tag == "Shell"      ? Visibility.Visible : Visibility.Collapsed;
        AdminView.Visibility          = tag == "Admin"      ? Visibility.Visible : Visibility.Collapsed;
        AccountView.Visibility        = tag == "Account"    ? Visibility.Visible : Visibility.Collapsed;
        SettingsView.Visibility       = tag == "Settings"   ? Visibility.Visible : Visibility.Collapsed;
        CaptureView.Visibility        = tag == "Capture"    ? Visibility.Visible : Visibility.Collapsed;
        if (tag == "Capture") CaptureView.Refresh();
        ChallengesHostGrid.Visibility = tag == "Challenges" ? Visibility.Visible : Visibility.Collapsed;
        AboutView.Visibility          = tag == "About"      ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnLogout(object sender, RoutedEventArgs e)
    {
        App.Auth?.Logout();
        new LoginWindow().Show();
        Close();
    }

    private void OnCycleTheme(object sender, RoutedEventArgs e)
    {
        MVTC.App.Services.ThemeService.Cycle(App.InstallRoot);
        ThemeBtn.ToolTip = $"Theme: {MVTC.App.Services.ThemeService.Current.Name}";
    }

    private void OnCycleLayout(object sender, RoutedEventArgs e)
    {
        MVTC.App.Services.LayoutService.Cycle(App.InstallRoot);
        LayoutBtn.ToolTip = $"Layout: {MVTC.App.Services.LayoutService.CurrentName}";
    }

    private void OnSearchFocus(object sender, RoutedEventArgs e)
    {
        if (TopSearch.Text == "search assets, reports, users...") { TopSearch.Text = ""; TopSearch.Opacity = 1; }
    }

    private void OnSearchBlur(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(TopSearch.Text)) { TopSearch.Text = "search assets, reports, users..."; TopSearch.Opacity = 0.75; }
    }

    private void OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F12 &&
            (Keyboard.Modifiers & (ModifierKeys.Control | ModifierKeys.Shift)) == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            if (App.AppDatabase is null) return;
            var win = new DebugDiagnosticsWindow(App.AppDatabase) { Owner = this };
            win.Show();
            e.Handled = true;
        }
    }

    // Mac traffic-light handlers
    private void OnDotClose(object sender, MouseButtonEventArgs e) => Close();
    private void OnDotMin(object sender, MouseButtonEventArgs e)   => WindowState = WindowState.Minimized;
    private void OnDotMax(object sender, MouseButtonEventArgs e)   =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
}
