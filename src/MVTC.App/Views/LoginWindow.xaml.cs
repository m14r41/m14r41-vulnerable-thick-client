using System.Windows;
using System.Windows.Input;
using MVTC.Core.Services;

namespace MVTC.App.Views;

public partial class LoginWindow : Window
{
    public LoginWindow()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            // Pre-fill the demo password so first-time users can just click
            // Sign in. Still a lab convenience; real users clear and retype.
            PasswordBox.Password = "test@123";
            UsernameBox.Focus();
        };
    }

    private void OnToggleNotes(object sender, RoutedEventArgs e)
    {
        var open = NotesBody.Visibility == Visibility.Visible;
        NotesBody.Visibility = open ? Visibility.Collapsed : Visibility.Visible;
        // Chevron right (E70D) when collapsed, chevron down (E70D) when open.
        // Use ScaleTransform for rotation hint without needing a 2nd icon.
        NotesCaret.Text = open ? "" : "";
    }

    private void OnSignIn(object sender, RoutedEventArgs e)
    {
        var user = UsernameBox.Text.Trim();
        var pwd = PasswordBox.Password;
        if (string.IsNullOrWhiteSpace(user)) { ErrorText.Text = "Enter a username."; return; }
        if (App.Auth is null)                 { ErrorText.Text = "Auth service not ready."; return; }
        var session = App.Auth.Login(user, pwd);
        if (session is null) { ErrorText.Text = "Invalid credentials. Access denied."; return; }
        new MainWindow().Show();
        Close();
    }

    private void OnDotClose(object sender, MouseButtonEventArgs e) => Close();
    private void OnDotMin(object sender, MouseButtonEventArgs e)   => WindowState = WindowState.Minimized;
    private void OnDotMax(object sender, MouseButtonEventArgs e)   =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnCycleTheme(object sender, RoutedEventArgs e)
    {
        MVTC.App.Services.ThemeService.Cycle(App.InstallRoot);
        ThemeBtn.ToolTip = $"Theme: {MVTC.App.Services.ThemeService.Current.Name}";
    }

    // #46 - predictable account-recovery token. The dialog is a convenience
    // wrapper around the same vulnerable code path used by the post-login
    // Account panel, so the challenge is reachable with or without a session.
    private void OnForgotPassword(object sender, RoutedEventArgs e)
    {
        var dlg = new ForgotPasswordDialog { Owner = this };
        dlg.ShowDialog();
    }
}
