using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Data.Sqlite;
using MVTC.Core.Services;
using MVTC.Core.Services.Insecure;
using MVTC.Core.Services.Vuln;

namespace MVTC.App.Views;

public partial class PrivescLabPanel : UserControl
{
    private AdminFeatures? _admin;
    private readonly ObservableCollection<UserRow>   _users  = new();
    private readonly ObservableCollection<SealedRow> _sealed = new();

    public PrivescLabPanel()
    {
        InitializeComponent();
        UsersGrid.ItemsSource = _users;
        SealedGrid.ItemsSource = _sealed;
    }

    public void Attach(Func<int, string?> flagLookup)
    {
        _admin = new AdminFeatures(flagLookup);
        ExtraPriv.IsChecked = _admin.ExtraPrivilegeConfirmed;
        RefreshRole();
    }

    private void RefreshRole()
    {
        RoleProvider.Reload();
        // Show the EFFECTIVE role - session wins if present, otherwise fall
        // back to the HKCU registry role (which is what #10's exploit flips).
        var sessionRole = AuthService.CurrentSession?.Role;
        var effective = !string.IsNullOrEmpty(sessionRole) ? sessionRole : RoleProvider.CurrentRole;
        var src = !string.IsNullOrEmpty(sessionRole) ? "session" : "registry";
        RoleBadge.Text = $"role: {effective} ({src})";

        var isAdmin = string.Equals(effective, "admin", StringComparison.OrdinalIgnoreCase);
        RoleGateBanner.Visibility = isAdmin ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnReloadRole(object sender, RoutedEventArgs e)
    {
        RefreshRole();
        UsersError.Text = "role reloaded from registry";
    }

    private void OnLoadUsers(object sender, RoutedEventArgs e)
    {
        _users.Clear();
        UsersError.Text = "";
        if (_admin is null || !_admin.CanOpenAdminUsers())
        {
            UsersError.Text = "Access denied. Admin role required.";
            return;
        }
        try
        {
            if (App.AppDatabase is null) return;
            using var conn = App.AppDatabase.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, username, role, api_key FROM Users ORDER BY id;";
            using var r = cmd.ExecuteReader();
            var fakeEmails = new[] { "", "j.doe@m14r41.local", "svc_backup@m14r41.local", "auditor@m14r41.local" };
            var fakeLogins = new[] { "2026-10-21 09:14", "2026-10-22 11:02", "2026-10-19 18:40", "2026-10-15 07:30" };
            while (r.Read())
            {
                var id = r.GetInt32(0);
                _users.Add(new UserRow
                {
                    Id = id,
                    Username = r.GetString(1),
                    Role = r.GetString(2),
                    Email = id == 1 ? "admin@m14r41.local" : fakeEmails[Math.Min(id - 1, fakeEmails.Length - 1)],
                    ApiKey = r.IsDBNull(3) ? "" : r.GetString(3),
                    LastLogin = fakeLogins[Math.Min(id - 1, fakeLogins.Length - 1)]
                });
            }
        }
        catch (Exception ex) { UsersError.Text = ex.Message; }
    }

    private void OnOpenSealedVault(object sender, RoutedEventArgs e)
    {
        _sealed.Clear();
        if (_admin is null) return;
        // Mirror checkbox into the backing field so a debugger-flipped field
        // AND a UI click both work.
        _admin.ExtraPrivilegeConfirmed = ExtraPriv.IsChecked == true;
        foreach (var (name, value, note) in _admin.ListSealedSecrets())
            _sealed.Add(new SealedRow { Name = name, Value = value, Note = note });
    }

    private void OnVerifyIntegrity(object sender, RoutedEventArgs e)
    {
        if (_admin is null) return;
        // The signature field is only populated when IntegrityVerified is
        // true. In secure code that would be a server-signed capability;
        // here it is a public mutable bool that a tester flips via dnSpy or
        // x64dbg to force the client to release the signed token.
        VerifyOut.Text = _admin.BuildIntegrityReportJson();
    }

    private void OnLoadHelper(object sender, RoutedEventArgs e)
    {
        var (ok, err) = DllHelperLoader.TryLoadBareName(HelperDll.Text?.Trim() ?? "AppHelper.dll");
        HelperOut.Text = ok
            ? "module loaded"
            : err;
    }

    public sealed class UserRow
    {
        public int Id { get; set; }
        public string Username { get; set; } = "";
        public string Role { get; set; } = "";
        public string Email { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public string LastLogin { get; set; } = "";
    }

    public sealed class SealedRow
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string Note { get; set; } = "";
    }
}
