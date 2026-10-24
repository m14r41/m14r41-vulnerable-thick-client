using System.Text;
using System.Windows;
using Microsoft.Data.Sqlite;
using MVTC.Core.Data;

namespace MVTC.App.Views;

public partial class DebugDiagnosticsWindow : Window
{
    private readonly AppDb _appDb;

    public DebugDiagnosticsWindow(AppDb appDb)
    {
        _appDb = appDb;
        InitializeComponent();
    }

    private void OnDumpConfig(object sender, RoutedEventArgs e)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-- Config --");
        foreach (var (k, v) in _appDb.ListConfig())
            sb.AppendLine($"{k,-20} = {v}");
        Output.Text = sb.ToString();
    }

    private void OnDumpUsers(object sender, RoutedEventArgs e) => Dump("SELECT id, username, password_hash, role, api_key FROM Users;");
    private void OnDumpAssets(object sender, RoutedEventArgs e) => Dump("SELECT id, owner_id, name, secret_note FROM Assets;");

    private void OnRunSql(object sender, RoutedEventArgs e)
    {
        var sql = SqlInput.Text?.Trim();
        if (string.IsNullOrWhiteSpace(sql))
        {
            Output.Text = "(enter a SELECT)";
            return;
        }
        Dump(sql);
    }

    private void Dump(string sql)
    {
        try
        {
            using var conn = _appDb.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            using var r = cmd.ExecuteReader();
            var sb = new StringBuilder();
            // VULN: #40 - raw column names + rows dumped as-is. No row-level ACL,
            // no column masking, no auditing - the whole point of this menu.
            for (var i = 0; i < r.FieldCount; i++)
            {
                if (i > 0) sb.Append(" | ");
                sb.Append(r.GetName(i));
            }
            sb.AppendLine();
            while (r.Read())
            {
                for (var i = 0; i < r.FieldCount; i++)
                {
                    if (i > 0) sb.Append(" | ");
                    sb.Append(r.IsDBNull(i) ? "<null>" : r.GetValue(i).ToString());
                }
                sb.AppendLine();
            }
            Output.Text = sb.ToString();
        }
        catch (SqliteException ex)
        {
            // VULN: #40 (also #34 preview) - verbose error returned to the UI
            // leaks SQLite internals and query echo.
            Output.Text = $"SQLite error {ex.SqliteErrorCode} / extended {ex.SqliteExtendedErrorCode}\nQuery: {sql}\n\n{ex}";
        }
        catch (Exception ex)
        {
            Output.Text = ex.ToString();
        }
    }
}
