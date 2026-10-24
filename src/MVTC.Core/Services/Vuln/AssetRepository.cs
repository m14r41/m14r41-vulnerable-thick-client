using Microsoft.Data.Sqlite;
using MVTC.Core.Data;

namespace MVTC.Core.Services.Vuln;

public sealed record AssetRow(int Id, int OwnerId, string Name, string? SecretNote);

/// <summary>
/// VULN: #34 - CWE-89 - SQL injection via string concatenation.
/// Builds the WHERE clause by interpolating the user's query directly into SQL.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #34): parameterize the query (<c>WHERE name LIKE $q AND
///   owner_id = $owner</c>). Never bind user input via <c>$"...{q}..."</c>.
/// </remarks>
public sealed class AssetRepository
{
    private readonly AppDb _db;

    public AssetRepository(AppDb db) { _db = db; }

    public IReadOnlyList<AssetRow> Search(int currentUserId, string query)
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        // VULN: #34 - string.Format straight into the SQL text. Also missing
        // the owner-scoping clause when the search is "advanced" - see below.
        cmd.CommandText =
            $"SELECT id, owner_id, name, secret_note FROM Assets " +
            $"WHERE owner_id = {currentUserId} AND name LIKE '%{query}%';";
        using var r = cmd.ExecuteReader();
        var rows = new List<AssetRow>();
        while (r.Read())
        {
            rows.Add(new AssetRow(
                r.GetInt32(0),
                r.GetInt32(1),
                r.GetString(2),
                r.IsDBNull(3) ? null : r.GetString(3)));
        }
        return rows;
    }

    public string LastQuery { get; private set; } = "";

    public (string Sql, IReadOnlyList<string> Rows) RunDiagnostic(int currentUserId, string query)
    {
        var sql = $"SELECT id, owner_id, name, secret_note FROM Assets WHERE owner_id = {currentUserId} AND name LIKE '%{query}%';";
        LastQuery = sql;
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        using var r = cmd.ExecuteReader();
        var rows = new List<string>();
        while (r.Read())
        {
            var line = new List<string>();
            for (var i = 0; i < r.FieldCount; i++)
                line.Add(r.IsDBNull(i) ? "<null>" : r.GetValue(i).ToString() ?? "");
            rows.Add(string.Join(" | ", line));
        }
        return (sql, rows);
    }
}
