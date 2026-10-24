using Microsoft.Data.Sqlite;
using MVTC.Core.Crypto;

namespace MVTC.Core.Data;

/// <summary>
/// MVTC.db - the application database (Users, Assets, Sessions, Config, AuditLog).
/// Pre-seeded on first launch. Different users exercise different vulnerability paths
/// (see docs). Everything here is intentional insecurity: MD5 passwords, plaintext
/// credential storage, AES-ECB with a hardcoded key, and secrets left in config.
/// </summary>
public sealed class AppDb
{
    private readonly string _connectionString;
    public string DbPath { get; }

    public AppDb(string dbPath)
    {
        DbPath = dbPath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();
    }

    public SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        return c;
    }

    public void EnsureSeeded(string flagCipherPlaintext, string flagDebugBackdoor, string flagSqliInAsset102, string flagAdminApiKey)
    {
        var dir = Path.GetDirectoryName(DbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        Exec(conn, tx, Schema);
        var count = ScalarLong(conn, tx, "SELECT COUNT(*) FROM Users;");
        if (count == 0) SeedRows(conn, tx, flagCipherPlaintext, flagDebugBackdoor, flagSqliInAsset102, flagAdminApiKey);
        tx.Commit();
    }

    /// <summary>Inserts the user if it does not already exist (upgrade path).</summary>
    public void EnsureUser(int id, string username, string passwordHash, string role, string? apiKey)
    {
        using var conn = Open();
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM Users WHERE username = $u;";
        check.Parameters.AddWithValue("$u", username);
        var n = Convert.ToInt32(check.ExecuteScalar());
        if (n > 0) return;
        using var ins = conn.CreateCommand();
        ins.CommandText = "INSERT INTO Users(id, username, password_hash, role, api_key) VALUES($id,$u,$h,$r,$k);";
        ins.Parameters.AddWithValue("$id", id);
        ins.Parameters.AddWithValue("$u", username);
        ins.Parameters.AddWithValue("$h", passwordHash);
        ins.Parameters.AddWithValue("$r", role);
        ins.Parameters.AddWithValue("$k", (object?)apiKey ?? DBNull.Value);
        ins.ExecuteNonQuery();
    }

    // ---- queries used by UI, debug menu, and later-phase SQLi target ----

    public IReadOnlyList<(string Key, string Value)> ListConfig()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key, value FROM Config ORDER BY key;";
        using var r = cmd.ExecuteReader();
        var list = new List<(string, string)>();
        while (r.Read()) list.Add((r.GetString(0), r.GetString(1)));
        return list;
    }

    public (int Id, string Role)? FindUser(string username, string md5PasswordHex)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        // Parameterized - the SQLi vulnerability lives in Phase 3's AssetRepository.
        cmd.CommandText = "SELECT id, role FROM Users WHERE username = $u AND password_hash = $h;";
        cmd.Parameters.AddWithValue("$u", username);
        cmd.Parameters.AddWithValue("$h", md5PasswordHex);
        using var r = cmd.ExecuteReader();
        return r.Read() ? (r.GetInt32(0), r.GetString(1)) : null;
    }

    public string? GetConfigValue(string key)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM Config WHERE key = $k;";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    // ---- seeding ----

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT
        );
        CREATE TABLE IF NOT EXISTS Assets (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            secret_note TEXT
        );
        CREATE TABLE IF NOT EXISTS Sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS Config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS AuditLog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT
        );
        """;

    private static void SeedRows(SqliteConnection conn, SqliteTransaction tx, string flagCipherPlaintext, string flagDebugBackdoor, string flagSqliInAsset102, string flagAdminApiKey)
    {
        // Users - four very different weakness paths.
        // VULN: #10 - admin's api_key IS the flag; it only shows up to a caller
        //       whose role check (RoleProvider) returns "admin". Flipping HKCU
        //       lets you reach the Users directory and see it as "just another
        //       api_key column" among realistic-looking records.
        InsertUser(conn, tx, 1, "admin",      WeakCrypto.MdFive("admin"),     "admin", flagAdminApiKey);
        // VULN: #24 - new onboarding user. Visible-by-default to the lab tester
        //       on the login screen (shipping-defaults are a real-world misconfig
        //       - admins forget to remove the demo account before go-live).
        InsertUser(conn, tx, 5, "m14r41",     WeakCrypto.MdFive("test@123"),  "user",  "pk_live_m14r41_ab9e2d");
        InsertUser(conn, tx, 2, "jdoe",       WeakCrypto.MdFive("password"),  "user",  null);                           // VULN: #24 - MD5('password')
        InsertUser(conn, tx, 3, "svc_backup", /* plaintext */ "Backup@2024",  "admin", null);                           // VULN: #25 - plaintext password in DB
        InsertUser(conn, tx, 4, "auditor",    Convert.ToBase64String(WeakCrypto.EncryptEcb("Audit!2026")), "user", null); // VULN: #24 - AES-ECB with the hardcoded key

        // Assets - IDOR fodder (jdoe owns 101 only).
        InsertAsset(conn, tx, 101, 2, "Laptop-TN-0456", "BitLocker PIN: 8842");
        // VULN: #34 - jdoe (owner_id=2) shouldn't be able to read asset 102. A
        // SQLi UNION SELECT on the Assets search exfiltrates this row.
        InsertAsset(conn, tx, 102, 1, "Server-DC01",     flagSqliInAsset102);
        InsertAsset(conn, tx, 103, 3, "Backup-NAS",      "smb://nas/backup pw=N@S2024");

        // Session - long-lived; UAF fodder for #22 later.
        InsertSession(conn, tx, "SESS-0000000001", 2, DateTime.UtcNow.AddYears(1));

        // Config - the "many ways to the same secret" plants.
        InsertConfig(conn, tx, "db_password",     "sqlite_sa_2024");                                                     // VULN: #25 - plaintext
        InsertConfig(conn, tx, "update_url",      "http://127.0.0.1:5090/manifest.json");                                // Phase 4 (#38)
        InsertConfig(conn, tx, "encryption_key",  "D0NTUSETHISKEY00");                                                   // VULN: #24/#26 - also in binary/registry
        InsertConfig(conn, tx, "debug_mode",      "false");                                                              // VULN: #40 - flip to true
        InsertConfig(conn, tx, "DebugFlag",       flagDebugBackdoor);                                                    // VULN: #40 - revealed by debug SQL console
        // VULN: #24 - AES-ECB(hardcoded key, static IV) of the random #24 flag plaintext.
        InsertConfig(conn, tx, "FlagCipher",      Convert.ToBase64String(WeakCrypto.EncryptEcb(flagCipherPlaintext)));

        // AuditLog - pre-seeded "verbose startup" line so #28's log-leak path has
        // content even on first launch.
        InsertAudit(conn, tx, "system", "startup", "service bootstrap complete; see logs/audit.log for runtime events");
    }

    private static void InsertUser(SqliteConnection conn, SqliteTransaction tx, int id, string username, string hash, string role, string? apiKey)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO Users(id, username, password_hash, role, api_key) VALUES($id,$u,$h,$r,$k);";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$u", username);
        cmd.Parameters.AddWithValue("$h", hash);
        cmd.Parameters.AddWithValue("$r", role);
        cmd.Parameters.AddWithValue("$k", (object?)apiKey ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private static void InsertAsset(SqliteConnection conn, SqliteTransaction tx, int id, int ownerId, string name, string? note)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO Assets(id, owner_id, name, secret_note) VALUES($id,$o,$n,$s);";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$o", ownerId);
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$s", (object?)note ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private static void InsertSession(SqliteConnection conn, SqliteTransaction tx, string token, int userId, DateTime expires)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO Sessions(token, user_id, expires) VALUES($t,$u,$e);";
        cmd.Parameters.AddWithValue("$t", token);
        cmd.Parameters.AddWithValue("$u", userId);
        cmd.Parameters.AddWithValue("$e", expires.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    private static void InsertConfig(SqliteConnection conn, SqliteTransaction tx, string key, string value)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO Config(key, value) VALUES($k,$v);";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    private static void InsertAudit(SqliteConnection conn, SqliteTransaction tx, string user, string action, string detail)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO AuditLog(ts, user, action, detail) VALUES($t,$u,$a,$d);";
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$u", user);
        cmd.Parameters.AddWithValue("$a", action);
        cmd.Parameters.AddWithValue("$d", detail);
        cmd.ExecuteNonQuery();
    }

    private static long ScalarLong(SqliteConnection conn, SqliteTransaction tx, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    private static void Exec(SqliteConnection conn, SqliteTransaction tx, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}
