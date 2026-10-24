using Microsoft.Data.Sqlite;
using MVTC.Core.Crypto;
using MVTC.Core.Models;

namespace MVTC.Core.Data;

/// <summary>
/// Reads and writes <c>progress.db</c>. Seeds the 40 challenges on first use and
/// records flag submissions, status transitions, points, and rank.
/// </summary>
public sealed class ProgressStore
{
    private readonly string _connectionString;
    public string DbPath { get; }

    public ProgressStore(string dbPath)
    {
        DbPath = dbPath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();
    }

    public void EnsureSeeded()
    {
        var dir = Path.GetDirectoryName(DbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using var conn = Open();
        using (var tx = conn.BeginTransaction())
        {
            Exec(conn, tx, """
                CREATE TABLE IF NOT EXISTS Challenges (
                    id INTEGER PRIMARY KEY,
                    vuln_no INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    cwe TEXT NOT NULL,
                    flag_hash TEXT NOT NULL,
                    prereq_ids TEXT NOT NULL DEFAULT '',
                    writeup_path TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS Progress (
                    challenge_id INTEGER PRIMARY KEY REFERENCES Challenges(id),
                    status TEXT NOT NULL,
                    solved_at TEXT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    hint_cost_paid INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS Profile (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    total_points INTEGER NOT NULL DEFAULT 0,
                    rank TEXT NOT NULL DEFAULT 'Script Kiddie',
                    started_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS FlagPlaintext (
                    challenge_id INTEGER PRIMARY KEY REFERENCES Challenges(id),
                    plaintext TEXT NOT NULL
                );
                """);

            // Upsert: insert any challenge from ChallengeSeedData that isn't
            // already in the DB. On a fresh install this seeds all 45 rows;
            // on an upgrade it only adds the newly-defined ones (#41-#45),
            // leaving existing scored progress untouched.
            foreach (var seed in ChallengeSeedData.All)
            {
                using var check = conn.CreateCommand();
                check.Transaction = tx;
                check.CommandText = "SELECT COUNT(*) FROM Challenges WHERE vuln_no = $vn;";
                check.Parameters.AddWithValue("$vn", seed.VulnNo);
                var present = Convert.ToInt32(check.ExecuteScalar());
                if (present > 0) continue;

                var flag = seed.HardcodedFlag ?? FlagGenerator.NewRandom(seed.VulnNo, seed.Slug);
                var hash = FlagGenerator.Hash(flag);
                using var ins = conn.CreateCommand();
                ins.Transaction = tx;
                ins.CommandText = """
                    INSERT INTO Challenges(id, vuln_no, title, category, tier, points, cwe, flag_hash, prereq_ids, writeup_path)
                    VALUES($id, $vn, $t, $c, $tier, $p, $cwe, $h, $pre, $w);
                    INSERT INTO Progress(challenge_id, status) VALUES($id, $st);
                    INSERT INTO FlagPlaintext(challenge_id, plaintext) VALUES($id, $pt);
                    """;
                ins.Parameters.AddWithValue("$id", seed.VulnNo);
                ins.Parameters.AddWithValue("$vn", seed.VulnNo);
                ins.Parameters.AddWithValue("$t", seed.Title);
                ins.Parameters.AddWithValue("$c", seed.Category);
                ins.Parameters.AddWithValue("$tier", seed.Tier);
                ins.Parameters.AddWithValue("$p", seed.Points);
                ins.Parameters.AddWithValue("$cwe", seed.Cwe);
                ins.Parameters.AddWithValue("$h", hash);
                ins.Parameters.AddWithValue("$pre", seed.PrereqIds);
                ins.Parameters.AddWithValue("$w", seed.WriteupPath);
                ins.Parameters.AddWithValue("$st", LockedIfHasPrereq(seed.PrereqIds));
                ins.Parameters.AddWithValue("$pt", flag);
                ins.ExecuteNonQuery();
            }

            Exec(conn, tx, """
                INSERT OR IGNORE INTO Profile(singleton, total_points, rank, started_at)
                VALUES(1, 0, 'Script Kiddie', $now);
                """, ("$now", DateTime.UtcNow.ToString("O")));
            tx.Commit();
        }
    }

    public IReadOnlyList<ChallengeView> List() => List(includeHint: false);

    public IReadOnlyList<ChallengeView> List(bool includeHint)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT c.id, c.vuln_no, c.title, c.category, c.tier, c.points, c.cwe, c.flag_hash, c.prereq_ids, c.writeup_path,
                   p.status, p.solved_at, p.attempts, p.hint_cost_paid
            FROM Challenges c JOIN Progress p ON p.challenge_id = c.id
            ORDER BY c.vuln_no;
            """;
        using var r = cmd.ExecuteReader();
        var list = new List<ChallengeView>();
        while (r.Read())
        {
            var chall = new Challenge
            {
                Id = r.GetInt32(0),
                VulnNo = r.GetInt32(1),
                Title = r.GetString(2),
                Category = r.GetString(3),
                Tier = r.GetString(4),
                Points = r.GetInt32(5),
                Cwe = r.GetString(6),
                FlagHash = r.GetString(7),
                PrereqIds = r.GetString(8),
                WriteupPath = r.GetString(9)
            };
            var prog = new ProgressRow
            {
                ChallengeId = chall.Id,
                Status = r.GetString(10),
                SolvedAt = r.IsDBNull(11) ? null : r.GetString(11),
                Attempts = r.GetInt32(12),
                HintCostPaid = r.GetInt32(13)
            };
            var locked = string.Equals(prog.Status, "Locked", StringComparison.OrdinalIgnoreCase);
            list.Add(new ChallengeView { Challenge = chall, Progress = prog, IsLocked = locked });
        }
        return list;
    }

    public string? GetFlagPlaintext(int challengeId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT plaintext FROM FlagPlaintext WHERE challenge_id = $id;";
        cmd.Parameters.AddWithValue("$id", challengeId);
        return cmd.ExecuteScalar() as string;
    }

    public ProfileRow GetProfile()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT total_points, rank, started_at FROM Profile WHERE singleton = 1;";
        using var r = cmd.ExecuteReader();
        return r.Read()
            ? new ProfileRow { TotalPoints = r.GetInt32(0), Rank = r.GetString(1), StartedAt = r.GetString(2) }
            : new ProfileRow();
    }

    /// <summary>
    /// Returns one row per challenge: id, points value, and whether the
    /// current user has solved it. Used by the dashboard tiles and the
    /// Mission-Control sparkline.
    /// </summary>
    public List<ChallengeStatusRow> GetAllPointsAndStatus()
    {
        var list = new List<ChallengeStatusRow>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT c.id, c.points, p.status
            FROM Challenges c LEFT JOIN Progress p ON p.challenge_id = c.id
            ORDER BY c.id;
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var id = r.GetInt32(0);
            var points = r.GetInt32(1);
            var status = r.IsDBNull(2) ? "Open" : r.GetString(2);
            list.Add(new ChallengeStatusRow(id, points, string.Equals(status, "Solved", StringComparison.OrdinalIgnoreCase)));
        }
        return list;
    }

    public SubmitResult Submit(int challengeId, string submission)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();

        using var get = conn.CreateCommand();
        get.Transaction = tx;
        get.CommandText = """
            SELECT c.flag_hash, c.points, p.status
            FROM Challenges c JOIN Progress p ON p.challenge_id = c.id
            WHERE c.id = $id;
            """;
        get.Parameters.AddWithValue("$id", challengeId);
        using var r = get.ExecuteReader();
        if (!r.Read()) return SubmitResult.NotFound;
        var expectedHash = r.GetString(0);
        var points = r.GetInt32(1);
        var currentStatus = r.GetString(2);
        r.Close();

        var submittedHash = FlagGenerator.Hash(submission);

        using var incAttempts = conn.CreateCommand();
        incAttempts.Transaction = tx;
        incAttempts.CommandText = "UPDATE Progress SET attempts = attempts + 1 WHERE challenge_id = $id;";
        incAttempts.Parameters.AddWithValue("$id", challengeId);
        incAttempts.ExecuteNonQuery();

        if (string.Equals(currentStatus, "Locked", StringComparison.OrdinalIgnoreCase))
        {
            tx.Commit();
            return SubmitResult.Locked;
        }

        if (!FlagGenerator.ConstantTimeEquals(submittedHash, expectedHash))
        {
            tx.Commit();
            return SubmitResult.Incorrect;
        }

        if (string.Equals(currentStatus, "Solved", StringComparison.OrdinalIgnoreCase))
        {
            tx.Commit();
            return new SubmitResult(SubmitOutcome.AlreadySolved, 0, GetProfile());
        }

        using var mark = conn.CreateCommand();
        mark.Transaction = tx;
        mark.CommandText = "UPDATE Progress SET status = 'Solved', solved_at = $now WHERE challenge_id = $id;";
        mark.Parameters.AddWithValue("$id", challengeId);
        mark.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
        mark.ExecuteNonQuery();

        UnlockDependents(conn, tx, challengeId);

        var newTotal = RecomputePoints(conn, tx);
        var newRank = RankCalculator.ForPoints(newTotal);
        using var updProfile = conn.CreateCommand();
        updProfile.Transaction = tx;
        updProfile.CommandText = "UPDATE Profile SET total_points = $pts, rank = $rk WHERE singleton = 1;";
        updProfile.Parameters.AddWithValue("$pts", newTotal);
        updProfile.Parameters.AddWithValue("$rk", newRank);
        updProfile.ExecuteNonQuery();

        tx.Commit();
        return new SubmitResult(SubmitOutcome.Solved, points, new ProfileRow { TotalPoints = newTotal, Rank = newRank, StartedAt = "" });
    }

    public void SoftReset()
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        Exec(conn, tx, """
            UPDATE Progress SET status = CASE WHEN challenge_id IN (
                SELECT id FROM Challenges WHERE prereq_ids <> ''
            ) THEN 'Locked' ELSE 'Unsolved' END,
            solved_at = NULL, attempts = 0, hint_cost_paid = 0;
            UPDATE Profile SET total_points = 0, rank = 'Script Kiddie' WHERE singleton = 1;
            """);
        tx.Commit();
    }

    // ---- helpers ----

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        using var pragma = c.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys = ON;";
        pragma.ExecuteNonQuery();
        return c;
    }

    private static int RecomputePoints(SqliteConnection conn, SqliteTransaction tx)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT COALESCE(SUM(c.points), 0)
            FROM Challenges c JOIN Progress p ON p.challenge_id = c.id
            WHERE p.status = 'Solved';
            """;
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static void UnlockDependents(SqliteConnection conn, SqliteTransaction tx, int solvedId)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT id, prereq_ids FROM Challenges WHERE prereq_ids LIKE '%' || $id || '%';
            """;
        cmd.Parameters.AddWithValue("$id", solvedId);
        var pending = new List<(int Id, string Prereqs)>();
        using (var r = cmd.ExecuteReader())
        {
            while (r.Read()) pending.Add((r.GetInt32(0), r.GetString(1)));
        }
        foreach (var (id, prereqs) in pending)
        {
            var ids = prereqs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (!ids.Contains(solvedId.ToString())) continue;
            if (AllPrereqsSolved(conn, tx, ids))
            {
                using var upd = conn.CreateCommand();
                upd.Transaction = tx;
                upd.CommandText = "UPDATE Progress SET status = 'Unsolved' WHERE challenge_id = $cid AND status = 'Locked';";
                upd.Parameters.AddWithValue("$cid", id);
                upd.ExecuteNonQuery();
            }
        }
    }

    private static bool AllPrereqsSolved(SqliteConnection conn, SqliteTransaction tx, string[] ids)
    {
        foreach (var id in ids)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT status FROM Progress WHERE challenge_id = $id;";
            cmd.Parameters.AddWithValue("$id", int.Parse(id));
            var s = cmd.ExecuteScalar() as string;
            if (!string.Equals(s, "Solved", StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

    private static string LockedIfHasPrereq(string prereqIds) =>
        string.IsNullOrWhiteSpace(prereqIds) ? "Unsolved" : "Locked";

    private static long ScalarLong(SqliteConnection conn, SqliteTransaction tx, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    private static void Exec(SqliteConnection conn, SqliteTransaction tx, string sql, params (string, object)[] parms)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in parms) cmd.Parameters.AddWithValue(n, v);
        cmd.ExecuteNonQuery();
    }
}

public enum SubmitOutcome { Solved, AlreadySolved, Incorrect, Locked, NotFound }

public sealed record SubmitResult(SubmitOutcome Outcome, int AwardedPoints, ProfileRow Profile)
{
    public static readonly SubmitResult NotFound = new(SubmitOutcome.NotFound, 0, new ProfileRow());
    public static readonly SubmitResult Incorrect = new(SubmitOutcome.Incorrect, 0, new ProfileRow());
    public static readonly SubmitResult Locked = new(SubmitOutcome.Locked, 0, new ProfileRow());
}
