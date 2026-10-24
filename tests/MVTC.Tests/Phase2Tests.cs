using System.Text;
using System.Xml.Linq;
using Microsoft.Data.Sqlite;
using MVTC.Core.Crypto;
using MVTC.Core.Data;
using MVTC.Core.Logging;
using MVTC.Core.Secrets;
using Xunit;

namespace MVTC.Tests;

public class Phase2Tests
{
    private static (string Root, AppStateSeeder Seeder, ProgressStore Progress, AppDb AppDb) Fresh()
    {
        var root = Path.Combine(Path.GetTempPath(), $"mvtc-p2-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var progress = new ProgressStore(Path.Combine(root, "progress.db"));
        var appDb = new AppDb(Path.Combine(root, "MVTC.db"));
        var log = new LeakyLogger(Path.Combine(root, "logs", "audit.log"));
        var seeder = new AppStateSeeder(root, progress, appDb, log);
        seeder.Seed();
        return (root, seeder, progress, appDb);
    }

    [Fact]
    public void Challenge26_Flag_Is_Hardcoded_In_Binary_Constant()
    {
        var (_, _, p, _) = Fresh();
        var planted = p.GetFlagPlaintext(26);
        Assert.Equal(HardcodedSecrets.LegacyLicenseFlag, planted);
    }

    [Fact]
    public void WeakCrypto_RoundTrips_With_Hardcoded_Key()
    {
        var plaintext = "MVTC{v24_test}";
        var ct = WeakCrypto.EncryptEcb(plaintext);
        Assert.NotEqual(Encoding.UTF8.GetBytes(plaintext), ct);
        var back = WeakCrypto.DecryptEcb(ct);
        Assert.Equal(plaintext, back);
    }

    [Fact]
    public void Challenge24_FlagCipher_Decrypts_With_Hardcoded_Key()
    {
        var (_, _, p, appDb) = Fresh();
        var expected = p.GetFlagPlaintext(24);
        var cipherB64 = appDb.GetConfigValue("FlagCipher");
        Assert.NotNull(cipherB64);
        var recovered = WeakCrypto.DecryptEcb(Convert.FromBase64String(cipherB64!));
        Assert.Equal(expected, recovered);
    }

    [Fact]
    public void Challenge25_Flag_Appears_In_ConfigXml_ServiceAccountPassword()
    {
        var (root, _, p, _) = Fresh();
        var expected = p.GetFlagPlaintext(25);
        var doc = XDocument.Load(Path.Combine(root, "config.xml"));
        var pw = doc.Root!.Element("Secrets")!.Element("ServiceAccountPassword")!.Value;
        Assert.Equal(expected, pw);
    }

    [Fact]
    public void Challenge28_Flag_Appears_In_AuditLog()
    {
        var (root, _, p, _) = Fresh();
        var expected = p.GetFlagPlaintext(28);
        var contents = File.ReadAllText(Path.Combine(root, "logs", "audit.log"));
        Assert.Contains(expected!, contents);
    }

    [Fact]
    public void Challenge40_Flag_Appears_In_Config_DebugFlag_Row()
    {
        var (_, _, p, appDb) = Fresh();
        var expected = p.GetFlagPlaintext(40);
        var row = appDb.GetConfigValue("DebugFlag");
        Assert.Equal(expected, row);
    }

    [Fact]
    public void AppDb_Seeds_All_Four_User_Rows()
    {
        var (_, _, _, appDb) = Fresh();
        using var conn = appDb.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT username, role FROM Users ORDER BY id;";
        using var r = cmd.ExecuteReader();
        var rows = new List<string>();
        while (r.Read()) rows.Add($"{r.GetString(0)}:{r.GetString(1)}");
        Assert.Equal(new[] { "admin:admin", "jdoe:user", "svc_backup:admin", "auditor:user" }, rows);
    }

    [Fact]
    public void Admin_Login_Succeeds_With_MD5_Password()
    {
        var (root, _, _, appDb) = Fresh();
        var auth = new MVTC.Core.Services.AuthService(appDb, new LeakyLogger(Path.Combine(root, "logs", "audit.log")));
        var s = auth.Login("admin", "admin");
        Assert.NotNull(s);
        Assert.Equal("admin", s!.Role);
    }

    [Fact]
    public void SvcBackup_Login_Succeeds_With_Plaintext_Password()
    {
        var (root, _, _, appDb) = Fresh();
        var auth = new MVTC.Core.Services.AuthService(appDb, new LeakyLogger(Path.Combine(root, "logs", "audit.log")));
        var s = auth.Login("svc_backup", "Backup@2024");
        Assert.NotNull(s);
    }

    [Fact]
    public void Current_Session_Holds_Plaintext_Password_For_MemDump()
    {
        var (root, _, _, appDb) = Fresh();
        var auth = new MVTC.Core.Services.AuthService(appDb, new LeakyLogger(Path.Combine(root, "logs", "audit.log")));
        auth.Login("jdoe", "password");
        Assert.NotNull(MVTC.Core.Services.AuthService.CurrentSession);
        Assert.Equal("password", MVTC.Core.Services.AuthService.CurrentSession!.PlaintextPassword);
    }

    [Fact]
    public void Seeded_Flag_For_26_Is_Submittable_And_Awards_Points()
    {
        var (_, _, p, _) = Fresh();
        var r = p.Submit(26, HardcodedSecrets.LegacyLicenseFlag);
        Assert.Equal(SubmitOutcome.Solved, r.Outcome);
        Assert.Equal(50, r.AwardedPoints);
    }
}
