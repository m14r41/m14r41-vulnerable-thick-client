using System.IO.Compression;
using System.Runtime.Versioning;
using System.Xml.Linq;
using Microsoft.Win32;
using MVTC.Core.Crypto;
using MVTC.Core.Logging;
using MVTC.Core.Secrets;

namespace MVTC.Core.Data;

/// <summary>
/// Plants the Phase-2 and Phase-3 flags into the places a learner has to go
/// to find them. See each private method for the per-challenge mapping.
/// </summary>
public sealed class AppStateSeeder
{
    private readonly string _installRoot;
    private readonly ProgressStore _progress;
    private readonly AppDb _appDb;
    private readonly LeakyLogger _logger;

    public string FlagsDir   => Path.Combine(_installRoot, "flags");
    public string SamplesDir => Path.Combine(_installRoot, "samples");
    public string ReportsDir => Path.Combine(_installRoot, "reports");
    public string StartupDir => Path.Combine(_installRoot, "Startup");

    public AppStateSeeder(string installRoot, ProgressStore progress, AppDb appDb, LeakyLogger logger)
    {
        _installRoot = installRoot;
        _progress = progress;
        _appDb = appDb;
        _logger = logger;
    }

    public void Seed()
    {
        Directory.CreateDirectory(_installRoot);
        Directory.CreateDirectory(FlagsDir);
        Directory.CreateDirectory(SamplesDir);
        Directory.CreateDirectory(ReportsDir);
        Directory.CreateDirectory(StartupDir);
        _progress.EnsureSeeded();

        var flag24 = _progress.GetFlagPlaintext(24)!;
        var flag25 = _progress.GetFlagPlaintext(25)!;
        var flag28 = _progress.GetFlagPlaintext(28)!;
        var flag34 = _progress.GetFlagPlaintext(34)!;
        var flag40 = _progress.GetFlagPlaintext(40)!;

        var flag10 = _progress.GetFlagPlaintext(10)!;
        _appDb.EnsureSeeded(flag24, flag40, flag34, flag10);

        // Upgrade path: make sure the shipping-default demo user exists even
        // when the Users table was seeded by an earlier install that didn't
        // know about m14r41.
        _appDb.EnsureUser(
            id: 5,
            username: "m14r41",
            passwordHash: MVTC.Core.Crypto.WeakCrypto.MdFive("test@123"),
            role: "user",
            apiKey: "pk_live_m14r41_ab9e2d");

        PlantConfigXml(flag25);
        PlantAuditLogLeak(flag28);
        PlantRegistryRoleValue();

        // Phase 3 plants
        PlantFile(29, "v29_autorun.txt");
        PlantFile(31, "v31.txt");
        PlantFile(32, "v32.txt");
        PlantFile(33, "v33.txt");
        PlantFile(35, "v35.txt");
        PlantFile(36, "v36.txt");
        PlantVaultFlagFor37();

        // Phase 4 plants
        PlantFile(1, "v01_dllh.txt");
        PlantFile(4, "v04_wrd.txt");
        PlantFile(7, "v07_sxs.txt");
        PlantFile(8, "v08_prs.txt");
        PlantFile(19, "v19_debug.txt");

        // v1.2 plants (#41-#45)
        PlantFile(43, "v43_url.txt");

        PlantZipSlipSample();
        PlantXxePayloadSample();
        PlantDeserializationGadgetSample();

        PlantSampleReport();
        PlantHelpTarget();

        // v1.4 plants (#46-#50)
        PlantAccountRecoveryLeak();
        PlantFile(47, "v47_idor.txt");
    }

    private void PlantAccountRecoveryLeak()
    {
        // VULN: #46 - leaks a sample reset request so an operator can
        // reconstruct the token formula from one real pair. The audit line is
        // intentionally verbose; a real audit log would log a request id,
        // never a plaintext token or its inputs.
        var sampleUser = "testops";
        var token = Crypto.WeakCrypto.MdFive(
            sampleUser + DateTime.UtcNow.ToString("yyyy-MM-dd") + HardcodedSecrets.RecoverySalt);
        _logger.Write("INFO", "accountrecovery",
            $"reset requested :: user={sampleUser} token={token} formula=md5(user+yyyy-MM-dd+salt) salt=see HardcodedSecrets");
    }

    // ---- Phase 2 ----

    private void PlantConfigXml(string flag25)
    {
        var path = Path.Combine(_installRoot, "config.xml");
        if (File.Exists(path)) return;
        var doc = new XDocument(
            new XComment(" MVTC configuration - intentional insecure storage demo. Do NOT model production config on this file. "),
            new XElement("Config",
                new XElement("Database",
                    new XElement("Path", "MVTC.db"),
                    new XElement("Password", "sqlite_sa_2024")),
                new XElement("Updater",
                    new XElement("Url", "http://127.0.0.1:5090/manifest.json"),
                    new XElement("CheckSignature", "false")),
                new XElement("Crypto",
                    new XElement("EncryptionKey", HardcodedSecrets.EncryptionKey),
                    new XElement("ApiKey", HardcodedSecrets.LegacyApiKey)),
                new XElement("Secrets",
                    new XComment(" Operations: password rotation ticket NET-412 open since Q2 2024. "),
                    new XElement("ServiceAccountPassword", flag25),
                    new XElement("LegacyToken", "token_7a9c3e1b_rotateme")),
                new XElement("Debug",
                    new XElement("Enabled", "false"),
                    new XElement("Hotkey", "Ctrl+Shift+F12"))));
        doc.Save(path);
    }

    private void PlantAuditLogLeak(string flag28)
    {
        _logger.Write("INFO", "startup", "MVTC runtime initializing (verbose=true)");
        _logger.Write("DEBUG", "config", "key=update_url value=http://127.0.0.1:5090/manifest.json");
        _logger.Write("DEBUG", "config", "key=encryption_key value=" + HardcodedSecrets.EncryptionKey);
        _logger.Write("INFO",  "session",  $"restored last session; recovery_token={flag28}");
        _logger.Write("INFO",  "ready",    "scoreboard online");
    }

    private void PlantRegistryRoleValue()
    {
        if (!OperatingSystem.IsWindows()) return;
        PlantRegistryRoleValueWindows();
    }

    [SupportedOSPlatform("windows")]
    private static void PlantRegistryRoleValueWindows()
    {
        try
        {
            using var sw = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\M14R41 Labs\MVTC");
            if (sw is null) return;
            if (sw.GetValue("role") is null) sw.SetValue("role", "user", RegistryValueKind.String);
            if (sw.GetValue("EncKey") is null) sw.SetValue("EncKey", HardcodedSecrets.EncryptionKey, RegistryValueKind.String);
        }
        catch
        {
            // Not fatal; see SETUP.md for the registry fallback recipe.
        }
    }

    // ---- Phase 3 ----

    private void PlantFile(int vulnNo, string filename)
    {
        var path = Path.Combine(FlagsDir, filename);
        if (File.Exists(path)) return;
        File.WriteAllText(path, _progress.GetFlagPlaintext(vulnNo) ?? "");
    }

    private void PlantVaultFlagFor37()
    {
        var dir = Path.Combine(_installRoot, "vault");
        Directory.CreateDirectory(dir);
        PlantIfMissing(Path.Combine(dir, "flag_37.txt"), _progress.GetFlagPlaintext(37) ?? "");
        PlantIfMissing(Path.Combine(dir, "flag_06.txt"), _progress.GetFlagPlaintext(6)  ?? "");
        PlantIfMissing(Path.Combine(dir, "flag_12.txt"), _progress.GetFlagPlaintext(12) ?? "");
    }

    private static void PlantIfMissing(string path, string content)
    {
        if (File.Exists(path)) return;
        File.WriteAllText(path, content);
    }

    private void PlantZipSlipSample()
    {
        var path = Path.Combine(SamplesDir, "zipslip.zip");
        if (File.Exists(path)) return;
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        // Legit entry so a casual listing shows "normal" content.
        var benign = zip.CreateEntry("readme.txt");
        using (var w = new StreamWriter(benign.Open())) w.Write("MVTC Zip Slip lab sample - see SOLUTIONS/30-zip-slip.md.");
        // VULN: #30 - path-traversal entry name. Extracting with Path.Combine
        // lands this file outside the destination directory.
        var escaping = zip.CreateEntry("../v30_slip.txt");
        using (var w = new StreamWriter(escaping.Open())) w.Write(_progress.GetFlagPlaintext(30) ?? "");
    }

    private void PlantXxePayloadSample()
    {
        var path = Path.Combine(SamplesDir, "payload.xml");
        if (File.Exists(path)) return;
        // Reference flags\v36.txt via a file: URL. The entity reference lands
        // in <leak>, which the XmlImportService returns as part of OuterXml.
        var target = Path.Combine(FlagsDir, "v36.txt").Replace('\\', '/');
        var xml =
            $"<?xml version=\"1.0\"?>\n" +
            $"<!DOCTYPE profile [\n" +
            $"  <!ENTITY xxe SYSTEM \"file:///{target}\">\n" +
            $"]>\n" +
            $"<profile>\n" +
            $"  <name>test</name>\n" +
            $"  <leak>&xxe;</leak>\n" +
            $"</profile>\n";
        File.WriteAllText(path, xml);
    }

    private void PlantDeserializationGadgetSample()
    {
        var path = Path.Combine(SamplesDir, "gadget.json");
        if (File.Exists(path)) return;
        var target = Path.Combine(FlagsDir, "v33.txt").Replace("\\", "\\\\");
        var json =
            "{\n" +
            "  \"$type\": \"MVTC.Core.Services.Vuln.StateProbe, MVTC.Core\",\n" +
            $"  \"Path\": \"{target}\"\n" +
            "}\n";
        File.WriteAllText(path, json);
    }

    private void PlantSampleReport()
    {
        var path = Path.Combine(ReportsDir, "quarterly.txt");
        if (File.Exists(path)) return;
        File.WriteAllText(path, "MVTC Quarterly Report\n=====================\n\n(stub - reports root used by #32 path-traversal lab)\n");
    }

    private void PlantHelpTarget()
    {
        var path = Path.Combine(_installRoot, "help", "index.chm.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path)) return;
        File.WriteAllText(path, "MVTC Help (stub) - see docs/SOLUTIONS/31-chm-injection.md");
    }
}
