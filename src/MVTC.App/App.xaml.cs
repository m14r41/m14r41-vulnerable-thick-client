using System.IO;
using System.Windows;
using MVTC.Core.Data;
using MVTC.Core.Logging;
using MVTC.Core.Services;
using MVTC.MockApi;
using MVTC.MockUpdate;
using MVTC.Scoreboard;
using MVTC.VaultSvc;

namespace MVTC.App;

public partial class App : Application
{
    public static ScoreboardHost.Started? ScoreboardStarted { get; private set; }
    public static MockApiHost.Started? MockApiStarted { get; private set; }
    public static MockUpdateHost.Started? MockUpdateStarted { get; private set; }
    public static VaultPipeServer? VaultServer { get; private set; }

    public static string InstallRoot { get; private set; } = "";
    public static string ProgressDbPath { get; private set; } = "";

    public static ProgressStore? Progress { get; private set; }
    public static AppDb? AppDatabase { get; private set; }
    public static AuthService? Auth { get; private set; }
    public static LeakyLogger? Logger { get; private set; }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try
        {
            InstallRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MVTC");
            Directory.CreateDirectory(InstallRoot);
            ProgressDbPath = Path.Combine(InstallRoot, "progress.db");

            // Apply the persisted title-bar theme before the first window opens.
            MVTC.App.Services.ThemeService.Init(InstallRoot);
            MVTC.App.Services.LayoutService.Init(InstallRoot);

            var appDbPath = Path.Combine(InstallRoot, "MVTC.db");
            var auditLogPath = Path.Combine(InstallRoot, "logs", "audit.log");

            Progress = new ProgressStore(ProgressDbPath);
            AppDatabase = new AppDb(appDbPath);
            Logger = new LeakyLogger(auditLogPath);
            Auth = new AuthService(AppDatabase, Logger);

            var seeder = new AppStateSeeder(InstallRoot, Progress, AppDatabase, Logger);
            seeder.Seed();

            AuthService.RestoredRecoveryToken = Progress.GetFlagPlaintext(27);
            AuthService.FlagLookup = Progress.GetFlagPlaintext;

            // VULN: #42 - CWE-214 - Password in command-line arguments.
            // When MVTC is launched with --login-as <user> --password <pwd>,
            // the password is visible in `tasklist /v` and Process Explorer.
            // On successful silent-login we write a diagnostic audit entry
            // that includes the #42 token.
            TryHandleCliLogin(e.Args, Auth, Logger, Progress.GetFlagPlaintext(42));

            // Local services: scoreboard, mock API (#39 target), mock update
            // (#38 target), vault pipe (#37 target). All loopback-bound.
            ScoreboardStarted = await ScoreboardHost.StartAsync(ProgressDbPath, preferredPort: 0);
            var flag38 = Progress.GetFlagPlaintext(38) ?? "";
            var flag39 = Progress.GetFlagPlaintext(39) ?? "";
            MockApiStarted = await MockApiHost.StartAsync(flag39);
            MockUpdateStarted = await MockUpdateHost.StartAsync(flag38);
            VaultServer = new VaultPipeServer(
                Path.Combine(InstallRoot, "vault", "flag_37.txt"),
                Path.Combine(InstallRoot, "vault", "flag_06.txt"),
                Path.Combine(InstallRoot, "vault", "flag_12.txt"));

            MVTC.Core.Services.Vuln.RoleProvider.Reload();
            MVTC.Core.Services.Vuln.InjectionSentinels.Initialize(Progress.GetFlagPlaintext);

            File.WriteAllText(Path.Combine(InstallRoot, "scoreboard.port"), ScoreboardStarted.Port.ToString());
            File.WriteAllText(Path.Combine(InstallRoot, "mockapi.port"), MockApiStarted.Port.ToString());
            File.WriteAllText(Path.Combine(InstallRoot, "mockupdate.port"), MockUpdateStarted.Port.ToString());

            // Now that all backend services are up and Auth is ready, show the login window.
            new MVTC.App.Views.LoginWindow().Show();
        }
        catch (Exception ex)
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MVTC");
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "startup_error.log"),
                    $"{DateTime.UtcNow:O}\n\n{ex}\n");
            }
            catch { }
            MessageBox.Show(
                $"Failed to start MVTC:\n{ex.Message}\n\n{ex.StackTrace}",
                "MVTC - startup error", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private static void TryHandleCliLogin(string[] args, AuthService auth, LeakyLogger logger, string? flag42)
    {
        string? user = null, pwd = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--login-as", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) user = args[++i];
            else if (args[i].Equals("--password", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) pwd = args[++i];
        }
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pwd)) return;
        var s = auth.Login(user, pwd);
        if (s is not null)
            logger.Write("INFO", "cli", $"silent-login success user={user}; cli_pwd_was_visible=true; diag_token={flag42 ?? ""}");
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { VaultServer?.Dispose(); } catch { }
        try { ScoreboardStarted?.App.StopAsync().GetAwaiter().GetResult(); } catch { }
        try { MockApiStarted?.App.StopAsync().GetAwaiter().GetResult(); } catch { }
        try { MockUpdateStarted?.App.StopAsync().GetAwaiter().GetResult(); } catch { }
        base.OnExit(e);
    }
}
