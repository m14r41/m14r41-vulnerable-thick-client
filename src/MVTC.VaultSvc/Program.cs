// MVTCVaultSvc.exe - standalone Windows Service host for the deliberately
// insecure named-pipe server (VaultPipeServer.cs). Speaks SCM protocol via
// UseWindowsService() so `sc start MVTCVaultSvc` works; also runs cleanly
// as a console app for dev.
//
// Author: Madhurendra Kumar (M14R41) · M14R41 Labs · © 2026

using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MVTC.VaultSvc;

var installRoot = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MVTC");
Directory.CreateDirectory(installRoot);
Directory.CreateDirectory(Path.Combine(installRoot, "vault"));

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSingleton(_ => new VaultPipeServer(
    Path.Combine(installRoot, "vault", "flag_37.txt"),
    Path.Combine(installRoot, "vault", "flag_06.txt"),
    Path.Combine(installRoot, "vault", "flag_12.txt")));
builder.Services.AddHostedService<VaultSvcWorker>();
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "MVTCVaultSvc";
});

var host = builder.Build();
await host.RunAsync();

namespace MVTC.VaultSvc
{
    internal sealed class VaultSvcWorker : BackgroundService
    {
        private readonly VaultPipeServer _server;
        public VaultSvcWorker(VaultPipeServer server) { _server = server; }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // VaultPipeServer starts its accept loop in its ctor, so this
            // worker just owns its lifetime.
            return Task.Delay(Timeout.Infinite, stoppingToken);
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _server.Dispose();
            return base.StopAsync(cancellationToken);
        }
    }
}
