using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MVTC.MockUpdate;

/// <summary>
/// VULN: #38 - Mock update server, HTTP only, no signing.
/// </summary>
public static class MockUpdateHost
{
    public sealed record Started(WebApplication App, int Port);

    public static async Task<Started> StartAsync(string releaseNotesFlag38, CancellationToken ct = default)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = "MVTC.MockUpdate",
            EnvironmentName = Environments.Production
        });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();

        app.MapGet("/health", () => Results.Ok(new { ok = true, service = "MVTC.MockUpdate" }));

        app.MapGet("/manifest.json", (HttpContext ctx) =>
        {
            var port = ctx.Request.Host.Port ?? 0;
            return Results.Json(new
            {
                version = "1.0.1",
                payload_url = $"http://127.0.0.1:{port}/payload.bin",
                // VULN: #38 - operator left the "release notes" field pointing at
                // what is in fact the signed-build-token, now shipping as plaintext
                // in every update broadcast. (Flag.)
                release_notes = $"Routine update. token={releaseNotesFlag38}"
            });
        });

        app.MapGet("/payload.bin", () =>
        {
            // Innocuous bytes - the vulnerability isn't the payload content, it
            // is that no signature on it is required.
            var bytes = System.Text.Encoding.UTF8.GetBytes("MVTC-update-payload-stub-v1.0.1\n");
            return Results.File(bytes, "application/octet-stream", "payload.bin");
        });

        await app.StartAsync(ct);
        var feature = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        var port = new Uri(feature!.Addresses.First()).Port;
        return new Started(app, port);
    }
}
