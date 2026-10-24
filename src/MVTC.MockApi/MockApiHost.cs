using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MVTC.MockApi;

/// <summary>
/// VULN: #39 - plain-HTTP mock backend. Serves <c>/login</c>, <c>/assets</c>,
/// and <c>/telemetry</c>. Replies include a <c>secure_token</c> field that is
/// in fact the Phase-3 flag planted at startup.
/// </summary>
public static class MockApiHost
{
    public sealed record Started(WebApplication App, int Port);

    public static async Task<Started> StartAsync(string flag39, CancellationToken ct = default)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = "MVTC.MockApi",
            EnvironmentName = Environments.Production
        });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();

        app.MapGet("/health", () => Results.Ok(new { ok = true, service = "MVTC.MockApi" }));

        app.MapPost("/login", async (HttpContext ctx) =>
        {
            // VULN: #39 - accepts credentials over cleartext HTTP and echoes a
            // "secure_token" back in the body. On a wire capture (Wireshark on
            // loopback / Fiddler / mitmproxy), the token walks right out.
            using var sr = new StreamReader(ctx.Request.Body);
            var body = await sr.ReadToEndAsync();
            var username = System.Text.RegularExpressions.Regex.Match(body, "\"username\"\\s*:\\s*\"([^\"]*)\"").Groups[1].Value;
            return Results.Ok(new
            {
                username,
                role = username == "admin" ? "admin" : "user",
                secure_token = flag39
            });
        });

        app.MapGet("/assets", () => Results.Ok(new[]
        {
            new { id = 101, name = "Laptop-TN-0456" },
            new { id = 102, name = "Server-DC01" },
            new { id = 103, name = "Backup-NAS" }
        }));

        app.MapPost("/telemetry", async (HttpContext ctx) =>
        {
            using var sr = new StreamReader(ctx.Request.Body);
            var body = await sr.ReadToEndAsync();
            return Results.Ok(new { received = body.Length });
        });

        await app.StartAsync(ct);
        var feature = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        var port = new Uri(feature!.Addresses.First()).Port;
        return new Started(app, port);
    }
}
