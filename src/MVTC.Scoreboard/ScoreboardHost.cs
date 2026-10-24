using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MVTC.Core.Data;

namespace MVTC.Scoreboard;

/// <summary>
/// Local-only flag validation / progress service bound to 127.0.0.1.
/// Hosted in-process by <c>MVTC.exe</c>; the port is written to
/// <c>%APPDATA%\MVTC\scoreboard.port</c> so the Challenges panel can find it.
/// </summary>
public static class ScoreboardHost
{
    public sealed record Started(WebApplication App, int Port);

    public static async Task<Started> StartAsync(string progressDbPath, int preferredPort = 0, CancellationToken ct = default)
    {
        var store = new ProgressStore(progressDbPath);
        store.EnsureSeeded();

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = "MVTC.Scoreboard",
            EnvironmentName = Environments.Production
        });
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(store);
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Listen(IPAddress.Loopback, preferredPort);
        });

        var app = builder.Build();
        MapEndpoints(app);

        await app.StartAsync(ct);

        var port = ResolvePort(app);
        return new Started(app, port);
    }

    private static int ResolvePort(WebApplication app)
    {
        var server = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>();
        var feature = server.Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        var address = feature?.Addresses.FirstOrDefault() ?? "http://127.0.0.1:0";
        var uri = new Uri(address);
        return uri.Port;
    }

    private static void MapEndpoints(WebApplication app)
    {
        app.MapGet("/health", () => Results.Ok(new { ok = true, service = "MVTC.Scoreboard" }));

        app.MapGet("/list", (ProgressStore store) =>
        {
            var views = store.List().Select(v =>
            {
                var seed = MVTC.Core.Data.ChallengeSeedData.All.FirstOrDefault(s => s.VulnNo == v.Challenge.VulnNo);
                return new
                {
                    id = v.Challenge.Id,
                    vulnNo = v.Challenge.VulnNo,
                    title = v.Challenge.Title,
                    category = v.Challenge.Category,
                    tier = v.Challenge.Tier,
                    points = v.Challenge.Points,
                    cwe = v.Challenge.Cwe,
                    status = v.Progress.Status,
                    attempts = v.Progress.Attempts,
                    solvedAt = v.Progress.SolvedAt,
                    writeupPath = v.Challenge.WriteupPath,
                    locked = v.IsLocked,
                    flagFormat = $"MVTC{{v{v.Challenge.VulnNo:D2}_{seed?.Slug ?? "slug"}_<16-byte-base32>}}",
                    hint  = seed?.Hint ?? "",
                    tools = seed?.Tools ?? ""
                };
            });
            return Results.Ok(views);
        });

        app.MapGet("/profile", (ProgressStore store) =>
        {
            var p = store.GetProfile();
            return Results.Ok(new { totalPoints = p.TotalPoints, rank = p.Rank, startedAt = p.StartedAt });
        });

        app.MapPost("/submit", (SubmitRequest req, ProgressStore store) =>
        {
            if (req is null || string.IsNullOrWhiteSpace(req.Flag) || req.ChallengeId <= 0)
                return Results.BadRequest(new { error = "challengeId and flag required" });
            var result = store.Submit(req.ChallengeId, req.Flag);
            return Results.Ok(new
            {
                outcome = result.Outcome.ToString(),
                awarded = result.AwardedPoints,
                totalPoints = result.Profile.TotalPoints,
                rank = result.Profile.Rank
            });
        });

        app.MapPost("/reset/soft", (ProgressStore store) =>
        {
            store.SoftReset();
            return Results.Ok(new { ok = true });
        });
    }
}

public sealed record SubmitRequest(int ChallengeId, string Flag);
