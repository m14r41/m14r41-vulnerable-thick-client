using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace MVTC.Challenges;

public sealed class ScoreboardClient : IDisposable
{
    private readonly HttpClient _http;
    public Uri BaseUri { get; }

    public ScoreboardClient(int port)
    {
        BaseUri = new Uri($"http://127.0.0.1:{port}");
        _http = new HttpClient { BaseAddress = BaseUri, Timeout = TimeSpan.FromSeconds(5) };
    }

    public async Task<IReadOnlyList<ChallengeDto>> ListAsync(CancellationToken ct = default)
    {
        var list = await _http.GetFromJsonAsync<List<ChallengeDto>>("/list", ct);
        return list ?? new List<ChallengeDto>();
    }

    public async Task<ProfileDto> GetProfileAsync(CancellationToken ct = default)
    {
        var p = await _http.GetFromJsonAsync<ProfileDto>("/profile", ct);
        return p ?? new ProfileDto();
    }

    public async Task<SubmitResponseDto> SubmitAsync(int challengeId, string flag, CancellationToken ct = default)
    {
        var resp = await _http.PostAsJsonAsync("/submit", new { ChallengeId = challengeId, Flag = flag }, ct);
        resp.EnsureSuccessStatusCode();
        var dto = await resp.Content.ReadFromJsonAsync<SubmitResponseDto>(cancellationToken: ct);
        return dto ?? new SubmitResponseDto();
    }

    public void Dispose() => _http.Dispose();
}

public sealed class ChallengeDto
{
    [JsonPropertyName("id")] public int Id { get; set; }
    [JsonPropertyName("vulnNo")] public int VulnNo { get; set; }
    [JsonPropertyName("title")] public string Title { get; set; } = "";
    [JsonPropertyName("category")] public string Category { get; set; } = "";
    [JsonPropertyName("tier")] public string Tier { get; set; } = "";
    [JsonPropertyName("points")] public int Points { get; set; }
    [JsonPropertyName("cwe")] public string Cwe { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("attempts")] public int Attempts { get; set; }
    [JsonPropertyName("solvedAt")] public string? SolvedAt { get; set; }
    [JsonPropertyName("writeupPath")] public string WriteupPath { get; set; } = "";
    [JsonPropertyName("locked")] public bool Locked { get; set; }
    [JsonPropertyName("flagFormat")] public string FlagFormat { get; set; } = "";
    [JsonPropertyName("hint")]  public string Hint  { get; set; } = "";
    [JsonPropertyName("tools")] public string Tools { get; set; } = "";
    public string Display => $"#{VulnNo:D2}  [{Tier,-6}] {Title}";
    public string StatusDisplay => Locked ? "Locked" : Status;
}

public sealed class ProfileDto
{
    [JsonPropertyName("totalPoints")] public int TotalPoints { get; set; }
    [JsonPropertyName("rank")] public string Rank { get; set; } = "Script Kiddie";
    [JsonPropertyName("startedAt")] public string StartedAt { get; set; } = "";
}

public sealed class SubmitResponseDto
{
    [JsonPropertyName("outcome")] public string Outcome { get; set; } = "";
    [JsonPropertyName("awarded")] public int Awarded { get; set; }
    [JsonPropertyName("totalPoints")] public int TotalPoints { get; set; }
    [JsonPropertyName("rank")] public string Rank { get; set; } = "Script Kiddie";
}
