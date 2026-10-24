namespace MVTC.Core.Models;

public sealed class Challenge
{
    public int Id { get; init; }
    public int VulnNo { get; init; }
    public string Title { get; init; } = "";
    public string Category { get; init; } = "";
    public string Tier { get; init; } = "EASY";
    public int Points { get; init; }
    public string Cwe { get; init; } = "";
    public string FlagHash { get; init; } = "";
    public string PrereqIds { get; init; } = "";
    public string WriteupPath { get; init; } = "";
}

public sealed class ProgressRow
{
    public int ChallengeId { get; set; }
    public string Status { get; set; } = "Unsolved";
    public string? SolvedAt { get; set; }
    public int Attempts { get; set; }
    public int HintCostPaid { get; set; }
}

public sealed record ChallengeStatusRow(int Id, int Points, bool Solved);

public sealed class ProfileRow
{
    public int TotalPoints { get; set; }
    public string Rank { get; set; } = "Script Kiddie";
    public string StartedAt { get; set; } = "";
}

public sealed class ChallengeView
{
    public required Challenge Challenge { get; init; }
    public required ProgressRow Progress { get; init; }
    public bool IsLocked { get; init; }
}
