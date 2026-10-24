namespace MVTC.Core.Data;

public static class RankCalculator
{
    public const int MaxPoints = 4340;

    private static readonly (int Threshold, string Rank)[] Ladder =
    {
        (4340, "Thick Client Master"),
        (3200, "SYSTEM Whisperer"),
        (2300, "Vault Breaker"),
        (1500, "Pipe Dreamer"),
        (900,  "Reverser-in-Training"),
        (350,  "Lab Rat"),
        (0,    "Script Kiddie"),
    };

    public static string ForPoints(int points)
    {
        foreach (var (t, r) in Ladder)
            if (points >= t) return r;
        return "Script Kiddie";
    }
}
