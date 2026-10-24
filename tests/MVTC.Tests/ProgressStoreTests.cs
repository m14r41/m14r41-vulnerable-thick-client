using Microsoft.Data.Sqlite;
using MVTC.Core.Crypto;
using MVTC.Core.Data;
using Xunit;

namespace MVTC.Tests;

public class ProgressStoreTests
{
    private static ProgressStore FreshStore()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mvtc-test-{Guid.NewGuid():N}.db");
        var store = new ProgressStore(path);
        store.EnsureSeeded();
        return store;
    }

    [Fact]
    public void Seeded_All_40_Challenges()
    {
        var store = FreshStore();
        var all = store.List();
        Assert.Equal(40, all.Count);
        Assert.Equal(3950, ChallengeSeedData.All.Sum(s => s.Points));
        Assert.Equal(RankCalculator.MaxPoints, ChallengeSeedData.All.Sum(s => s.Points));
    }

    [Fact]
    public void Prerequisite_Challenges_Start_Locked()
    {
        var store = FreshStore();
        var all = store.List();
        var six = all.First(c => c.Challenge.VulnNo == 6);
        Assert.True(six.IsLocked, "Challenge #6 should start Locked (prereq #37)");
        var one = all.First(c => c.Challenge.VulnNo == 1);
        Assert.False(one.IsLocked, "Challenge #1 should start Unlocked");
    }

    [Fact]
    public void Correct_Flag_Marks_Solved_And_Awards_Points()
    {
        var store = FreshStore();
        var flag = ReadFlagPlaintext(store.DbPath, challengeId: 1);
        var result = store.Submit(challengeId: 1, submission: flag);
        Assert.Equal(SubmitOutcome.Solved, result.Outcome);
        Assert.Equal(90, result.AwardedPoints);
        Assert.Equal(90, result.Profile.TotalPoints);
    }

    [Fact]
    public void Wrong_Flag_Returns_Incorrect_And_Increments_Attempts()
    {
        var store = FreshStore();
        var r = store.Submit(challengeId: 1, submission: "MVTC{v01_dllh_WRONGWRONG}");
        Assert.Equal(SubmitOutcome.Incorrect, r.Outcome);
        var row = store.List().First(c => c.Challenge.Id == 1);
        Assert.Equal(1, row.Progress.Attempts);
    }

    [Fact]
    public void Locked_Challenge_Rejects_Submission()
    {
        var store = FreshStore();
        var flag = ReadFlagPlaintext(store.DbPath, challengeId: 6);
        var r = store.Submit(challengeId: 6, submission: flag);
        Assert.Equal(SubmitOutcome.Locked, r.Outcome);
    }

    [Fact]
    public void Solving_Prerequisite_Unlocks_Dependent()
    {
        var store = FreshStore();
        // Challenge 7 depends on 1
        var seven = store.List().First(c => c.Challenge.Id == 7);
        Assert.True(seven.IsLocked);

        var flag1 = ReadFlagPlaintext(store.DbPath, 1);
        store.Submit(1, flag1);

        var sevenAfter = store.List().First(c => c.Challenge.Id == 7);
        Assert.False(sevenAfter.IsLocked, "Challenge #7 should unlock once #1 is solved");
    }

    [Fact]
    public void Already_Solved_Does_Not_Double_Award()
    {
        var store = FreshStore();
        var flag = ReadFlagPlaintext(store.DbPath, 1);
        var r1 = store.Submit(1, flag);
        var r2 = store.Submit(1, flag);
        Assert.Equal(SubmitOutcome.Solved, r1.Outcome);
        Assert.Equal(SubmitOutcome.AlreadySolved, r2.Outcome);
        Assert.Equal(90, r1.Profile.TotalPoints);
    }

    [Fact]
    public void Rank_Updates_With_Points()
    {
        Assert.Equal("Script Kiddie", RankCalculator.ForPoints(0));
        Assert.Equal("Lab Rat", RankCalculator.ForPoints(300));
        Assert.Equal("Lab Rat", RankCalculator.ForPoints(799));
        Assert.Equal("Reverser-in-Training", RankCalculator.ForPoints(800));
        Assert.Equal("Thick Client Master", RankCalculator.ForPoints(3950));
    }

    [Fact]
    public void Soft_Reset_Clears_Progress_But_Keeps_Challenges()
    {
        var store = FreshStore();
        var flag = ReadFlagPlaintext(store.DbPath, 1);
        store.Submit(1, flag);
        Assert.Equal(90, store.GetProfile().TotalPoints);

        store.SoftReset();

        Assert.Equal(0, store.GetProfile().TotalPoints);
        Assert.Equal(40, store.List().Count);
        var one = store.List().First(c => c.Challenge.Id == 1);
        Assert.Equal("Unsolved", one.Progress.Status);
        Assert.Equal(0, one.Progress.Attempts);
    }

    [Fact]
    public void Flag_Format_Is_MVTC_Braced()
    {
        var store = FreshStore();
        var flag = ReadFlagPlaintext(store.DbPath, 1);
        Assert.StartsWith("MVTC{v01_dllh_", flag);
        Assert.EndsWith("}", flag);
    }

    private static string ReadFlagPlaintext(string dbPath, int challengeId)
    {
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT plaintext FROM FlagPlaintext WHERE challenge_id = $id;";
        cmd.Parameters.AddWithValue("$id", challengeId);
        return (string)cmd.ExecuteScalar()!;
    }
}
