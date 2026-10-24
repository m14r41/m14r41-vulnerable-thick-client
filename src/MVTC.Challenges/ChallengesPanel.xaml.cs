using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;

namespace MVTC.Challenges;

public partial class ChallengesPanel : UserControl
{
    private readonly ObservableCollection<ChallengeDto> _rows = new();
    private ScoreboardClient? _client;
    private ChallengeDto? _selected;

    public ChallengesPanel()
    {
        InitializeComponent();
        ChallengeGrid.ItemsSource = _rows;
    }

    public async Task AttachAsync(ScoreboardClient client)
    {
        _client = client;
        await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (_client is null) return;
        try
        {
            var list = await _client.ListAsync();
            _rows.Clear();
            foreach (var c in list) _rows.Add(c);
            var profile = await _client.GetProfileAsync();
            RankText.Text = $"  ·  {profile.Rank}";
            PointsText.Text = $"  ·  {profile.TotalPoints} pts / 3950";
            var solved = list.Count(c => string.Equals(c.Status, "Solved", StringComparison.OrdinalIgnoreCase));
            SolvedText.Text = $"  ·  {solved} / {list.Count} solved";
        }
        catch (Exception ex)
        {
            Toast($"Refresh failed: {ex.Message}", error: true);
        }
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _selected = ChallengeGrid.SelectedItem as ChallengeDto;
        if (_selected is null)
        {
            SelectedText.Text = "Select a row to see its hint.";
            FormatText.Text = HintText.Text = ToolsText.Text = "";
            return;
        }
        SelectedText.Text = $"#{_selected.VulnNo:D2} · {_selected.Title}  ·  {_selected.Tier}  ·  {_selected.Points} pts  ·  {_selected.Cwe}";
        FormatText.Text   = "Flag format:  " + _selected.FlagFormat;
        HintText.Text     = "Hint:         " + _selected.Hint;
        ToolsText.Text    = _selected.Tools.Length == 0 ? "" : "Tools:        " + _selected.Tools;
    }

    private async void OnSubmit(object sender, RoutedEventArgs e)
    {
        if (_client is null || _selected is null)
        {
            Toast("Pick a challenge, then paste the flag.", error: true);
            return;
        }
        var flag = FlagInput.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(flag))
        {
            Toast("Paste a flag first.", error: true);
            return;
        }
        try
        {
            var r = await _client.SubmitAsync(_selected.Id, flag);
            switch (r.Outcome)
            {
                case "Solved":
                    Toast($"Nice. +{r.Awarded} pts - now {r.Rank} ({r.TotalPoints} / 3950)");
                    FlagInput.Clear();
                    break;
                case "AlreadySolved":
                    Toast("Already solved.", error: false);
                    break;
                case "Incorrect":
                    Toast("Nope - wrong flag.", error: true);
                    break;
                case "Locked":
                    Toast("Challenge locked - solve its prerequisite first.", error: true);
                    break;
                default:
                    Toast($"Server said: {r.Outcome}", error: true);
                    break;
            }
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            Toast($"Submit failed: {ex.Message}", error: true);
        }
    }

    private async void OnRefresh(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async void OnSoftReset(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(
            "This clears your progress (challenge states, points, rank). Continue?",
            "MVTC - Soft reset", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        if (_client is null) return;
        try
        {
            using var http = new System.Net.Http.HttpClient { BaseAddress = _client.BaseUri };
            await http.PostAsync("/reset/soft", null);
            await RefreshAsync();
            Toast("Progress reset.");
        }
        catch (Exception ex)
        {
            Toast($"Reset failed: {ex.Message}", error: true);
        }
    }

    private void Toast(string text, bool error = false)
    {
        ToastText.Text = text;
        ToastText.Foreground = error
            ? System.Windows.Media.Brushes.OrangeRed
            : System.Windows.Media.Brushes.LightGreen;
    }
}
