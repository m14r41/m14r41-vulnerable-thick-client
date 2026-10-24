using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MVTC.Core.Services;

namespace MVTC.App.Views;

public partial class WorkspaceLayout : UserControl
{
    public WorkspaceLayout()
    {
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    public void Refresh()
    {
        var sess = AuthService.CurrentSession;
        if (sess is not null)
        {
            HelloText.Text = $"Welcome back, {sess.Username}.";
            SubText.Text = $"Signed in at {DateTime.Now:HH:mm} · role: {sess.Role}";
            RoleText.Text = sess.Role;
            RoleSub2.Text = string.Equals(sess.Role, "admin", StringComparison.OrdinalIgnoreCase)
                ? "admin console open" : "admin locked";
        }

        int points = 0, solved = 0, total = 50;
        try
        {
            var pts = App.Progress?.GetAllPointsAndStatus();
            if (pts is not null)
            {
                foreach (var row in pts) if (row.Solved) { points += row.Points; solved++; }
            }
        }
        catch { }

        ProgressText.Text = $"{solved} / {total}";
        PointsText.Text   = points.ToString("n0");
        RankText.Text     = RankFor(points);
        RankSub.Text      = $"next: {NextRankIn(points)} pts away";

        PopulateActivity();
    }

    private void PopulateActivity()
    {
        ActivityList.Children.Clear();
        var path = Path.Combine(App.InstallRoot, "logs", "audit.log");
        if (!File.Exists(path))
        {
            ActivityList.Children.Add(new TextBlock
            {
                Text = "No activity yet. Submit your first flag.",
                FontSize = 12,
                Foreground = (Brush)FindResource("TextMutedBrush"),
                Opacity = 0.75
            });
            return;
        }

        try
        {
            var lines = File.ReadAllLines(path);
            var tail = lines.Reverse().Take(8).ToArray();
            foreach (var l in tail)
            {
                var row = new TextBlock
                {
                    Text = l.Length > 160 ? l[..160] + "…" : l,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 11,
                    Foreground = (Brush)FindResource("TextPrimaryBrush"),
                    Opacity = 0.9,
                    Padding = new Thickness(0, 4, 0, 4),
                    TextWrapping = TextWrapping.NoWrap,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                ActivityList.Children.Add(row);
                var sep = new Border { Height = 1, Background = (Brush)FindResource("CardBorderBrush"), Opacity = 0.6 };
                ActivityList.Children.Add(sep);
            }
        }
        catch { }
    }

    private static string RankFor(int p) => p switch
    {
        >= 4680 => "M14R41 Operator",
        >= 3950 => "Thick Client Master",
        >= 3000 => "SYSTEM Whisperer",
        >= 2100 => "Vault Breaker",
        >= 1400 => "Pipe Dreamer",
        >= 800  => "Reverser-in-Training",
        >= 300  => "Lab Rat",
        _       => "Script Kiddie"
    };

    private static int NextRankIn(int p)
    {
        int[] thresholds = { 300, 800, 1400, 2100, 3000, 3950, 4680 };
        foreach (var t in thresholds) if (p < t) return t - p;
        return 0;
    }

    private void NavTo(string tag)
    {
        if (Window.GetWindow(this) is MainWindow mw) mw.NavTo(tag);
    }

    private void OnSubmit(object sender, RoutedEventArgs e)         => NavTo("Challenges");
    private void OnOpenFlagsConsole(object sender, RoutedEventArgs e) => NavTo("Challenges");
    private void OnOpenShell(object sender, RoutedEventArgs e)      => NavTo("Shell");
    private void OnOpenAdmin(object sender, RoutedEventArgs e)      => NavTo("Admin");
}
