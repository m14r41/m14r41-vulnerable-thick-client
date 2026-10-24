using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using MVTC.Core.Services;

namespace MVTC.App.Views;

/// <summary>
/// Mission-control dashboard: status strip + 4 colored-rail metric tiles
/// + a sparkline of points over time + a system-health rail.
/// </summary>
public partial class MissionControlLayout : UserControl
{
    public MissionControlLayout()
    {
        InitializeComponent();
        Loaded += (_, _) => Refresh();
        SizeChanged += (_, _) => RedrawChart();
    }

    public void Refresh()
    {
        var sess = AuthService.CurrentSession;
        if (sess is not null)
        {
            RoleValue.Text = sess.Role;
            RoleSub.Text = string.Equals(sess.Role, "admin", StringComparison.OrdinalIgnoreCase)
                ? "admin console open"
                : "admin console locked";
            SessionText.Text = "Session: SESS_" + (sess.Token.Length > 10 ? sess.Token[..10] : sess.Token);
        }

        // Points + progress numbers
        int points = 0, solved = 0, totalChallenges = 50;
        var open = totalChallenges;
        try
        {
            var pts = App.Progress?.GetAllPointsAndStatus();
            if (pts is not null)
            {
                foreach (var row in pts)
                {
                    if (row.Solved) { points += row.Points; solved++; }
                }
            }
        }
        catch { }

        open = Math.Max(0, totalChallenges - solved);
        PointsValue.Text = points.ToString("n0");
        PointsSub.Text   = "of 4,680 total";
        ProgressValue.Text = $"{solved} / {totalChallenges}";
        ProgressSub.Text   = "challenges solved";
        OpenValue.Text     = open.ToString();

        PopulateHealth();
        RedrawChart();
    }

    private void PopulateHealth()
    {
        HealthList.Children.Clear();
        var items = new (string Label, string Status, Brush Color)[]
        {
            ("Vault pipe",    "online",     new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7))),
            ("Scoreboard",    "online",     new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7))),
            ("Audit log",     TailAuditLog(), new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7))),
            ("HSM channel",   "online",     new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7))),
            ("Mock update",   "plaintext",  new SolidColorBrush(Color.FromRgb(0xFB, 0xB4, 0x63))),
        };

        foreach (var it in items)
        {
            var row = new Grid();
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var k = new TextBlock
            {
                Text = it.Label,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = (Brush)FindResource("TextPrimaryBrush")
            };
            Grid.SetColumn(k, 0);

            var vs = new StackPanel { Orientation = Orientation.Horizontal };
            Grid.SetColumn(vs, 1);
            var dot = new Ellipse
            {
                Width = 7, Height = 7,
                Fill = it.Color,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0)
            };
            vs.Children.Add(dot);
            vs.Children.Add(new TextBlock
            {
                Text = it.Status,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                Foreground = it.Color,
                VerticalAlignment = VerticalAlignment.Center
            });

            row.Children.Add(k);
            row.Children.Add(vs);
            row.Margin = new Thickness(0, 6, 0, 6);
            HealthList.Children.Add(row);

            var sep = new Border
            {
                Height = 1,
                Background = (Brush)FindResource("CardBorderBrush"),
                Opacity = 0.6
            };
            HealthList.Children.Add(sep);
        }
    }

    private static string TailAuditLog()
    {
        try
        {
            var path = System.IO.Path.Combine(App.InstallRoot, "logs", "audit.log");
            if (!System.IO.File.Exists(path)) return "no log";
            var fi = new System.IO.FileInfo(path);
            return $"{fi.Length:n0} bytes";
        }
        catch { return "unavailable"; }
    }

    private void RedrawChart()
    {
        ChartCanvas.Children.Clear();
        var w = ChartCanvas.ActualWidth;
        var h = ChartCanvas.ActualHeight;
        if (w <= 20 || h <= 20) return;

        // Build an increasing timeline from the current solved points. If no
        // progress yet, draw an inviting empty-state curve so the card isn't
        // dead.
        var cumulative = new List<int>();
        var running = 0;
        try
        {
            var pts = App.Progress?.GetAllPointsAndStatus();
            if (pts is not null)
            {
                foreach (var r in pts)
                {
                    if (r.Solved) { running += r.Points; cumulative.Add(running); }
                }
            }
        }
        catch { }

        if (cumulative.Count < 2)
        {
            // Flat empty-state line with a small decorative wave at the end
            cumulative = new List<int> { 0, 0, 0, 0, 0, 0, 0, 0 };
        }

        var maxY = cumulative[^1] == 0 ? 1 : cumulative[^1];
        var n = cumulative.Count;
        var padLeft   = 6.0;
        var padRight  = 6.0;
        var padTop    = 10.0;
        var padBottom = 10.0;
        var cw = w - padLeft - padRight;
        var ch = h - padTop  - padBottom;

        var points = new PointCollection();
        for (var i = 0; i < n; i++)
        {
            var x = padLeft + (cw * i) / Math.Max(1, n - 1);
            var y = padTop  + ch - (ch * cumulative[i] / maxY);
            points.Add(new Point(x, y));
        }

        // Area fill
        var area = new Polygon
        {
            Fill = new LinearGradientBrush(
                Color.FromArgb(0x66, 0x60, 0xA5, 0xFA),
                Color.FromArgb(0x00, 0x60, 0xA5, 0xFA),
                new Point(0.5, 0), new Point(0.5, 1))
        };
        var areaPts = new PointCollection(points) { new Point(padLeft + cw, padTop + ch), new Point(padLeft, padTop + ch) };
        area.Points = areaPts;
        ChartCanvas.Children.Add(area);

        // Line
        var line = new Polyline
        {
            Stroke = (Brush)FindResource("TextAccentBrush"),
            StrokeThickness = 1.8,
            Points = points,
            StrokeLineJoin = PenLineJoin.Round
        };
        ChartCanvas.Children.Add(line);

        // Endpoint dot
        var last = points[^1];
        var dot = new Ellipse
        {
            Width = 8, Height = 8,
            Fill = (Brush)FindResource("TextAccentBrush")
        };
        Canvas.SetLeft(dot, last.X - 4);
        Canvas.SetTop(dot,  last.Y - 4);
        ChartCanvas.Children.Add(dot);

        ChartLatest.Text = $"now · {cumulative[^1]:n0} pts";
    }
}
