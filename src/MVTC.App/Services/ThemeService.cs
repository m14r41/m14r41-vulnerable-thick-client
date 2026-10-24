using System.IO;
using System.Windows;
using System.Windows.Media;

namespace MVTC.App.Services;

/// <summary>
/// Full-application theme switcher. Each theme is a palette for the custom
/// window chrome, sub-header, sidebar, content area, cards, buttons and
/// text. Themes are applied by swapping the <c>Color</c> property of the
/// SolidColorBrush resources declared in <c>App.xaml</c>, so every control
/// that binds to them via <c>DynamicResource</c> re-renders live. Selection
/// persists to <c>%APPDATA%\MVTC\theme.txt</c>.
/// </summary>
public static class ThemeService
{
    public sealed record Theme(
        string Name,
        // Title bar
        Color TitleBar, Color TitleAccent, Color TitleFg,
        Color BadgeBg,  Color BadgeFg,
        // Sub-header (brand + search)
        Color SubHeaderBg, Color SubHeaderBorder, Color BrandBg, Color BrandFg,
        // Sidebar
        Color SidebarBg, Color SidebarBorder, Color SidebarActive, Color SidebarFg, Color SidebarActiveFg,
        // Main content canvas
        Color AppBg, Color OuterBorder,
        // Cards / panels inside content
        Color CardBg, Color CardBorder,
        // Text
        Color TextPrimary, Color TextMuted, Color TextAccent,
        // Footer
        Color FooterBg, Color FooterFg);

    // Palettes modelled on real pro apps (JetBrains / IntelliJ, VSCode, Figma,
    // MS Teams, Hyper). Design rules:
    //   TITLE bar is clearly brighter than APP body (visible elevation strip)
    //   APP body sits in the mid-grey range (never below ~#1E)
    //   SIDEBAR sits a touch DARKER than body (visible column edge)
    //   CARDS sit a touch LIGHTER than body (readable panels)
    //   Borders soft but visible; accents brand-leaning, not neon
    public static readonly IReadOnlyList<Theme> All = new[]
    {
        // DEFAULT - Mesh: cohesive with the login's pink/indigo gradient.
        // Pink brand, cyan accent, elevated purple-grey title.
        new Theme("Mesh",
            TitleBar: C("1A1826"), TitleAccent: C("3B2F55"), TitleFg: C("F0E6F5"),
            BadgeBg:  C("1F2E2A"), BadgeFg:    C("50FA7B"),
            SubHeaderBg: C("14121D"), SubHeaderBorder: C("2A2435"), BrandBg: C("FF4F8B"), BrandFg: C("2A0C1A"),
            SidebarBg: C("0F0E16"), SidebarBorder: C("2A2435"), SidebarActive: C("261B38"), SidebarFg: C("B8B3C7"), SidebarActiveFg: C("FFBED6"),
            AppBg: C("14121D"), OuterBorder: C("2A2435"),
            CardBg: C("1C1A27"), CardBorder: C("2A2435"),
            TextPrimary: C("F0E6F5"), TextMuted: C("A098B4"), TextAccent: C("8BE9FD"),
            FooterBg: C("0F0E16"), FooterFg: C("A098B4")),

        // Dracula - iconic dark theme every pentester/dev knows.
        new Theme("Dracula",
            TitleBar: C("44475A"), TitleAccent: C("6272A4"), TitleFg: C("F8F8F2"),
            BadgeBg:  C("1F2E2A"), BadgeFg:    C("50FA7B"),
            SubHeaderBg: C("353749"), SubHeaderBorder: C("6272A4"), BrandBg: C("FF79C6"), BrandFg: C("2A1A24"),
            SidebarBg: C("21222C"), SidebarBorder: C("44475A"), SidebarActive: C("3B3E52"), SidebarFg: C("C0C3D0"), SidebarActiveFg: C("BD93F9"),
            AppBg: C("282A36"), OuterBorder: C("44475A"),
            CardBg: C("343746"), CardBorder: C("44475A"),
            TextPrimary: C("F8F8F2"), TextMuted: C("A8ABB8"), TextAccent: C("8BE9FD"),
            FooterBg: C("21222C"), FooterFg: C("A8ABB8")),

        // Nord - cool arctic grey-blue with soft accents
        new Theme("Nord",
            TitleBar: C("3B4252"), TitleAccent: C("4C566A"), TitleFg: C("ECEFF4"),
            BadgeBg:  C("1E2E24"), BadgeFg:    C("A3BE8C"),
            SubHeaderBg: C("2E3440"), SubHeaderBorder: C("4C566A"), BrandBg: C("88C0D0"), BrandFg: C("1C2129"),
            SidebarBg: C("242933"), SidebarBorder: C("4C566A"), SidebarActive: C("3B4252"), SidebarFg: C("D8DEE9"), SidebarActiveFg: C("88C0D0"),
            AppBg: C("2E3440"), OuterBorder: C("4C566A"),
            CardBg: C("3B4252"), CardBorder: C("4C566A"),
            TextPrimary: C("ECEFF4"), TextMuted: C("A8B0BC"), TextAccent: C("88C0D0"),
            FooterBg: C("242933"), FooterFg: C("A8B0BC")),

        // Solarized Dark - classic terminal palette
        new Theme("Solarized",
            TitleBar: C("003745"), TitleAccent: C("073642"), TitleFg: C("FDF6E3"),
            BadgeBg:  C("1F2E22"), BadgeFg:    C("859900"),
            SubHeaderBg: C("002631"), SubHeaderBorder: C("093948"), BrandBg: C("CB4B16"), BrandFg: C("FDF6E3"),
            SidebarBg: C("001E27"), SidebarBorder: C("093948"), SidebarActive: C("093948"), SidebarFg: C("93A1A1"), SidebarActiveFg: C("CB4B16"),
            AppBg: C("002B36"), OuterBorder: C("093948"),
            CardBg: C("073642"), CardBorder: C("093948"),
            TextPrimary: C("FDF6E3"), TextMuted: C("93A1A1"), TextAccent: C("B58900"),
            FooterBg: C("001E27"), FooterFg: C("93A1A1")),

        // Monokai Pro - warm classic coder palette
        new Theme("Monokai",
            TitleBar: C("3A3A42"), TitleAccent: C("545460"), TitleFg: C("FCFCFA"),
            BadgeBg:  C("2A2B2E"), BadgeFg:    C("A9DC76"),
            SubHeaderBg: C("2D2A2E"), SubHeaderBorder: C("545460"), BrandBg: C("FF6188"), BrandFg: C("261F23"),
            SidebarBg: C("222023"), SidebarBorder: C("545460"), SidebarActive: C("353437"), SidebarFg: C("CCC5BA"), SidebarActiveFg: C("FFD866"),
            AppBg: C("2D2A2E"), OuterBorder: C("545460"),
            CardBg: C("353337"), CardBorder: C("545460"),
            TextPrimary: C("FCFCFA"), TextMuted: C("B6B2AF"), TextAccent: C("FFD866"),
            FooterBg: C("222023"), FooterFg: C("B6B2AF")),

        // Graphite - Figma / Vercel vibe. Warm neutral grey, violet accent.
        new Theme("Graphite",
            TitleBar: C("3F3F42"), TitleAccent: C("55555A"), TitleFg: C("EDEDED"),
            BadgeBg:  C("2E2A1F"), BadgeFg:    C("E4D27A"),
            SubHeaderBg: C("2A2A2D"), SubHeaderBorder: C("3F3F42"), BrandBg: C("7C5CFF"), BrandFg: C("FFFFFF"),
            SidebarBg: C("1F1F22"), SidebarBorder: C("3F3F42"), SidebarActive: C("2A2A2D"), SidebarFg: C("B1B1B5"), SidebarActiveFg: C("A594FF"),
            AppBg: C("2A2A2D"), OuterBorder: C("3F3F42"),
            CardBg: C("313135"), CardBorder: C("3F3F42"),
            TextPrimary: C("EDEDED"), TextMuted: C("A1A1A5"), TextAccent: C("A594FF"),
            FooterBg: C("1F1F22"), FooterFg: C("A1A1A5")),

        // Carbon - VSCode Dark+ vibe. Classic editor dark with blue accent.
        new Theme("Carbon",
            TitleBar: C("3C3C3C"), TitleAccent: C("505050"), TitleFg: C("E6E6E6"),
            BadgeBg:  C("253621"), BadgeFg:    C("89D185"),
            SubHeaderBg: C("252526"), SubHeaderBorder: C("3C3C3C"), BrandBg: C("007ACC"), BrandFg: C("FFFFFF"),
            SidebarBg: C("252526"), SidebarBorder: C("3C3C3C"), SidebarActive: C("37373D"), SidebarFg: C("B5B5B5"), SidebarActiveFg: C("4FC1FF"),
            AppBg: C("1E1E1E"), OuterBorder: C("3C3C3C"),
            CardBg: C("252526"), CardBorder: C("3C3C3C"),
            TextPrimary: C("D4D4D4"), TextMuted: C("858585"), TextAccent: C("4FC1FF"),
            FooterBg: C("252526"), FooterFg: C("858585")),

        // Plum - MS Teams vibe. Soft purple strip up top, warm grey body.
        new Theme("Plum",
            TitleBar: C("464775"), TitleAccent: C("5B5C8A"), TitleFg: C("F5F3FA"),
            BadgeBg:  C("2E2825"), BadgeFg:    C("B2A99A"),
            SubHeaderBg: C("3B3A42"), SubHeaderBorder: C("4F4E5A"), BrandBg: C("8E88DD"), BrandFg: C("1A1830"),
            SidebarBg: C("29282C"), SidebarBorder: C("4F4E5A"), SidebarActive: C("3B3A42"), SidebarFg: C("BEBAC4"), SidebarActiveFg: C("B6B0FF"),
            AppBg: C("322F38"), OuterBorder: C("4F4E5A"),
            CardBg: C("3B3A42"), CardBorder: C("4F4E5A"),
            TextPrimary: C("EDEBF1"), TextMuted: C("A5A1AD"), TextAccent: C("B6B0FF"),
            FooterBg: C("29282C"), FooterFg: C("A5A1AD")),

        // Terminal - Hyper / Ghostty vibe. Grey-green body, phosphor accent.
        new Theme("Terminal",
            TitleBar: C("283028"), TitleAccent: C("3A4A3A"), TitleFg: C("D7E8D7"),
            BadgeBg:  C("1F2E22"), BadgeFg:    C("8EEF9E"),
            SubHeaderBg: C("1F241F"), SubHeaderBorder: C("354235"), BrandBg: C("4ADE80"), BrandFg: C("0C1A10"),
            SidebarBg: C("191D19"), SidebarBorder: C("354235"), SidebarActive: C("263226"), SidebarFg: C("A8BFA8"), SidebarActiveFg: C("8EEF9E"),
            AppBg: C("1E241E"), OuterBorder: C("354235"),
            CardBg: C("252D25"), CardBorder: C("354235"),
            TextPrimary: C("D7E8D7"), TextMuted: C("A2B2A2"), TextAccent: C("8EEF9E"),
            FooterBg: C("191D19"), FooterFg: C("A2B2A2")),
    };

    private static Color C(string hex) => (Color)ColorConverter.ConvertFromString("#" + hex);

    // Brush resource keys (match App.xaml declarations)
    public const string TitleBarBrushKey        = "TitleBarBrush";
    public const string TitleAccentBrushKey     = "TitleAccentBrush";
    public const string TitleFgBrushKey         = "TitleFgBrush";
    public const string TitleBadgeBgBrushKey    = "TitleBadgeBgBrush";
    public const string TitleBadgeFgBrushKey    = "TitleBadgeFgBrush";
    public const string SubHeaderBgBrushKey     = "SubHeaderBgBrush";
    public const string SubHeaderBorderBrushKey = "SubHeaderBorderBrush";
    public const string BrandBgBrushKey         = "BrandBgBrush";
    public const string BrandFgBrushKey         = "BrandFgBrush";
    public const string SidebarBgBrushKey       = "SidebarBgBrush";
    public const string SidebarBorderBrushKey   = "SidebarBorderBrush";
    public const string SidebarActiveBrushKey   = "SidebarActiveBrush";
    public const string SidebarFgBrushKey       = "SidebarFgBrush";
    public const string SidebarActiveFgBrushKey = "SidebarActiveFgBrush";
    public const string AppBgBrushKey           = "AppBgBrush";
    public const string OuterBorderBrushKey     = "OuterBorderBrush";
    public const string CardBgBrushKey          = "CardBgBrush";
    public const string CardBorderBrushKey      = "CardBorderBrush";
    public const string TextPrimaryBrushKey     = "TextPrimaryBrush";
    public const string TextMutedBrushKey       = "TextMutedBrush";
    public const string TextAccentBrushKey      = "TextAccentBrush";
    public const string FooterBgBrushKey        = "FooterBgBrush";
    public const string FooterFgBrushKey        = "FooterFgBrush";

    private static int _idx = 0;

    public static int CurrentIndex => _idx;
    public static Theme Current => All[_idx];

    public static void Init(string installRoot)
    {
        _idx = ReadPersistedIndex(installRoot);
        Apply();
    }

    public static void Cycle(string installRoot)
    {
        _idx = (_idx + 1) % All.Count;
        PersistIndex(installRoot, _idx);
        Apply();
    }

    public static void Apply()
    {
        var t = All[_idx];
        var r = Application.Current?.Resources;
        if (r is null) return;

        // ALWAYS reassign the key with a fresh brush instance. This forces every
        // DynamicResource consumer in the visual tree to re-resolve and re-render
        // without us having to walk the tree ourselves. Mutating the existing
        // brush's Color property works too, but only when the brush is unfrozen,
        // and XAML-declared SolidColorBrush instances are sometimes frozen by WPF
        // for performance (which silently makes the mutation a no-op in release).
        r[TitleBarBrushKey]        = new SolidColorBrush(t.TitleBar);
        r[TitleAccentBrushKey]     = new SolidColorBrush(t.TitleAccent);
        r[TitleFgBrushKey]         = new SolidColorBrush(t.TitleFg);
        r[TitleBadgeBgBrushKey]    = new SolidColorBrush(t.BadgeBg);
        r[TitleBadgeFgBrushKey]    = new SolidColorBrush(t.BadgeFg);
        r[SubHeaderBgBrushKey]     = new SolidColorBrush(t.SubHeaderBg);
        r[SubHeaderBorderBrushKey] = new SolidColorBrush(t.SubHeaderBorder);
        r[BrandBgBrushKey]         = new SolidColorBrush(t.BrandBg);
        r[BrandFgBrushKey]         = new SolidColorBrush(t.BrandFg);
        r[SidebarBgBrushKey]       = new SolidColorBrush(t.SidebarBg);
        r[SidebarBorderBrushKey]   = new SolidColorBrush(t.SidebarBorder);
        r[SidebarActiveBrushKey]   = new SolidColorBrush(t.SidebarActive);
        r[SidebarFgBrushKey]       = new SolidColorBrush(t.SidebarFg);
        r[SidebarActiveFgBrushKey] = new SolidColorBrush(t.SidebarActiveFg);
        r[AppBgBrushKey]           = new SolidColorBrush(t.AppBg);
        r[OuterBorderBrushKey]     = new SolidColorBrush(t.OuterBorder);
        r[CardBgBrushKey]          = new SolidColorBrush(t.CardBg);
        r[CardBorderBrushKey]      = new SolidColorBrush(t.CardBorder);
        r[TextPrimaryBrushKey]     = new SolidColorBrush(t.TextPrimary);
        r[TextMutedBrushKey]       = new SolidColorBrush(t.TextMuted);
        r[TextAccentBrushKey]      = new SolidColorBrush(t.TextAccent);
        r[FooterBgBrushKey]        = new SolidColorBrush(t.FooterBg);
        r[FooterFgBrushKey]        = new SolidColorBrush(t.FooterFg);
    }

    private static string PathFor(string installRoot) =>
        Path.Combine(installRoot, "theme.txt");

    private static int ReadPersistedIndex(string installRoot)
    {
        try
        {
            var p = PathFor(installRoot);
            if (!File.Exists(p)) return 0;
            if (int.TryParse(File.ReadAllText(p).Trim(), out var i) && i >= 0 && i < All.Count)
                return i;
        }
        catch { }
        return 0;
    }

    private static void PersistIndex(string installRoot, int i)
    {
        try
        {
            Directory.CreateDirectory(installRoot);
            File.WriteAllText(PathFor(installRoot), i.ToString());
        }
        catch { }
    }
}
