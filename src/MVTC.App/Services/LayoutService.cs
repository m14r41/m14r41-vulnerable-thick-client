using System.IO;

namespace MVTC.App.Services;

/// <summary>
/// Dashboard layout preference. Users cycle through layouts via a small
/// icon in the title bar (next to the theme switcher). The selection
/// persists to <c>%APPDATA%\MVTC\layout.txt</c>.
/// </summary>
public static class LayoutService
{
    public enum Kind
    {
        OperatorMissionControl = 0,
        SaasWorkspace          = 1,
    }

    public static readonly (Kind Kind, string Name)[] All =
    {
        (Kind.OperatorMissionControl, "Mission control"),
        (Kind.SaasWorkspace,          "Workspace"),
    };

    private static int _idx = 0;

    public static Kind Current => All[_idx].Kind;
    public static string CurrentName => All[_idx].Name;

    public static event Action? Changed;

    public static void Init(string installRoot)
    {
        _idx = ReadIndex(installRoot);
    }

    public static void Cycle(string installRoot)
    {
        _idx = (_idx + 1) % All.Length;
        PersistIndex(installRoot, _idx);
        Changed?.Invoke();
    }

    private static string PathFor(string installRoot) => Path.Combine(installRoot, "layout.txt");

    private static int ReadIndex(string installRoot)
    {
        try
        {
            var p = PathFor(installRoot);
            if (File.Exists(p) && int.TryParse(File.ReadAllText(p).Trim(), out var i) && i >= 0 && i < All.Length)
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
