using Newtonsoft.Json;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #29 - CWE-434 - Insecure file import to an autorun location.
/// VULN: #33 - CWE-502 - Insecure deserialization with
/// <see cref="TypeNameHandling"/>=<c>All</c>.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #29): bind imports to a fixed destination with filename
///   sanitization and never follow attacker-chosen file names. Autorun
///   locations must be read-only to the service account.<br/>
///   SECURE FIX (writeup #33): use <c>TypeNameHandling.None</c>, prefer POCO
///   DTOs, or move to <c>System.Text.Json</c> which has no polymorphic handling
///   by default.
/// </remarks>
public sealed class ImportService
{
    private readonly string _installRoot;

    public ImportService(string installRoot) { _installRoot = installRoot; }

    public string StartupDir => Path.Combine(_installRoot, "Startup");

    /// <summary>
    /// Writes <paramref name="payload"/> to the Startup folder under
    /// <paramref name="filename"/>. The filename is NOT sanitized, so a value
    /// like <c>..\..\flags\pwn.txt</c> escapes.
    /// </summary>
    public string ImportProfile(string filename, byte[] payload)
    {
        Directory.CreateDirectory(StartupDir);
        // VULN: #29 - no filename sanitization.
        var target = Path.Combine(StartupDir, filename);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllBytes(target, payload);
        return target;
    }

    /// <summary>
    /// Simulates the on-launch autorun sweep that would otherwise require
    /// restarting MVTC - if the Startup folder contains ANY .pwn file the
    /// scanner emits the configured autorun token (the #29 flag).
    /// </summary>
    public string? ReadAutorunFlag(string flagsDir)
    {
        try
        {
            if (!Directory.Exists(StartupDir)) return null;
            if (!Directory.EnumerateFiles(StartupDir, "*.pwn", SearchOption.TopDirectoryOnly).Any())
                return null;
            var p = Path.Combine(flagsDir, "v29_autorun.txt");
            return File.Exists(p) ? File.ReadAllText(p) : null;
        }
        catch { return null; }
    }

    public string ImportState(string jsonPath)
    {
        var json = File.ReadAllText(jsonPath);
        // VULN: #33 - TypeNameHandling.All with no SerializationBinder, so an
        // attacker-chosen $type causes the deserializer to instantiate any
        // assembly-loaded type, running its ctor and any field setter.
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };
        var obj = JsonConvert.DeserializeObject<object>(json, settings);
        return obj?.ToString() ?? "<null>";
    }
}
