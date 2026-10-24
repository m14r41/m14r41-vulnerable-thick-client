namespace MVTC.Core.Services.Vuln;

/// <summary>
/// Deserialization gadget used by the #33 lab challenge. Having a public
/// setter that *reads a file* means that any attacker able to force this type
/// to be constructed through <c>Newtonsoft.Json</c> with
/// <see cref="Newtonsoft.Json.TypeNameHandling.All"/> can pick the file path.
/// </summary>
/// <remarks>
///   This exists to make the gadget demo work in-process. In real-world
///   deserialization chains the gadget is usually a type the application never
///   intended to be reachable (e.g. <c>ObjectDataProvider</c>,
///   <c>WindowsIdentity</c>) that happens to be loaded in-process.
/// </remarks>
public sealed class StateProbe
{
    private string _path = "";

    public string Path
    {
        get => _path;
        set
        {
            _path = value;
            try { Loaded = File.ReadAllText(value); }
            catch (Exception ex) { Loaded = $"<read failed: {ex.Message}>"; }
        }
    }

    public string Loaded { get; set; } = "";

    public override string ToString() => Loaded;
}
