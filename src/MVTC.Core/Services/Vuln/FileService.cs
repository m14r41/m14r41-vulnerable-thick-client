namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #32 - CWE-22 - Path traversal.
/// The "view report" feature concatenates a user path onto the reports root
/// with no normalization, so <c>..\..\flags\v32.txt</c> escapes.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #32): canonicalize via <c>Path.GetFullPath</c>, then
///   verify the result starts with the normalized base directory before
///   opening.
/// </remarks>
public sealed class FileService
{
    private readonly string _reportsRoot;
    public FileService(string reportsRoot) { _reportsRoot = reportsRoot; }

    public string ReadReport(string userPath)
    {
        // VULN: #32 - raw Path.Combine; a leading drive letter OR enough
        // "..\" segments break out of _reportsRoot.
        var full = Path.Combine(_reportsRoot, userPath);
        return File.ReadAllText(full);
    }
}
