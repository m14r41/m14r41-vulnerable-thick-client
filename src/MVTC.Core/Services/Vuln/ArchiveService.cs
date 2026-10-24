using System.IO.Compression;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #30 - CWE-22 - Zip Slip.
/// Extracts a zip archive by combining the destination directory with each
/// entry's name verbatim; a crafted entry name such as <c>../../pwn.txt</c>
/// escapes the target.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #30): compute the full destination path with
///   <c>Path.GetFullPath</c>, verify it starts with the target directory's
///   canonicalized form, and reject the entry otherwise. Prefer
///   <c>ZipFileExtensions.ExtractToDirectory(zip, dir, overwriteFiles: true)</c>
///   on recent .NET, which now rejects traversal, or validate yourself as below.
/// </remarks>
public sealed class ArchiveService
{
    public IReadOnlyList<string> Extract(string zipPath, string destinationDir)
    {
        Directory.CreateDirectory(destinationDir);
        var written = new List<string>();
        using var zip = ZipFile.OpenRead(zipPath);
        foreach (var entry in zip.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name)) continue;
            // VULN: #30 - naive combine, no normalization or containment check.
            var targetPath = Path.Combine(destinationDir, entry.FullName);
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            entry.ExtractToFile(targetPath, overwrite: true);
            written.Add(targetPath);
        }
        return written;
    }
}
