using System.Diagnostics;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #31 - CWE-74 - CHM file injection (via Windows' Help viewer).
/// The in-app Help menu accepts a user-chosen .chm path and launches hh.exe
/// against it, so a maliciously-crafted .chm can run embedded commands.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #31): ship a single bundled .chm under the install
///   directory, open only that fixed path, and never accept a user-chosen help
///   file. If dynamic docs are needed, host them in-app rather than via
///   <c>hh.exe</c>.
/// </remarks>
public sealed class HelpService
{
    public (int ExitCode, string Output) OpenHelp(string helpFilePath)
    {
        // VULN: #31 - accepts any path; a malicious .chm or any other file type
        // the shell will execute (.lnk, .url) gets opened verbatim.
        var ext = Path.GetExtension(helpFilePath).ToLowerInvariant();
        var psi = ext switch
        {
            ".chm" => new ProcessStartInfo("hh.exe", $"\"{helpFilePath}\"") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true },
            _      => new ProcessStartInfo(helpFilePath) { UseShellExecute = true }
        };
        try
        {
            using var p = Process.Start(psi);
            if (p is null) return (-1, "no process");
            if (psi.RedirectStandardOutput)
            {
                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5_000);
                return (p.ExitCode, output);
            }
            return (0, $"launched: {helpFilePath}");
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }
}
