using System.Diagnostics;
using System.Text;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #35 - CWE-78 - OS command injection.
/// The "network diagnostics" ping feature concatenates user input directly
/// into a shell command line.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #35): launch the target program with argument-array
///   APIs, never <c>UseShellExecute</c> or <c>/c &lt;input&gt;</c>; validate the
///   host against a hostname / IP regex before invocation.
/// </remarks>
public sealed class DiagService
{
    public (int ExitCode, string Output) Ping(string host)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            // VULN: #35 - classic shell interpolation. "127.0.0.1 & type ..\flag.txt"
            // runs ping AND type-dumps whatever path the attacker names.
            Arguments = $"/c ping -n 1 {host}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        var sb = new StringBuilder();
        sb.Append(p.StandardOutput.ReadToEnd());
        sb.Append(p.StandardError.ReadToEnd());
        p.WaitForExit(10_000);
        return (p.ExitCode, sb.ToString());
    }
}
