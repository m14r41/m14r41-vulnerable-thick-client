using System.IO.Pipes;
using System.Text;

namespace MVTC.Core.Services.Insecure;

/// <summary>
/// Client half of the insecure IPC pair (VULN: #37). Any caller - regardless
/// of integrity level - can connect to the pipe and invoke privileged ops.
/// </summary>
public sealed class VaultPipeClient
{
    public const string PipeName = "MVTCVaultSvc";

    public static string Call(string verb, string argument = "", int timeoutMs = 2000)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
        pipe.Connect(timeoutMs);
        var request = Encoding.UTF8.GetBytes($"{verb}|{argument}");
        pipe.Write(request, 0, request.Length);
        pipe.WaitForPipeDrain();
        var buf = new byte[65_536];
        var n = pipe.Read(buf, 0, buf.Length);
        return Encoding.UTF8.GetString(buf, 0, n);
    }
}
