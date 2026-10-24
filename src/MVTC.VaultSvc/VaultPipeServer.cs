using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using MVTC.Core.Services.Insecure;

namespace MVTC.VaultSvc;

/// <summary>
/// VULN: #37 - CWE-306 - Insecure IPC.
/// Named-pipe server that accepts every caller with no authentication, no
/// client-identity check, and no integrity-level gate. Verbs include
/// <c>GET_FLAG_37</c>, <c>IMPERSONATE_READ</c> (#6), and <c>TOCTOU_COPY</c>
/// (#12), each of which exposes a path the service runs with elevated
/// access to (SYSTEM in MSI deployments; current user in dev).
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #37): construct the pipe with a restrictive
///   <see cref="PipeSecurity"/> (grant only the known-trusted principal), call
///   <c>pipe.RunAsClient(...)</c> + <c>WindowsIdentity.GetCurrent</c> to confirm
///   the caller, and reject unauthenticated / low-IL clients.
/// </remarks>
public sealed class VaultPipeServer : IDisposable
{
    private readonly string _flagFilePath37;
    private readonly string _flagFilePath06;
    private readonly string _flagFilePath12;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public VaultPipeServer(string flagFilePath37, string flagFilePath06, string flagFilePath12)
    {
        _flagFilePath37 = flagFilePath37;
        _flagFilePath06 = flagFilePath06;
        _flagFilePath12 = flagFilePath12;
        _loop = Task.Run(() => AcceptLoop(_cts.Token));
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreateInsecurePipe();
                await pipe.WaitForConnectionAsync(ct);
                await HandleAsync(pipe, ct);
            }
            catch (OperationCanceledException) { break; }
            catch { /* swallow and keep serving */ }
            finally { pipe?.Dispose(); }
        }
    }

    private static NamedPipeServerStream CreateInsecurePipe()
    {
        if (OperatingSystem.IsWindows())
            return CreateInsecurePipeWindows();
        // On non-Windows there's no NamedPipeServerStreamAcl; fall back to defaults.
        return new NamedPipeServerStream(
            VaultPipeClient.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateInsecurePipeWindows()
    {
        // VULN: #37 - grant Everyone (WorldSid) full read/write on the pipe.
        // In an MSI SYSTEM-service deployment, this means any logged-in user
        // can invoke the privileged verbs without authentication.
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            VaultPipeClient.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 4096,
            outBufferSize: 4096,
            pipeSecurity: security);
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var buf = new byte[4096];
        var n = await pipe.ReadAsync(buf, 0, buf.Length, ct);
        if (n <= 0) return;
        var request = Encoding.UTF8.GetString(buf, 0, n);
        var parts = request.Split('|', 2);
        var verb = parts[0];
        var arg = parts.Length > 1 ? parts[1] : "";

        // All verbs return a JSON-shaped response so a wire capture doesn't
        // immediately scream "flag". Learners have to recognise which field
        // in the response is actually sensitive.
        var response = verb switch
        {
            "PING"             => "{\"result\":\"pong\",\"service\":\"MVTCVaultSvc\"}",
            "WHOAMI"           => $"{{\"identity\":\"{Environment.UserName}@{Environment.MachineName}\"}}",
            // Shadow of the old flag-named verbs, kept because the writeups
            // reference them by name - but we also accept nicer verbs.
            "GET_FLAG_37" or "EXPORT_SERVICE_KEY" or "EXPORT_SVC_CREDS" =>
                $"{{\"status\":\"ok\",\"key_id\":\"svc-key-001\",\"issued\":\"{DateTime.UtcNow:O}\",\"value\":\"{SafeRead(_flagFilePath37)}\"}}",
            "IMPERSONATE_READ" or "SYS_READ" =>
                $"{{\"status\":\"ok\",\"caller\":\"<impersonated>\",\"payload\":\"{SafeRead(_flagFilePath06)}\"}}",
            "TOCTOU_COPY" or "ATOMIC_COPY" =>
                $"{{\"status\":\"ok\",\"transferred\":true,\"content\":\"{SafeRead(_flagFilePath12)}\"}}",
            "ECHO"             => $"{{\"echo\":\"{arg.Replace("\"", "\\\"")}\"}}",
            _                  => $"{{\"error\":\"unknown verb\",\"verb\":\"{verb}\"}}"
        };

        var bytes = Encoding.UTF8.GetBytes(response);
        await pipe.WriteAsync(bytes, 0, bytes.Length, ct);
        await pipe.FlushAsync(ct);
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loop.Wait(500); } catch { }
        _cts.Dispose();
    }

    private static string SafeRead(string path) =>
        File.Exists(path) ? File.ReadAllText(path).Replace("\"", "\\\"").Replace("\n","").Replace("\r","") : "";
}
