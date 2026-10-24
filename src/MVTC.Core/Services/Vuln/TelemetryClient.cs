using System.Net.Http;
using System.Net.Http.Json;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #45 - CWE-918 - Thick-client SSRF via attacker-configurable
/// "diagnostic telemetry" endpoint. The URL is read straight from the user's
/// config without origin / scheme / host validation, and the POST body
/// contains session identifiers that would be privileged in a real deployment.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #45): pin the telemetry endpoint to a known origin
///   in a signed build-time manifest, hash + sign the payload, require mutual
///   TLS. If the endpoint is user-configurable at all, allow only an
///   organization-level allowlist resolved by the backend.
/// </remarks>
public sealed class TelemetryClient
{
    private readonly HttpClient _http;

    public TelemetryClient()
    {
        var handler = new HttpClientHandler
        {
            // VULN: accept any TLS cert - intentional for the lab.
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
    }

    /// <summary>
    /// POSTs a diagnostic bundle to the configured endpoint. The bundle
    /// deliberately includes the #45 flag as the <c>trace_token</c> field -
    /// a learner stands up a listener (nc, Burp Collaborator, requestbin) and
    /// reads it off the wire.
    /// </summary>
    public async Task<string> SendAsync(string endpointUrl, string? flagLookup45, string? username, string? role)
    {
        if (string.IsNullOrWhiteSpace(endpointUrl))
            throw new InvalidOperationException("No telemetry endpoint configured.");

        var body = new
        {
            agent = "MVTC/1.2 (vault-manager; windows)",
            timestamp = DateTime.UtcNow.ToString("O"),
            user = username ?? "<none>",
            role = role ?? "<none>",
            // VULN: #45 - this is the sensitive bit a tester fishes out of
            // their attacker-controlled listener's inbound request body.
            trace_token = flagLookup45 ?? "",
            modules = new[] { "MVTC.exe", "MVTC.Core.dll", "MVTCVaultSvc.exe" }
        };

        var resp = await _http.PostAsJsonAsync(endpointUrl, body);
        return $"POST {endpointUrl}\nstatus: {(int)resp.StatusCode} {resp.ReasonPhrase}";
    }
}
