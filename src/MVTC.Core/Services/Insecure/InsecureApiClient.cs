using System.Net.Http;
using System.Net.Http.Json;
using MVTC.Core.Services;

namespace MVTC.Core.Services.Insecure;

/// <summary>
/// VULN: #39 - CWE-295 - Improper TLS validation.
/// Accepts every certificate (callback returns true) and talks to the mock API
/// over plaintext HTTP, so credentials travel in the clear and MITM is trivial.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #39): remove the custom validation callback (let .NET
///   enforce chain + hostname + revocation), switch the endpoint to HTTPS, and
///   pin the server certificate's public key hash where appropriate.
/// </remarks>
public sealed class InsecureApiClient : IDisposable
{
    private readonly HttpClient _http;
    public Uri BaseUri { get; }

    public InsecureApiClient(Uri baseUri)
    {
        BaseUri = baseUri;
        var handler = new HttpClientHandler
        {
            // VULN: #39 - accept everything.
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        var capturing = new CapturingHandler(handler);
        _http = new HttpClient(capturing) { BaseAddress = baseUri, Timeout = TimeSpan.FromSeconds(5) };
    }

    public async Task<LoginResponse?> LoginAsync(string username, string password, CancellationToken ct = default)
    {
        // VULN: #39 - credentials in the request body, over HTTP, with no mutual auth.
        var resp = await _http.PostAsJsonAsync("/login", new { username, password }, ct);
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadFromJsonAsync<LoginResponse>(cancellationToken: ct);
    }

    public void Dispose() => _http.Dispose();

    public sealed class LoginResponse
    {
        public string? username { get; set; }
        public string? role { get; set; }
        public string? secure_token { get; set; }
    }
}
