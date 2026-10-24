using System.Net.Http;
using System.Text.Json.Serialization;

using MVTC.Core.Services;

namespace MVTC.Core.Services.Insecure;

/// <summary>
/// VULN: #38 - CWE-345 - Insecure auto-update.
/// Downloads the manifest and payload over plain HTTP, performs NO signature
/// / integrity check, and writes the payload under the install directory for
/// use at next launch. Anybody who can respond to the loopback-mock-update
/// endpoint can push code into MVTC.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #38): fetch the manifest over HTTPS pinned to the
///   publisher's root, verify a detached signature on both manifest and
///   payload (Ed25519 / ECDSA-P256), write to a staging directory with
///   restrictive DACLs, and only promote after signature verification.
/// </remarks>
public sealed class InsecureUpdateService
{
    private readonly HttpClient _http;
    private readonly string _installRoot;
    public Uri ManifestUrl { get; }

    public InsecureUpdateService(Uri manifestUrl, string installRoot)
    {
        ManifestUrl = manifestUrl;
        _installRoot = installRoot;
        _http = new HttpClient(new CapturingHandler()) { Timeout = TimeSpan.FromSeconds(5) };
    }

    public async Task<UpdateResult> CheckAndApplyAsync(CancellationToken ct = default)
    {
        var manifestJson = await _http.GetStringAsync(ManifestUrl, ct);
        // VULN: #38 - JSON parsed and acted on with no signature.
        var manifest = System.Text.Json.JsonSerializer.Deserialize<Manifest>(manifestJson);
        if (manifest is null) return new UpdateResult("no-manifest", "", "", "");

        var payloadBytes = await _http.GetByteArrayAsync(manifest.PayloadUrl, ct);
        // VULN: #38 - no hash check, no sig check, just write it under the install dir.
        var stagingDir = Path.Combine(_installRoot, "update_staging");
        Directory.CreateDirectory(stagingDir);
        var payloadPath = Path.Combine(stagingDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, payloadBytes, ct);

        return new UpdateResult("ok", manifest.Version, manifest.ReleaseNotes, payloadPath);
    }

    public sealed class Manifest
    {
        [JsonPropertyName("version")]       public string Version { get; set; } = "";
        [JsonPropertyName("payload_url")]   public string PayloadUrl { get; set; } = "";
        [JsonPropertyName("release_notes")] public string ReleaseNotes { get; set; } = "";
    }

    public sealed record UpdateResult(string Status, string Version, string ReleaseNotes, string PayloadPath);
}
