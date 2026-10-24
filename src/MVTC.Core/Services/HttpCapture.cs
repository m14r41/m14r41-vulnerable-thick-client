using System.Net.Http;
using System.Text;

namespace MVTC.Core.Services;

/// <summary>
/// Session-lifetime ring buffer of HTTP requests the app made. Used by the
/// in-app Network Capture viewer so testers don't strictly need Burp /
/// Wireshark to see what the app sent - though those tools still work.
/// </summary>
public static class HttpCapture
{
    private const int Capacity = 200;
    private static readonly LinkedList<CaptureEntry> _entries = new();
    private static readonly object _gate = new();

    public static void Record(CaptureEntry e)
    {
        lock (_gate)
        {
            _entries.AddLast(e);
            while (_entries.Count > Capacity) _entries.RemoveFirst();
        }
    }

    public static IReadOnlyList<CaptureEntry> Snapshot()
    {
        lock (_gate) return _entries.ToArray();
    }

    public static void Clear()
    {
        lock (_gate) _entries.Clear();
    }
}

public sealed class CaptureEntry
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Method { get; set; } = "";
    public string Url { get; set; } = "";
    public int? StatusCode { get; set; }
    public string? RequestBody { get; set; }
    public string? ResponseBody { get; set; }
    public long DurationMs { get; set; }
}

/// <summary>
/// Attach to an <see cref="HttpClient"/> as a <see cref="DelegatingHandler"/>
/// to append every request/response to <see cref="HttpCapture"/>.
/// </summary>
public sealed class CapturingHandler : DelegatingHandler
{
    public CapturingHandler() : base(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    }) { }

    public CapturingHandler(HttpMessageHandler inner) : base(inner) { }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var entry = new CaptureEntry
        {
            Timestamp = DateTime.UtcNow,
            Method = request.Method.Method,
            Url = request.RequestUri?.ToString() ?? "",
            RequestBody = request.Content is null ? null : await SafeReadAsync(request.Content)
        };
        var started = DateTime.UtcNow;
        try
        {
            var response = await base.SendAsync(request, cancellationToken);
            entry.StatusCode = (int)response.StatusCode;
            entry.ResponseBody = await SafeReadAsync(response.Content);
            entry.DurationMs = (long)(DateTime.UtcNow - started).TotalMilliseconds;
            HttpCapture.Record(entry);
            return response;
        }
        catch
        {
            entry.StatusCode = -1;
            entry.DurationMs = (long)(DateTime.UtcNow - started).TotalMilliseconds;
            HttpCapture.Record(entry);
            throw;
        }
    }

    private static async Task<string?> SafeReadAsync(HttpContent? content)
    {
        if (content is null) return null;
        try { return await content.ReadAsStringAsync(); }
        catch { return null; }
    }
}
