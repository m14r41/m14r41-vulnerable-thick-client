using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using MVTC.Core.Crypto;
using MVTC.Core.Secrets;

namespace MVTC.App.Views;

/// <summary>
/// Account & API surface. Each section hosts one deliberately-planted
/// vulnerability (#46-#50) and shows its challenge tag so the mapping to the
/// Flag console is obvious.
/// </summary>
public partial class AccountPanel : UserControl
{
    public AccountPanel()
    {
        InitializeComponent();
    }

    // ---------- #46 - predictable account-recovery token ----------

    private static string ComputeResetToken(string user)
    {
        var day = DateTime.UtcNow.ToString("yyyy-MM-dd");
        return WeakCrypto.MdFive(user.ToLowerInvariant() + day + HardcodedSecrets.RecoverySalt);
    }

    private void OnRequestReset(object sender, RoutedEventArgs e)
    {
        var user = ResetUserBox.Text.Trim();
        if (user.Length == 0) { ResetOut.Text = "Enter a username."; return; }

        // The real bug: the "reset email" is simulated locally and the token
        // itself is handed to the caller. Also written into the audit log, so
        // an operator reading logs sees a sample pair.
        var tok = ComputeResetToken(user);
        ResetOut.Text =
            $"[sim] Reset email dispatched to {user}@mvtc.local.\n" +
            $"[sim] token  = {tok}\n" +
            $"[sim] formula= md5(username + yyyy-MM-dd + salt).  See audit.log for a historical pair.";
    }

    private void OnRedeemReset(object sender, RoutedEventArgs e)
    {
        var user = ResetUserBox.Text.Trim();
        var tok  = ResetTokenBox.Text.Trim();
        if (user.Length == 0 || tok.Length == 0)
        {
            ResetOut.Text = "Need both a username and a token.";
            return;
        }
        var expected = ComputeResetToken(user);
        if (!string.Equals(tok, expected, StringComparison.OrdinalIgnoreCase))
        {
            ResetOut.Text = $"invalid token for user={user}.  (hint: formula is predictable)";
            return;
        }

        // Successful admin reset → flag revealed.
        if (string.Equals(user, "admin", StringComparison.OrdinalIgnoreCase))
        {
            var flag46 = App.Progress?.GetFlagPlaintext(46) ?? "MVTC{v46_rst_plant_missing}";
            ResetOut.Text =
                "Reset accepted for admin. Session re-issued.\n" +
                $"Flag: {flag46}";
        }
        else
        {
            ResetOut.Text = $"Reset accepted for {user}. (not an admin - no flag planted here)";
        }
    }

    // ---------- #47 - IDOR on asset lookup ----------

    private void OnLookupAsset(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(AssetIdBox.Text.Trim(), out var id)) { AssetOut.Text = "Enter a numeric id."; return; }

        // VULN #47 - no ownership check against the current session.
        // Normal records live 1..10. The admin's archive sits at a modest
        // ID that isn't publicised anywhere.
        if (id >= 1 && id <= 10)
        {
            AssetOut.Text = $"asset[{id}] owner=m14r41 kind=note title=\"my-{id}.txt\" preview=\"(user document)\"";
            return;
        }
        if (id == 1337)
        {
            // Admin ciphertext row - contains #47 flag inline.
            var planted = ReadPlantedFile("v47_idor.txt") ?? "MVTC{v47_idor_plant_missing}";
            AssetOut.Text =
                $"asset[1337] owner=admin kind=vault_archive title=\"admin_ciphertext.bin\"\n" +
                $"preview = \"... ... ... {planted}\"";
            return;
        }
        AssetOut.Text = $"asset[{id}] not found. (ownership check is… loose - try wider ranges)";
    }

    private static string? ReadPlantedFile(string name)
    {
        try
        {
            var path = Path.Combine(App.InstallRoot, "flags", name);
            if (File.Exists(path)) return File.ReadAllText(path).Trim();
        }
        catch { }
        return null;
    }

    // ---------- #48 - mass assignment ----------

    private void OnUpdateProfile(object sender, RoutedEventArgs e)
    {
        var raw = ProfileJsonBox.Text ?? "";
        if (raw.Trim().Length == 0) { ProfileOut.Text = "Empty body."; return; }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;

            // VULN #48 - no allow-list. We take whatever fields the body carries
            // and merge them into the user record. role, isAdmin, apiKeyRotation -
            // all accepted.
            var display = root.TryGetProperty("displayName", out var d) ? d.GetString() ?? "" : "";
            var email   = root.TryGetProperty("email",       out var m) ? m.GetString() ?? "" : "";
            var role    = root.TryGetProperty("role",        out var r) ? r.GetString() ?? "user" : "user";

            var sb = new StringBuilder();
            sb.AppendLine("PUT /api/profile  200 OK");
            sb.AppendLine("---");
            sb.AppendLine($"displayName = {display}");
            sb.AppendLine($"email       = {email}");
            sb.AppendLine($"role        = {role}");

            if (string.Equals(role, "admin", StringComparison.OrdinalIgnoreCase))
            {
                var flag48 = App.Progress?.GetFlagPlaintext(48) ?? "MVTC{v48_mas_plant_missing}";
                sb.AppendLine();
                sb.AppendLine("role=admin accepted. On role transition, server leaks the next-admin welcome payload:");
                sb.AppendLine($"welcome = {flag48}");
            }
            else
            {
                sb.AppendLine();
                sb.AppendLine("(no extra fields of interest were honoured)");
            }

            ProfileOut.Text = sb.ToString();
        }
        catch (JsonException ex)
        {
            ProfileOut.Text = "400 Bad Request :: invalid JSON (" + ex.Message + ")";
        }
    }

    // ---------- #49 - weak PRNG API key ----------

    private static string KeyFromSeed(int seed)
    {
        // Deterministic 32-char hex from System.Random. The weakness is the
        // seed, not the formatter: seed=42 always yields the same key.
        var rnd = new Random(seed);
        var buf = new byte[16];
        rnd.NextBytes(buf);
        var hex = new StringBuilder(32);
        foreach (var b in buf) hex.Append(b.ToString("x2"));
        return "pk_" + hex;
    }

    private void OnGenKey(object sender, RoutedEventArgs e)
    {
        var seed = DateTime.UtcNow.Second;
        var key = KeyFromSeed(seed);
        KeyOut.Text =
            $"issued key = {key}\n" +
            $"seed used  = DateTime.UtcNow.Second = {seed}\n" +
            $"(the admin API key was issued the same way, with a seed set at install time. Reproduce the seed, derive the key.)";
    }

    private void OnVerifyKey(object sender, RoutedEventArgs e)
    {
        var submitted = VerifyKeyBox.Text.Trim();
        if (submitted.Length == 0) { KeyOut.Text = "Enter the admin key you derived."; return; }

        var adminKey = KeyFromSeed(HardcodedSecrets.AdminApiKeyRandomSeed);
        if (string.Equals(submitted, adminKey, StringComparison.Ordinal))
        {
            var flag49 = App.Progress?.GetFlagPlaintext(49) ?? "MVTC{v49_prng_plant_missing}";
            KeyOut.Text =
                "match.  caller authenticated as admin.\n" +
                $"flag: {flag49}";
        }
        else
        {
            KeyOut.Text = "no match.  (hint: the seed is a hardcoded int literal - dnSpy on MVTC.Core.dll → HardcodedSecrets)";
        }
    }

    // ---------- #50 - hardcoded JWT secret ----------

    private static string Base64UrlEncode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }

    private void OnMintDemoJwt(object sender, RoutedEventArgs e)
    {
        // Convenience: mint a legit non-admin token so the user can see what a
        // valid payload looks like before forging their own.
        var header  = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        var payload = "{\"sub\":\"m14r41\",\"role\":\"user\"}";
        var tok = SignJwt(header, payload);
        JwtBox.Text = tok;
        JwtOut.Text = "demo JWT written to the box above. decode on jwt.io to see the claims - then try sub=admin.";
    }

    private static string SignJwt(string header, string payload)
    {
        var h = Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var p = Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var signing = h + "." + p;
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(HardcodedSecrets.JwtSigningSecret));
        var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(signing));
        return signing + "." + Base64UrlEncode(sig);
    }

    private void OnRestoreJwt(object sender, RoutedEventArgs e)
    {
        var tok = JwtBox.Text.Trim();
        var parts = tok.Split('.');
        if (parts.Length != 3) { JwtOut.Text = "400 :: not a JWS (expected header.payload.signature)."; return; }

        try
        {
            var signing = parts[0] + "." + parts[1];
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(HardcodedSecrets.JwtSigningSecret));
            var expected = Base64UrlEncode(hmac.ComputeHash(Encoding.UTF8.GetBytes(signing)));
            if (!string.Equals(expected, parts[2], StringComparison.Ordinal))
            {
                JwtOut.Text = "401 :: signature mismatch. (hint: HS256 secret is a string literal in MVTC.Core.dll → HardcodedSecrets)";
                return;
            }

            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            using var doc = JsonDocument.Parse(payloadJson);
            var sub = doc.RootElement.TryGetProperty("sub", out var s) ? s.GetString() ?? "" : "";

            if (string.Equals(sub, "admin", StringComparison.OrdinalIgnoreCase))
            {
                var flag50 = App.Progress?.GetFlagPlaintext(50) ?? "MVTC{v50_jwt_plant_missing}";
                JwtOut.Text =
                    $"200 OK :: session restored as sub={sub}, role=admin.\n" +
                    $"flag: {flag50}";
            }
            else
            {
                JwtOut.Text = $"200 OK :: session restored as sub={sub}.  (nothing admin-grade to leak for this subject)";
            }
        }
        catch (Exception ex)
        {
            JwtOut.Text = "500 :: " + ex.GetType().Name + " " + ex.Message;
        }
    }
}
