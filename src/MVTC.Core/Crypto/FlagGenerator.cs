using System.Security.Cryptography;
using System.Text;

namespace MVTC.Core.Crypto;

/// <summary>
/// Generates MVTC flags: <c>MVTC{v##_&lt;slug&gt;_&lt;16-byte base32&gt;}</c>.
/// Flag plaintexts are generated once at seed time; only SHA-256 hashes are stored.
/// </summary>
public static class FlagGenerator
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Build(int vulnNo, string slug, byte[] randomBytes)
    {
        var suffix = EncodeBase32(randomBytes);
        return $"MVTC{{v{vulnNo:D2}_{slug}_{suffix}}}";
    }

    public static string NewRandom(int vulnNo, string slug)
    {
        var bytes = RandomNumberGenerator.GetBytes(10);
        return Build(vulnNo, slug, bytes);
    }

    public static string Hash(string flag)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(flag.Trim()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static string EncodeBase32(byte[] bytes)
    {
        var sb = new StringBuilder();
        var bits = 0;
        var value = 0;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(Base32Alphabet[(value >> bits) & 0x1F]);
            }
        }
        if (bits > 0) sb.Append(Base32Alphabet[(value << (5 - bits)) & 0x1F]);
        return sb.ToString();
    }
}
