using System.Security.Cryptography;
using System.Text;
using MVTC.Core.Secrets;

namespace MVTC.Core.Crypto;

/// <summary>
/// Deliberately weak crypto helpers used by the app's config, session, and
/// legacy-asset-note subsystems. ECB mode, static IV, MD5 for password hashing.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #24): use AEAD (AES-GCM or ChaCha20-Poly1305) with
///   a random nonce per encryption, keys derived with HKDF, and passwords
///   hashed with Argon2id or PBKDF2 (≥ 600k iterations in 2026).
/// </remarks>
public static class WeakCrypto
{
    // VULN: #24 - CWE-327 - AES-ECB; identical plaintext blocks produce identical ciphertext.
    public static byte[] EncryptEcb(string plaintext, string? key = null)
    {
        var k = DeriveKey16(key ?? HardcodedSecrets.EncryptionKey);
        using var aes = Aes.Create();
        aes.Key = k;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        var pt = Encoding.UTF8.GetBytes(plaintext);
        return enc.TransformFinalBlock(pt, 0, pt.Length);
    }

    public static string DecryptEcb(byte[] ciphertext, string? key = null)
    {
        var k = DeriveKey16(key ?? HardcodedSecrets.EncryptionKey);
        using var aes = Aes.Create();
        aes.Key = k;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        var pt = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        return Encoding.UTF8.GetString(pt);
    }

    // VULN: #24 - CWE-328 - MD5 for password hashing. Fast, no salt, rainbow-table bait.
    public static string MdFive(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // Pad or truncate a key string to exactly 16 bytes (AES-128). Classic footgun -
    // discards entropy past 16 chars and pads short keys with 0x00.
    private static byte[] DeriveKey16(string key)
    {
        var buf = new byte[16];
        var kb = Encoding.UTF8.GetBytes(key);
        Array.Copy(kb, buf, Math.Min(kb.Length, buf.Length));
        return buf;
    }
}
