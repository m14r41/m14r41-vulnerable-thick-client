namespace MVTC.Core.Secrets;

/// <summary>
/// Hardcoded sensitive values. Everything in this class is a planted vulnerability -
/// values here ship inside the compiled DLL and are recoverable with any decompiler
/// (dnSpy, ILSpy, dotPeek) in seconds.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #26): secrets must come from a protected store at runtime
///   (DPAPI / Windows Credential Manager / Azure Key Vault / HSM) and never appear
///   as compiled string literals.
/// </remarks>
public static class HardcodedSecrets
{
    // VULN: #26 - CWE-798 - see SOLUTIONS/26-secrets-in-binary.md
    // Deliberately bogus "do not use this key" so students can see weak-key tells.
    public const string EncryptionKey = "D0NTUSETHISKEY00";

    // VULN: #26 - CWE-798 - flag planted directly in the compiled binary.
    // Static across all installs: the whole point is that a learner opens dnSpy
    // on MVTC.Core.dll (or MVTC.exe, which references this), sees the string
    // literal and submits it.
    public const string LegacyLicenseFlag = "MVTC{v26_bin_HARDC0DEDFLAG1NB1NARY_2026}";

    // VULN: #26 - "legacy support" API key - more plausibly-named decoy noise so
    // the dnSpy walk isn't a one-liner.
    public const string LegacyApiKey = "MVTC-APIKEY-7f3b9c-static-donotrotate";

    // VULN: #24 - CWE-327 - see SOLUTIONS/24-weak-crypto.md
    // Static IV (zero bytes) paired with AES-ECB. Deterministic ciphertexts for
    // the same plaintext; CPA-trivial.
    public static readonly byte[] StaticIv = new byte[16];

    // VULN: #46 - CWE-640 - predictable account-recovery token.
    // Reset token = MD5(username + yyyy-MM-dd + RecoverySalt). A hardcoded
    // tenant-wide salt means any attacker who ever decompiled the client can
    // forge a reset for any user, any day.
    public const string RecoverySalt = "mvtc-reset-2024";

    // VULN: #49 - CWE-338 - the "admin API key" is produced by System.Random
    // seeded with this constant. The whole point is that the seed is a
    // compiled integer literal: dnSpy on MVTC.Core.dll → this file → done.
    public const int AdminApiKeyRandomSeed = 42;

    // VULN: #50 - CWE-321 - HMAC-SHA256 signing secret for session JWTs.
    // Hardcoded string literal shipped in every binary. Anyone with the
    // binary can mint arbitrary tokens (sub=admin, role=admin, …).
    public const string JwtSigningSecret = "mvtc-super-secret-2024";
}
