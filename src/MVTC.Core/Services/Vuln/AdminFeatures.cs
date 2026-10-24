namespace MVTC.Core.Services.Vuln;

/// <summary>
/// Admin-only app features. Flags for #10, #11, and #19 are embedded in
/// realistic admin data (users directory, sealed-secret vault, signed
/// integrity report) rather than returned bare - a learner has to recognise
/// which field is actually sensitive.
/// </summary>
/// <remarks>
///   SECURE FIX: never gate privileged actions on client state. Have the
///   backend sign a short-lived capability token after a server-side
///   authorization check, bound to the user's session.
/// </remarks>
public sealed class AdminFeatures
{
    private readonly Func<int, string?> _flagLookup;

    public AdminFeatures(Func<int, string?> flagLookup) { _flagLookup = flagLookup; }

    // VULN: #11 - CWE-602 - "defense in depth" check that is itself in-client.
    public bool ExtraPrivilegeConfirmed { get; set; } = false;

    // VULN: #19 - populated only when the client's self-integrity gate flips
    // this field. In secure code the gate would be a signed capability from a
    // backend; here it is a public mutable bool a debugger can flip in a second.
    public bool IntegrityVerified { get; set; } = false;

    /// <summary>True iff the client is willing to show the Users directory.</summary>
    public bool CanOpenAdminUsers()
    {
        // VULN: #10 - the gate is OR'd between the HKCU role (registry flip,
        // writeup #10) and the current session's role (signing in as admin via
        // the login form - which the tester can discover by cracking admin's
        // MD5('admin') hash out of the users table they expose via SQLi, or by
        // reading svc_backup's plaintext password straight from the DB).
        var sessionRole = Services.AuthService.CurrentSession?.Role;
        if (string.Equals(sessionRole, "admin", StringComparison.OrdinalIgnoreCase)) return true;
        return string.Equals(RoleProvider.CurrentRole, "admin", StringComparison.OrdinalIgnoreCase);
    }

    public IReadOnlyList<(string Name, string Value, string Note)> ListSealedSecrets()
    {
        if (!ExtraPrivilegeConfirmed) return Array.Empty<(string, string, string)>();
        // VULN: #11 - flag is one of the three "sealed" entries. The others
        // are plausible-looking decoys so just dumping the list doesn't make
        // it obvious which value is actually the privileged secret.
        return new (string, string, string)[]
        {
            ("api.master.publishing",  "pub_sk_live_7af3b9c2d8e14",                   "Shared with the publishing CI"),
            ("vault.recovery.signing", _flagLookup(11) ?? "",                          "Rotated after each major release"),
            ("sso.okta.saml.cert",     "MIIC1TCCAb2gAwIBAgIQ…v2+Zu5A==",              "Public cert for SSO federation"),
        };
    }

    public string BuildIntegrityReportJson()
    {
        var now = DateTime.UtcNow.ToString("O");
        // VULN: #19 - signature is populated only when IntegrityVerified is
        // true. The report is otherwise built, signed, and returned exactly the
        // same way to any caller. Flip the field in dnSpy / x64dbg (there is
        // no server-signed check preventing it).
        var sig = IntegrityVerified ? (_flagLookup(19) ?? "") : "none";
        return "{\n" +
               $"  \"status\": \"ok\",\n" +
               $"  \"timestamp\": \"{now}\",\n" +
               $"  \"integrity\": \"verified\",\n" +
               $"  \"modules\": [\"MVTC.exe\",\"MVTC.Core.dll\",\"MVTCVaultSvc.exe\"],\n" +
               $"  \"debugger_detected\": false,\n" +
               $"  \"signature\": \"{sig}\"\n" +
               "}";
    }
}
