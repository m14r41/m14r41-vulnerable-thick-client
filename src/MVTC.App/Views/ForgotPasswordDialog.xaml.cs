using System.Windows;
using MVTC.Core.Crypto;
using MVTC.Core.Secrets;

namespace MVTC.App.Views;

/// <summary>
/// #46 - CWE-640. The "Forgot password?" link on the sign-in screen opens
/// this dialog. The token formula is identical to the Account panel's
/// post-login reset: <c>MD5(user + yyyy-MM-dd + salt)</c>. Both entry
/// points share the vulnerability.
/// </summary>
public partial class ForgotPasswordDialog : Window
{
    public ForgotPasswordDialog()
    {
        InitializeComponent();
    }

    private static string ComputeResetToken(string user)
    {
        var day = DateTime.UtcNow.ToString("yyyy-MM-dd");
        return WeakCrypto.MdFive(user.ToLowerInvariant() + day + HardcodedSecrets.RecoverySalt);
    }

    private void OnRequest(object sender, RoutedEventArgs e)
    {
        var user = UserBox.Text.Trim();
        if (user.Length == 0) { OutText.Text = "Enter a username."; return; }

        var tok = ComputeResetToken(user);
        OutText.Text =
            $"[sim] reset email dispatched to {user}@mvtc.local\n" +
            $"[sim] token  = {tok}\n" +
            $"[sim] formula = md5(user + yyyy-MM-dd + salt)";
    }

    private void OnRedeem(object sender, RoutedEventArgs e)
    {
        var user = UserBox.Text.Trim();
        var tok  = TokenBox.Text.Trim();
        if (user.Length == 0 || tok.Length == 0) { OutText.Text = "Need both a username and a token."; return; }

        var expected = ComputeResetToken(user);
        if (!string.Equals(tok, expected, StringComparison.OrdinalIgnoreCase))
        {
            OutText.Text = $"invalid token for user={user}. (hint: the formula is predictable)";
            return;
        }

        if (string.Equals(user, "admin", StringComparison.OrdinalIgnoreCase))
        {
            var flag46 = App.Progress?.GetFlagPlaintext(46) ?? "MVTC{v46_rst_plant_missing}";
            OutText.Text =
                "reset accepted for admin. session re-issued.\n" +
                $"flag: {flag46}";
        }
        else
        {
            OutText.Text = $"reset accepted for {user}. (not an admin - no flag planted here)";
        }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
