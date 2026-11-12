using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Codes;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

/// <summary>The step after the password: an email code (owners, players who chose it) or the authenticator app (admins).</summary>
public sealed class TwoStepModel(IAccountService accounts, ITwoFactorService twoFactor, IVerificationCodeService codes, SignInFlow flow) : AuthPageModel
{
    [BindProperty]
    public string Code { get; set; } = "";

    public bool UsesEmail { get; private set; }
    public string MaskedEmail { get; private set; } = "";
    public int ResendSeconds { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var (user, _) = await LoadAsync(cancellationToken);
        return user is null ? RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl }) : Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var (user, pending) = await LoadAsync(cancellationToken);
        if (user is null || pending is null) return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });

        var verified = await twoFactor.VerifyAsync(user, Code, cancellationToken);
        if (!verified.Succeeded)
        {
            ShowError(verified.Error);
            return Page();
        }

        await flow.CompleteAsync(user, pending.RememberMe, withTwoFactor: true);
        return Redirect(flow.Destination(pending.ReturnUrl ?? ReturnUrl));
    }

    public async Task<IActionResult> OnPostResendAsync(CancellationToken cancellationToken)
    {
        var (user, _) = await LoadAsync(cancellationToken);
        if (user is null) return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });

        var sent = await twoFactor.SendEmailCodeAsync(user, cancellationToken);
        if (sent.Succeeded) SuccessMessage = Ui.T("twostep.sent");
        else ShowError(sent.Error);
        ResendSeconds = await codes.SecondsUntilResendAsync(user.Id, CodePurpose.TwoFactor, cancellationToken);
        return Page();
    }

    private async Task<(AuthUser? User, PendingSignIn? Pending)> LoadAsync(CancellationToken cancellationToken)
    {
        var pending = flow.GetPending(PendingSignIn.TwoStep);
        if (pending is null) return (null, null);
        ReturnUrl ??= pending.ReturnUrl;
        var user = await accounts.FindAsync(pending.UserId, cancellationToken);
        if (user is null) return (null, null);

        UsesEmail = await twoFactor.RequiredMethodAsync(user) == TwoFactorMethod.Email;
        MaskedEmail = Mask(user.Email);
        if (UsesEmail) ResendSeconds = await codes.SecondsUntilResendAsync(user.Id, CodePurpose.TwoFactor, cancellationToken);
        return (user, pending);
    }

    /// <summary>"sohaib@example.com" becomes "so****@example.com".</summary>
    public static string Mask(string? email)
    {
        if (string.IsNullOrEmpty(email)) return "";
        var at = email.IndexOf('@');
        if (at <= 0) return email;
        var visible = Math.Min(2, at);
        return email[..visible] + new string('*', Math.Max(2, at - visible)) + email[at..];
    }
}
