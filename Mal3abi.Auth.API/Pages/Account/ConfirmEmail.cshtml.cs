using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Codes;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class ConfirmEmailModel(IAccountService accounts, ITwoFactorService twoFactor, IVerificationCodeService codes, SignInFlow flow) : AuthPageModel
{
    [BindProperty]
    public string Code { get; set; } = "";

    [BindProperty]
    public string? Email { get; set; }

    public bool HasPending { get; private set; }
    public bool Done { get; private set; }
    public string MaskedEmail { get; private set; } = "";
    public int ResendSeconds { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var user = await PendingUserAsync(cancellationToken);
        if (user?.EmailConfirmed == true) return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var pending = flow.GetPending(PendingSignIn.ConfirmEmail);
        var user = await PendingUserAsync(cancellationToken);

        if (user is null)
        {
            var errors = NewFieldErrors().Email(nameof(Email), Email, "confirm.email");
            if (Invalid(errors)) return Page();
            var byEmail = await accounts.ConfirmEmailAsync(Email!, Code, cancellationToken);
            if (!byEmail.Succeeded)
            {
                ShowError(byEmail.Error);
                return Page();
            }
            Done = true;
            return Page();
        }

        var confirmed = await accounts.ConfirmEmailAsync(user.Id, Code, cancellationToken);
        if (!confirmed.Succeeded)
        {
            ShowError(confirmed.Error);
            ResendSeconds = await codes.SecondsUntilResendAsync(user.Id, CodePurpose.EmailConfirmation, cancellationToken);
            return Page();
        }

        var method = await twoFactor.RequiredMethodAsync(user);
        if (method == TwoFactorMethod.Authenticator && user.TwoFactorMethod == TwoFactorMethod.Authenticator)
        {
            flow.SetPending(user.Id, PendingSignIn.TwoStep, pending!.RememberMe, pending.ReturnUrl);
            return RedirectToPage("/Account/TwoStep", new { returnUrl = pending.ReturnUrl });
        }

        await flow.CompleteAsync(user, pending!.RememberMe, withTwoFactor: method != TwoFactorMethod.Authenticator);
        return Redirect(flow.Destination(pending.ReturnUrl ?? ReturnUrl));
    }

    public async Task<IActionResult> OnPostResendAsync(CancellationToken cancellationToken)
    {
        var user = await PendingUserAsync(cancellationToken);
        var result = user is not null
            ? await accounts.SendConfirmationCodeAsync(user, cancellationToken)
            : string.IsNullOrWhiteSpace(Email) ? null : await accounts.SendConfirmationCodeAsync(Email, cancellationToken);

        if (result is null)
        {
            Invalid(NewFieldErrors().Email(nameof(Email), Email, "confirm.email"));
            return Page();
        }
        if (result.Succeeded) SuccessMessage = Ui.T("confirm.sent");
        else ShowError(result.Error);
        if (user is not null) ResendSeconds = await codes.SecondsUntilResendAsync(user.Id, CodePurpose.EmailConfirmation, cancellationToken);
        return Page();
    }

    private async Task<AuthUser?> PendingUserAsync(CancellationToken cancellationToken)
    {
        var pending = flow.GetPending(PendingSignIn.ConfirmEmail);
        if (pending is null) return null;
        ReturnUrl ??= pending.ReturnUrl;
        var user = await accounts.FindAsync(pending.UserId, cancellationToken);
        if (user is null) return null;
        HasPending = true;
        MaskedEmail = TwoStepModel.Mask(user.Email);
        ResendSeconds = await codes.SecondsUntilResendAsync(user.Id, CodePurpose.EmailConfirmation, cancellationToken);
        return user;
    }
}
