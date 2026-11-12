using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class LoginModel(IAccountService accounts, ITwoFactorService twoFactor, SignInFlow flow) : AuthPageModel
{
    [BindProperty]
    public LoginInput Input { get; set; } = new();

    public void OnGet(bool signedOut = false, string? error = null)
    {
        if (signedOut) SuccessMessage = Ui.T("login.signedOut");
        if (!string.IsNullOrEmpty(error)) ErrorMessage = Ui.Error(new Error(error));
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(Input.Identifier) || string.IsNullOrEmpty(Input.Password))
        {
            ErrorMessage = Ui.Error(new Error(ErrorCodes.InvalidCredentials));
            return Page();
        }

        var check = await accounts.CheckSignInAsync(Input.Identifier, Input.Password, cancellationToken);
        if (!check.Succeeded)
        {
            ShowError(check.Error);
            return Page();
        }

        var (user, needsConfirmation, method) = check.Value;
        await accounts.SetLanguageAsync(user.Id, Ui.Lang, cancellationToken);
        if (needsConfirmation)
        {
            await accounts.SendConfirmationCodeAsync(user, cancellationToken);
            flow.SetPending(user.Id, PendingSignIn.ConfirmEmail, Input.RememberMe, ReturnUrl);
            return RedirectToPage("/Account/ConfirmEmail", new { returnUrl = ReturnUrl });
        }

        if (method == TwoFactorMethod.None)
        {
            await flow.CompleteAsync(user, Input.RememberMe, withTwoFactor: false);
            return Redirect(flow.Destination(ReturnUrl));
        }

        if (method == TwoFactorMethod.Email) await twoFactor.SendEmailCodeAsync(user, cancellationToken);
        flow.SetPending(user.Id, PendingSignIn.TwoStep, Input.RememberMe, ReturnUrl);
        return RedirectToPage("/Account/TwoStep", new { returnUrl = ReturnUrl });
    }

    public sealed class LoginInput
    {
        public string Identifier { get; set; } = "";
        public string Password { get; set; } = "";
        public bool RememberMe { get; set; }
    }
}
