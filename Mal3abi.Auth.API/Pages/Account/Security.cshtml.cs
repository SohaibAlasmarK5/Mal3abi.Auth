using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class SecurityModel(IAccountService accounts, ITwoFactorService twoFactor, SignInFlow flow, IConfiguration configuration) : AuthPageModel
{
    [BindProperty]
    public string Code { get; set; } = "";

    public string Kind { get; private set; } = "player";
    public bool AuthenticatorOn { get; private set; }
    public bool EmailOn { get; private set; }
    public AuthenticatorSetup? Setup { get; private set; }
    public string? ContinueUrl { get; private set; }

    public async Task<IActionResult> OnGetAsync() => await LoadAsync() is null ? SignInAgain() : Page();

    public async Task<IActionResult> OnPostAuthenticatorAsync(CancellationToken cancellationToken)
    {
        var user = await LoadAsync();
        if (user is null) return SignInAgain();
        if (Kind != "admin") return Page();

        var enabled = await twoFactor.EnableAuthenticatorAsync(user, Code, cancellationToken);
        if (!enabled.Succeeded)
        {
            ShowError(enabled.Error);
            return Page();
        }

        await flow.CompleteAsync(user, rememberMe: false, withTwoFactor: true);
        var returnUrl = SignInFlow.SafeReturnUrl(ReturnUrl);
        if (returnUrl is not null) return Redirect(returnUrl);

        await LoadAsync();
        SuccessMessage = Ui.T("security.saved");
        return Page();
    }

    public async Task<IActionResult> OnPostEmailAsync(bool enabled, CancellationToken cancellationToken)
    {
        var user = await LoadAsync();
        if (user is null) return SignInAgain();
        var result = await twoFactor.SetEmailTwoFactorAsync(user, enabled, cancellationToken);
        if (result.Succeeded) SuccessMessage = Ui.T("security.saved");
        else ShowError(result.Error);
        await LoadAsync();
        return Page();
    }

    private async Task<AuthUser?> LoadAsync()
    {
        if (User.GetUserId() is not { } id) return null;
        var user = await accounts.FindAsync(id);
        if (user is null) return null;

        var method = await twoFactor.RequiredMethodAsync(user);
        var roles = await accounts.GetRolesAsync(user);
        Kind = roles.Contains(AuthRoles.SuperAdmin) ? "admin" : roles.Contains(AuthRoles.Owner) ? "owner" : "player";
        AuthenticatorOn = user.TwoFactorMethod == TwoFactorMethod.Authenticator;
        EmailOn = method == TwoFactorMethod.Email;
        if (Kind == "admin" && !AuthenticatorOn)
            Setup = await twoFactor.GetAuthenticatorSetupAsync(user, configuration["Authentication:AuthenticatorIssuer"] ?? "Mal3abi");
        if (Kind != "admin" || AuthenticatorOn) ContinueUrl = SignInFlow.SafeReturnUrl(ReturnUrl);
        return user;
    }

    private IActionResult SignInAgain() => RedirectToPage("/Account/Login", new { returnUrl = Request.Path + Request.QueryString, error = ErrorCodes.Unauthorized });
}
