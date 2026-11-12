using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

/// <summary>An invited owner or admin sets a password, then confirms the email with a code.</summary>
public sealed class AcceptInvitationModel(IAccountService accounts, SignInFlow flow) : AuthPageModel
{
    [BindProperty(SupportsGet = true)]
    public Guid UserId { get; set; }

    [BindProperty(SupportsGet = true)]
    public string Token { get; set; } = "";

    [BindProperty]
    public string Password { get; set; } = "";

    [BindProperty]
    public string ConfirmPassword { get; set; } = "";

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var errors = NewFieldErrors()
            .Password(nameof(Password), Password, "invite.password")
            .SamePassword(nameof(ConfirmPassword), Password, ConfirmPassword);
        if (Invalid(errors)) return Page();

        var result = await accounts.AcceptInvitationAsync(UserId, Token, Password, cancellationToken);
        if (!result.Succeeded)
        {
            ShowError(result.Error);
            return Page();
        }

        flow.SetPending(result.Value.Id, PendingSignIn.ConfirmEmail, rememberMe: false, returnUrl: null);
        return RedirectToPage("/Account/ConfirmEmail");
    }
}
