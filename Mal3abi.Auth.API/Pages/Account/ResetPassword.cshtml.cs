using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class ResetPasswordModel(IAccountService accounts) : AuthPageModel
{
    [BindProperty(SupportsGet = true)]
    public Guid UserId { get; set; }

    [BindProperty(SupportsGet = true)]
    public string Token { get; set; } = "";

    [BindProperty]
    public string Password { get; set; } = "";

    [BindProperty]
    public string ConfirmPassword { get; set; } = "";

    public bool Done { get; private set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var errors = NewFieldErrors()
            .Password(nameof(Password), Password, "reset.password")
            .SamePassword(nameof(ConfirmPassword), Password, ConfirmPassword);
        if (Invalid(errors)) return Page();

        var result = await accounts.ResetPasswordAsync(UserId, Token, Password, cancellationToken);
        if (result.Succeeded) Done = true;
        else ShowError(result.Error);
        return Page();
    }
}
