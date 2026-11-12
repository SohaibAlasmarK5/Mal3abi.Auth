using Mal3abi.Auth.API.Endpoints;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class ForgotPasswordModel(IAccountService accounts, IConfiguration configuration) : AuthPageModel
{
    [BindProperty]
    public string? Email { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (Invalid(NewFieldErrors().Email(nameof(Email), Email, "forgot.email"))) return Page();
        var result = await accounts.SendPasswordResetAsync(Email!, AccountEndpoints.PublicUrl(HttpContext, configuration, "/account/reset-password"), cancellationToken);
        // The same answer whether or not the account exists.
        if (result.Succeeded) SuccessMessage = Ui.T("forgot.sent");
        else ShowError(result.Error);
        return Page();
    }
}
