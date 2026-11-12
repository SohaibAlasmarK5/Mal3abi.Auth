using Mal3abi.Auth.API.Endpoints;
using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

/// <summary>Player sign-up, and court owner self sign-up with ?as=owner (reference section 5).</summary>
public sealed class RegisterModel(IAccountService accounts, SignInFlow flow) : AuthPageModel
{
    [BindProperty(SupportsGet = true)]
    public string? As { get; set; }

    [BindProperty]
    public RegisterRequest Input { get; set; } = new();

    public bool IsOwner => string.Equals(As, "owner", StringComparison.OrdinalIgnoreCase);

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var errors = NewFieldErrors();
        Input.Validate(errors);
        if (Invalid(errors)) return Page();

        var result = await accounts.RegisterAsync(new RegisterAccount(
            Input.Name, Input.Username, Input.Email, Input.Phone, Input.Age ?? 0, Input.PhotoUrl, Input.Password,
            IsOwner ? "owner" : "player", Ui.Lang), cancellationToken);
        if (!result.Succeeded)
        {
            ShowError(result.Error);
            return Page();
        }

        // The password was just set here, so after the email code the user is signed in directly.
        flow.SetPending(result.Value.Id, PendingSignIn.ConfirmEmail, rememberMe: false, ReturnUrl);
        return RedirectToPage("/Account/ConfirmEmail", new { returnUrl = ReturnUrl });
    }
}
