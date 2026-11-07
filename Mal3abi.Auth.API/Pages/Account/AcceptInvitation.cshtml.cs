using System.ComponentModel.DataAnnotations;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class AcceptInvitationModel(IAuthAccountService accounts) : PageModel
{
    [BindProperty(SupportsGet = true)] public Guid UserId { get; set; }
    [BindProperty(SupportsGet = true)] public string PasswordToken { get; set; } = string.Empty;
    [BindProperty(SupportsGet = true)] public string EmailToken { get; set; } = string.Empty;
    [BindProperty, Required, MinLength(8), MaxLength(128)] public string Password { get; set; } = string.Empty;
    [BindProperty, Required, Compare(nameof(Password))] public string ConfirmPassword { get; set; } = string.Empty;
    public string? Message { get; private set; }
    public bool Succeeded { get; private set; }
    public void OnGet() { }
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return Page();
        var result = await accounts.AcceptInvitationAsync(UserId, PasswordToken, EmailToken, Password, cancellationToken);
        Succeeded = result.Succeeded;
        Message = result.Succeeded ? "تم تفعيل حسابك. يمكنك تسجيل الدخول الآن." : result.Error;
        return Page();
    }
}
