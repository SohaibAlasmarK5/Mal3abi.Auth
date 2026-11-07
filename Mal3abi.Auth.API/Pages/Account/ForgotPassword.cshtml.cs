using System.ComponentModel.DataAnnotations;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class ForgotPasswordModel(IAuthAccountService accounts, IConfiguration configuration) : PageModel
{
    [BindProperty, Required, EmailAddress, MaxLength(256)] public string Email { get; set; } = string.Empty;
    public bool Sent { get; private set; }
    public void OnGet() { }
    public async Task OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return;
        await accounts.SendPasswordResetAsync(Email, configuration["Authentication:PublicOrigin"] ?? "https://localhost:44493", cancellationToken);
        Sent = true;
    }
}
