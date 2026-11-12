using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Pages.Account;

/// <summary>Signs out of the Auth Center only. The website signs out through BE and /connect/logout.</summary>
public sealed class LogoutModel(SignInManager<AuthUser> signInManager, SignInFlow flow) : AuthPageModel
{
    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        await signInManager.SignOutAsync();
        flow.ClearPending();
        return RedirectToPage("/Account/Login", new { signedOut = true });
    }
}
