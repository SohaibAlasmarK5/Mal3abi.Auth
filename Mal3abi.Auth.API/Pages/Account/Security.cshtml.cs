using System.ComponentModel.DataAnnotations;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages.Account;

[Authorize(Roles = "SuperAdmin,superadmin")]
public sealed class SecurityModel(UserManager<AuthUser> users) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    [BindProperty, Required, StringLength(10, MinimumLength = 6)] public string Code { get; set; } = string.Empty;
    public string? SharedKey { get; private set; }
    public bool IsEnabled { get; private set; }
    public string? Message { get; private set; }
    public bool Success { get; private set; }

    public async Task OnGetAsync() => await LoadAsync();

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        IsEnabled = user.TwoFactorEnabled;
        if (!IsEnabled && ModelState.IsValid)
        {
            var valid = await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, Code.Replace(" ", "").Replace("-", ""));
            if (valid)
            {
                var result = await users.SetTwoFactorEnabledAsync(user, true);
                Success = result.Succeeded;
                IsEnabled = result.Succeeded;
                Message = result.Succeeded ? "تم تفعيل المصادقة الثنائية." : string.Join(" ", result.Errors.Select(e => e.Description));
                if (result.Succeeded && !string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl)) return LocalRedirect(ReturnUrl);
                if (result.Succeeded) return Page();
            }
            else Message = "رمز المصادقة غير صحيح.";
        }
        await LoadKeyAsync(user);
        return Page();
    }

    private async Task LoadAsync()
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return;
        IsEnabled = user.TwoFactorEnabled;
        if (!IsEnabled) await LoadKeyAsync(user);
    }

    private async Task LoadKeyAsync(AuthUser user)
    {
        SharedKey = await users.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(SharedKey))
        {
            var reset = await users.ResetAuthenticatorKeyAsync(user);
            if (reset.Succeeded) SharedKey = await users.GetAuthenticatorKeyAsync(user);
        }
    }
}


