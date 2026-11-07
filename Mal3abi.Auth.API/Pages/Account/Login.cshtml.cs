using System.ComponentModel.DataAnnotations;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class LoginModel(SignInManager<AuthUser> signInManager, UserManager<AuthUser> users) : PageModel
{
    [BindProperty]
    public LoginInput Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool RequireTwoFactor { get; set; }

    public string? ErrorMessage { get; private set; }

    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated == true && IsLocalReturnUrl()) return LocalRedirect(ReturnUrl!);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!string.IsNullOrWhiteSpace(Input.AuthenticatorCode))
        {
            ModelState.Remove("Input.Password");
            ModelState.Remove("Input.Identifier");
            if (!ModelState.IsValid) return Page();
            var twoFactor = await signInManager.TwoFactorAuthenticatorSignInAsync(Input.AuthenticatorCode, Input.RememberMe, rememberClient: Input.RememberMe);
            if (twoFactor.Succeeded) return RedirectAfterLogin();
            ErrorMessage = "رمز المصادقة غير صحيح أو انتهت صلاحيته.";
            RequireTwoFactor = true;
            return Page();
        }

        if (!ModelState.IsValid) return Page();

        var identifier = Input.Identifier.Trim();
        var user = await users.FindByEmailAsync(identifier) ?? await users.FindByNameAsync(identifier);
        if (user is null)
        {
            ErrorMessage = "اسم المستخدم أو كلمة المرور غير صحيحة.";
            return Page();
        }

        var result = await signInManager.PasswordSignInAsync(user, Input.Password, Input.RememberMe, lockoutOnFailure: true);
        if (result.Succeeded) return RedirectAfterLogin();
        if (result.RequiresTwoFactor)
        {
            RequireTwoFactor = true;
            return Page();
        }
        ErrorMessage = result.IsLockedOut
            ? "تم إيقاف تسجيل الدخول مؤقتاً. حاول مرة أخرى لاحقاً."
            : "اسم المستخدم أو كلمة المرور غير صحيحة.";
        return Page();
    }

    private IActionResult RedirectAfterLogin() => IsLocalReturnUrl() ? LocalRedirect(ReturnUrl!) : Redirect("/");
    private bool IsLocalReturnUrl() => !string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl);

    public sealed class LoginInput
    {
        [Required, MaxLength(256)] public string Identifier { get; set; } = string.Empty;
        [Required, MaxLength(128)] public string Password { get; set; } = string.Empty;
        [MaxLength(10)] public string? AuthenticatorCode { get; set; }
        public bool RememberMe { get; set; }
    }
}

