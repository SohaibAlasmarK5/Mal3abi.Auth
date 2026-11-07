using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class ConfirmEmailModel(IAuthAccountService accounts, IConfiguration configuration) : PageModel
{
    [BindProperty(SupportsGet = true)] public Guid UserId { get; set; }
    [BindProperty(SupportsGet = true)] public string Token { get; set; } = string.Empty;
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    public string Heading { get; private set; } = "تأكيد البريد الإلكتروني";
    public string Message { get; private set; } = "رابط التأكيد غير صالح أو منتهي الصلاحية.";
    public string LoginUrl => !string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl)
        ? Url.Page("/Account/Login", new { returnUrl = ReturnUrl }) ?? "/account/login"
        : configuration["Authentication:ClientLoginUrl"] ?? "/account/login";

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        if (UserId == Guid.Empty || string.IsNullOrWhiteSpace(Token)) return;
        var result = await accounts.ConfirmEmailAsync(UserId, Token, cancellationToken);
        Heading = result.Succeeded ? "تم تأكيد بريدك الإلكتروني" : "تعذر تأكيد البريد الإلكتروني";
        Message = result.Succeeded ? "تم تفعيل حسابك. يمكنك الآن تسجيل الدخول إلى ملعبي." : result.Error ?? Message;
    }
}
