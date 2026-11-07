using System.ComponentModel.DataAnnotations;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages.Account;

public sealed class RegisterModel(IAuthAccountService accounts, IConfiguration configuration) : PageModel
{
    [BindProperty] public RegisterInput Input { get; set; } = new();
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    public string? Message { get; private set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return Page();
        var result = await accounts.RegisterPlayerAsync(
            new PlayerRegistration(Input.Name, Input.Username, Input.Email, Input.Phone, Input.Age, Input.PhotoUrl, Input.Password),
            configuration["Authentication:PublicOrigin"] ?? "https://localhost:44493",
            !string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : null,
            cancellationToken);
        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Could not create the account.");
            return Page();
        }
        Message = "تحقق من بريدك الإلكتروني واضغط على رابط التأكيد لتفعيل الحساب.";
        ModelState.Clear();
        Input = new();
        return Page();
    }

    public sealed class RegisterInput
    {
        [Required, MaxLength(120)] public string Name { get; set; } = string.Empty;
        [Required, MinLength(3), MaxLength(32), RegularExpression("^[A-Za-z0-9_.-]+$")] public string Username { get; set; } = string.Empty;
        [Required, EmailAddress, MaxLength(256)] public string Email { get; set; } = string.Empty;
        [Required, Phone, MaxLength(32)] public string Phone { get; set; } = string.Empty;
        [Range(13, 120)] public int Age { get; set; }
        [Url, MaxLength(2048)] public string? PhotoUrl { get; set; }
        [Required, MinLength(8), MaxLength(128)] public string Password { get; set; } = string.Empty;
    }
}
