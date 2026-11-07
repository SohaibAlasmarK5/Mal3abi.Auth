#nullable enable

using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Controllers;

[ApiController]
[Route("api/accounts")]
public sealed class AccountsController(
    IAuthAccountService accounts,
    UserManager<AuthUser> users,
    IAntiforgery antiforgery,
    IConfiguration configuration) : ControllerBase
{
    private Guid CurrentUserId => Guid.Parse(User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    private string PublicOrigin => configuration["Authentication:PublicOrigin"] ?? "https://localhost:44493";

    [HttpGet("csrf")]
    [AllowAnonymous]
    public IActionResult CsrfToken()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });
        return Ok(new { token = tokens.RequestToken });
    }

    [HttpPost("register")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterAccountRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.RegisterPlayerAsync(new PlayerRegistration(request.Name, request.Username, request.Email, request.Phone, request.Age, request.PhotoUrl, request.Password), PublicOrigin, null, cancellationToken);
        return result.Succeeded ? Accepted(new { message = "Check your email to confirm your Mal3abi account." }) : BadRequest(new { message = result.Error });
    }

    [HttpPost("confirmation/resend")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResendConfirmation(EmailRequest request, CancellationToken cancellationToken)
    {
        await accounts.ResendConfirmationAsync(request.Email, PublicOrigin, cancellationToken);
        return Ok(new { message = "If an account needs confirmation, an email has been sent." });
    }

    [HttpPost("password-reset")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RequestPasswordReset(EmailRequest request, CancellationToken cancellationToken)
    {
        await accounts.SendPasswordResetAsync(request.Email, PublicOrigin, cancellationToken);
        return Ok(new { message = "If a confirmed account matches that address, a reset link has been sent." });
    }

    [HttpPost("password-reset/complete")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompletePasswordReset(CompletePasswordResetRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.ResetPasswordAsync(request.UserId, request.Token, request.Password, cancellationToken);
        return result.Succeeded ? Ok(new { message = "Password updated." }) : BadRequest(new { message = result.Error });
    }

    [HttpPost("invitations/accept")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AcceptInvitation(AcceptInvitationRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.AcceptInvitationAsync(request.UserId, request.PasswordToken, request.EmailToken, request.Password, cancellationToken);
        return result.Succeeded ? Ok(new { message = "Invitation accepted. You can now sign in." }) : BadRequest(new { message = result.Error });
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Profile(CancellationToken cancellationToken)
    {
        var profile = await accounts.GetProfileAsync(CurrentUserId, cancellationToken);
        return profile is null ? NotFound() : Ok(profile);
    }

    [HttpPut("me")]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateProfile(ProfileRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.UpdateProfileAsync(CurrentUserId, new ProfileUpdate(request.Name, request.Username, request.Phone, request.Age, request.PhotoUrl), cancellationToken);
        return result.Succeeded ? NoContent() : BadRequest(new { message = result.Error });
    }

    [HttpPost("me/email")]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangeEmail(ChangeEmailRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.StartEmailChangeAsync(CurrentUserId, request.Email, PublicOrigin, cancellationToken);
        return result.Succeeded ? Accepted(new { message = "A confirmation link was sent to the new address." }) : BadRequest(new { message = result.Error });
    }

    [HttpGet("me/email/confirm")]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmailChange([FromQuery] Guid userId, [FromQuery] string email, [FromQuery] string token, CancellationToken cancellationToken)
    {
        var result = await accounts.ConfirmEmailChangeAsync(userId, email, token, cancellationToken);
        return result.Succeeded ? Content("<html lang=\"ar\" dir=\"rtl\"><meta charset=\"utf-8\"><h1>تم تحديث البريد الإلكتروني بنجاح.</h1></html>", "text/html") : BadRequest(new { message = result.Error });
    }

    [HttpPost("me/password")]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.ChangePasswordAsync(CurrentUserId, request.CurrentPassword, request.NewPassword, cancellationToken);
        return result.Succeeded ? NoContent() : BadRequest(new { message = result.Error });
    }

    [HttpGet("super-admins")]
    [Authorize(Roles = "SuperAdmin,superadmin")]
    public async Task<IActionResult> SuperAdmins(CancellationToken cancellationToken) => Ok(await accounts.ListSuperAdminsAsync(cancellationToken));

    [HttpPost("owners")]
    [Authorize(Roles = "SuperAdmin,superadmin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> InviteOwner(InviteAccountRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.InviteOwnerAsync(ToInvitation(request), PublicOrigin, cancellationToken);
        return result.Succeeded ? Accepted(new { message = "Owner invitation sent." }) : BadRequest(new { message = result.Error });
    }

    [HttpPost("super-admins")]
    [Authorize(Roles = "SuperAdmin,superadmin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> InviteSuperAdmin(InviteAccountRequest request, CancellationToken cancellationToken)
    {
        var result = await accounts.InviteSuperAdminAsync(ToInvitation(request), PublicOrigin, cancellationToken);
        return result.Succeeded ? Accepted(new { message = "Super-admin invitation sent." }) : BadRequest(new { message = result.Error });
    }

    [HttpGet("me/two-factor/setup")]
    [Authorize(Roles = "SuperAdmin,superadmin")]
    public async Task<IActionResult> BeginTwoFactorSetup()
    {
        var user = await users.FindByIdAsync(CurrentUserId.ToString());
        if (user is null || string.IsNullOrWhiteSpace(user.Email)) return NotFound();
        var key = await users.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(key))
        {
            var reset = await users.ResetAuthenticatorKeyAsync(user);
            if (!reset.Succeeded) return BadRequest(new { message = string.Join(" ", reset.Errors.Select(e => e.Description)) });
            key = await users.GetAuthenticatorKeyAsync(user);
        }
        var issuer = "Mal3abi";
        var label = Uri.EscapeDataString($"{issuer}:{user.Email}");
        var uri = $"otpauth://totp/{label}?secret={Uri.EscapeDataString(key!)}&issuer={Uri.EscapeDataString(issuer)}&digits=6";
        return Ok(new { sharedKey = key, authenticatorUri = uri, enabled = user.TwoFactorEnabled });
    }

    [HttpPost("me/two-factor/enable")]
    [Authorize(Roles = "SuperAdmin,superadmin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableTwoFactor(AuthenticatorCodeRequest request)
    {
        var user = await users.FindByIdAsync(CurrentUserId.ToString());
        if (user is null) return NotFound();
        var valid = await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, request.Code.Replace(" ", "").Replace("-", ""));
        if (!valid) return BadRequest(new { message = "The authenticator code is invalid." });
        var result = await users.SetTwoFactorEnabledAsync(user, true);
        return result.Succeeded ? Ok(new { enabled = true }) : BadRequest(new { message = string.Join(" ", result.Errors.Select(e => e.Description)) });
    }

    private static AccountInvitation ToInvitation(InviteAccountRequest request) =>
        new(request.Name, request.Username, request.Email, request.Phone, request.Age, request.PhotoUrl);

    public sealed class RegisterAccountRequest
    {
        [Required, MaxLength(120)] public string Name { get; set; } = string.Empty;
        [Required, MinLength(3), MaxLength(32), RegularExpression("^[A-Za-z0-9_.-]+$")] public string Username { get; set; } = string.Empty;
        [Required, EmailAddress, MaxLength(256)] public string Email { get; set; } = string.Empty;
        [Required, Phone, MaxLength(32)] public string Phone { get; set; } = string.Empty;
        [Range(13, 120)] public int Age { get; set; }
        [Url, MaxLength(2048)] public string? PhotoUrl { get; set; }
        [Required, MinLength(8), MaxLength(128)] public string Password { get; set; } = string.Empty;
    }

    public sealed class ProfileRequest
    {
        [Required, MaxLength(120)] public string Name { get; set; } = string.Empty;
        [Required, MinLength(3), MaxLength(32), RegularExpression("^[A-Za-z0-9_.-]+$")] public string Username { get; set; } = string.Empty;
        [Required, Phone, MaxLength(32)] public string Phone { get; set; } = string.Empty;
        [Range(13, 120)] public int Age { get; set; }
        [Url, MaxLength(2048)] public string? PhotoUrl { get; set; }
    }

    public sealed class InviteAccountRequest
    {
        [Required, MaxLength(120)] public string Name { get; set; } = string.Empty;
        [Required, MinLength(3), MaxLength(32), RegularExpression("^[A-Za-z0-9_.-]+$")] public string Username { get; set; } = string.Empty;
        [Required, EmailAddress, MaxLength(256)] public string Email { get; set; } = string.Empty;
        [Required, Phone, MaxLength(32)] public string Phone { get; set; } = string.Empty;
        [Range(18, 120)] public int Age { get; set; }
        [Url, MaxLength(2048)] public string? PhotoUrl { get; set; }
    }

    public sealed class EmailRequest { [Required, EmailAddress, MaxLength(256)] public string Email { get; set; } = string.Empty; }
    public sealed class ChangeEmailRequest { [Required, EmailAddress, MaxLength(256)] public string Email { get; set; } = string.Empty; }
    public sealed class ChangePasswordRequest
    {
        [Required] public string CurrentPassword { get; set; } = string.Empty;
        [Required, MinLength(8), MaxLength(128)] public string NewPassword { get; set; } = string.Empty;
    }
    public sealed class CompletePasswordResetRequest
    {
        [Required] public Guid UserId { get; set; }
        [Required] public string Token { get; set; } = string.Empty;
        [Required, MinLength(8), MaxLength(128)] public string Password { get; set; } = string.Empty;
    }
    public sealed class AcceptInvitationRequest
    {
        [Required] public Guid UserId { get; set; }
        [Required] public string PasswordToken { get; set; } = string.Empty;
        [Required] public string EmailToken { get; set; } = string.Empty;
        [Required, MinLength(8), MaxLength(128)] public string Password { get; set; } = string.Empty;
    }
    public sealed class AuthenticatorCodeRequest { [Required, StringLength(10, MinimumLength = 6)] public string Code { get; set; } = string.Empty; }
}

