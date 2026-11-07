#nullable enable

using Mal3abi.Auth.Core.Accounts;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Net;


namespace Mal3abi.Auth.Infra.Accounts;

public sealed class AuthAccountService(
    UserManager<AuthUser> users,
    IAuthEmailSender emailSender,
    ILogger<AuthAccountService> logger) : IAuthAccountService
{
    public async Task<AccountOperation> RegisterPlayerAsync(PlayerRegistration request, string confirmationBaseUrl, string? returnUrl = null, CancellationToken cancellationToken = default)
    {
        var user = new AuthUser
        {
            UserName = request.Username.Trim(),
            Email = request.Email.Trim(),
            PhoneNumber = request.Phone.Trim(),
            FullName = request.Name.Trim(),
            Age = request.Age,
            PhotoUrl = NormalizePhoto(request.PhotoUrl)
        };

        var created = await users.CreateAsync(user, request.Password);
        if (!created.Succeeded) return FromIdentity(created);

        var roleResult = await users.AddToRoleAsync(user, AuthRoles.Player);
        if (!roleResult.Succeeded)
        {
            await users.DeleteAsync(user);
            return FromIdentity(roleResult);
        }

        try
        {
            await SendEmailConfirmationAsync(user, confirmationBaseUrl, cancellationToken, returnUrl);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Confirmation email could not be sent for newly registered account {UserId}.", user.Id);
            return AccountOperation.Failure("Your account was created, but we could not send the confirmation email. Use the resend confirmation option.");
        }
        return AccountOperation.Success();
    }

    public async Task<AccountOperation> ConfirmEmailAsync(Guid userId, string token, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return AccountOperation.Failure("This confirmation link is invalid or expired.");
        var result = await users.ConfirmEmailAsync(user, token);
        return result.Succeeded ? AccountOperation.Success() : FromIdentity(result);
    }

    public async Task ResendConfirmationAsync(string email, string confirmationBaseUrl, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByEmailAsync(email.Trim());
        if (user is null || user.EmailConfirmed) return;
        await SendEmailConfirmationAsync(user, confirmationBaseUrl, cancellationToken);
    }

    public async Task<AccountSummary?> GetProfileAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        return user is null ? null : await ToSummaryAsync(user);
    }

    public async Task<AccountOperation> UpdateProfileAsync(Guid userId, ProfileUpdate request, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return AccountOperation.Failure("Account not found.");
        user.FullName = request.Name.Trim();
        user.PhoneNumber = request.Phone.Trim();
        user.Age = request.Age;
        user.PhotoUrl = NormalizePhoto(request.PhotoUrl);
        var nameResult = await users.SetUserNameAsync(user, request.Username.Trim());
        if (!nameResult.Succeeded) return FromIdentity(nameResult);
        return FromIdentity(await users.UpdateAsync(user));
    }

    public async Task<AccountOperation> StartEmailChangeAsync(Guid userId, string email, string confirmationBaseUrl, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return AccountOperation.Failure("Account not found.");
        var newEmail = email.Trim();
        var token = await users.GenerateChangeEmailTokenAsync(user, newEmail);
        var link = BuildLink(confirmationBaseUrl, "api/accounts/me/email/confirm", ("userId", user.Id.ToString()), ("email", newEmail), ("token", token));
        await emailSender.SendAsync(newEmail, "Confirm your Mal3abi email", $"<p>Confirm your new email address:</p><p><a href=\"{Html(link)}\">Confirm email</a></p>", cancellationToken);
        return AccountOperation.Success();
    }

    public async Task<AccountOperation> ConfirmEmailChangeAsync(Guid userId, string email, string token, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return AccountOperation.Failure("This confirmation link is invalid or expired.");
        var result = await users.ChangeEmailAsync(user, email.Trim(), token);
        if (!result.Succeeded) return FromIdentity(result);
        user.EmailConfirmed = true;
        return FromIdentity(await users.UpdateAsync(user));
    }

    public async Task<AccountOperation> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return AccountOperation.Failure("Account not found.");
        return FromIdentity(await users.ChangePasswordAsync(user, currentPassword, newPassword));
    }

    public async Task SendPasswordResetAsync(string email, string resetBaseUrl, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByEmailAsync(email.Trim());
        if (user is null || user.Email is null || !user.EmailConfirmed) return;
        var token = await users.GeneratePasswordResetTokenAsync(user);
        var link = BuildLink(resetBaseUrl, "account/reset-password", ("userId", user.Id.ToString()), ("token", token));
        await emailSender.SendAsync(user.Email, "Reset your Mal3abi password", $"<p>Use the link below to choose a new password:</p><p><a href=\"{Html(link)}\">Reset password</a></p>", cancellationToken);
    }

    public async Task<AccountOperation> ResetPasswordAsync(Guid userId, string token, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        return user is null ? AccountOperation.Failure("This password reset link is invalid or expired.") : FromIdentity(await users.ResetPasswordAsync(user, token, newPassword));
    }

    public async Task<IReadOnlyList<AccountSummary>> ListAccountsAsync(CancellationToken cancellationToken = default)
    {
        var rows = await users.Users.OrderBy(user => user.FullName).ToListAsync(cancellationToken);
        var summaries = new List<AccountSummary>(rows.Count);
        foreach (var user in rows) summaries.Add(await ToSummaryAsync(user));
        return summaries;
    }
    public async Task<IReadOnlyList<AccountSummary>> ListSuperAdminsAsync(CancellationToken cancellationToken = default)
    {
        var admins = await users.GetUsersInRoleAsync(AuthRoles.SuperAdmin);
        var rows = new List<AccountSummary>(admins.Count);
        foreach (var admin in admins) rows.Add(await ToSummaryAsync(admin));
        return rows;
    }

    public Task<AccountOperation> InviteOwnerAsync(AccountInvitation request, string invitationBaseUrl, CancellationToken cancellationToken = default) =>
        InviteAsync(request, AuthRoles.Owner, invitationBaseUrl, cancellationToken);

    public Task<AccountOperation> InviteSuperAdminAsync(AccountInvitation request, string invitationBaseUrl, CancellationToken cancellationToken = default) =>
        InviteAsync(request, AuthRoles.SuperAdmin, invitationBaseUrl, cancellationToken);

    public async Task<AccountOperation> AcceptInvitationAsync(Guid userId, string passwordToken, string emailToken, string password, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null || user.Email is null) return AccountOperation.Failure("This invitation is invalid or expired.");
        var emailResult = await users.ConfirmEmailAsync(user, emailToken);
        if (!emailResult.Succeeded) return FromIdentity(emailResult);
        return FromIdentity(await users.ResetPasswordAsync(user, passwordToken, password));
    }

    private async Task<AccountOperation> InviteAsync(AccountInvitation request, string role, string invitationBaseUrl, CancellationToken cancellationToken)
    {
        var user = new AuthUser
        {
            UserName = request.Username.Trim(),
            Email = request.Email.Trim(),
            PhoneNumber = request.Phone.Trim(),
            FullName = request.Name.Trim(),
            Age = request.Age,
            PhotoUrl = NormalizePhoto(request.PhotoUrl)
        };
        var created = await users.CreateAsync(user);
        if (!created.Succeeded) return FromIdentity(created);

        var roleResult = await users.AddToRoleAsync(user, role);
        if (!roleResult.Succeeded)
        {
            await users.DeleteAsync(user);
            return FromIdentity(roleResult);
        }

        try
        {
            var passwordToken = await users.GeneratePasswordResetTokenAsync(user);
            var emailToken = await users.GenerateEmailConfirmationTokenAsync(user);
            var link = BuildLink(invitationBaseUrl, "account/accept-invitation", ("userId", user.Id.ToString()), ("passwordToken", passwordToken), ("emailToken", emailToken));
            await emailSender.SendAsync(user.Email!, "Your Mal3abi account invitation", $"<p>Set your password and confirm your email to activate your {WebUtility.HtmlEncode(role)} account:</p><p><a href=\"{Html(link)}\">Accept invitation</a></p>", cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Invitation email could not be sent for account {UserId}.", user.Id);
            return AccountOperation.Failure("The account was created, but we could not send the invitation email. Try the invitation again after configuring email delivery.");
        }
        return AccountOperation.Success();
    }

    private async Task SendEmailConfirmationAsync(AuthUser user, string baseUrl, CancellationToken cancellationToken, string? returnUrl = null)
    {
        var token = await users.GenerateEmailConfirmationTokenAsync(user);
        var query = new List<(string Key, string Value)> { ("userId", user.Id.ToString()), ("token", token) };
        if (!string.IsNullOrWhiteSpace(returnUrl)) query.Add(("returnUrl", returnUrl));
        var link = BuildLink(baseUrl, "account/confirm-email", query.ToArray());
        await emailSender.SendAsync(user.Email!, "Confirm your Mal3abi account", $"<p>Confirm your email address:</p><p><a href=\"{Html(link)}\">Confirm email</a></p>", cancellationToken);
    }

    private async Task<AccountSummary> ToSummaryAsync(AuthUser user)
    {
        var roles = await users.GetRolesAsync(user);
        var role = roles.Contains(AuthRoles.SuperAdmin) ? "superadmin" : roles.Contains(AuthRoles.Owner) || roles.Contains(AuthRoles.Admin) ? "owner" : "player";
        return new AccountSummary(user.Id, user.FullName, user.UserName ?? "", user.Email ?? "", user.PhoneNumber ?? "", user.Age, user.PhotoUrl, role, user.EmailConfirmed, user.TwoFactorEnabled);
    }

    private static AccountOperation FromIdentity(IdentityResult result) => result.Succeeded
        ? AccountOperation.Success()
        : AccountOperation.Failure(string.Join(" ", result.Errors.Select(error => error.Description)));

    private static string? NormalizePhoto(string? photoUrl) => string.IsNullOrWhiteSpace(photoUrl) ? null : photoUrl.Trim();
    private static string Html(string value) => WebUtility.HtmlEncode(value);
    private static string BuildLink(string baseUrl, string path, params (string Key, string Value)[] query)
    {
        var parameters = string.Join("&", query.Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        return $"{baseUrl.TrimEnd('/')}/{path}?{parameters}";
    }
}

