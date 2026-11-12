using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Bans;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace Mal3abi.Auth.Core.Services;

public sealed class AccountService(
    UserManager<AuthUser> users,
    SignInManager<AuthUser> signIn,
    IAccountRepository accounts,
    IRepository<BannedIdentifier> bans,
    IVerificationCodeService codes,
    IAuditService audit,
    AuditLabel label,
    IEmailSender email,
    TimeProvider time) : IAccountService
{
    public async Task<Result<AuthUser>> RegisterAsync(RegisterAccount request, CancellationToken cancellationToken = default)
    {
        var role = AuthRoles.FromPublic(request.Role) ?? AuthRoles.Player;
        if (role == AuthRoles.SuperAdmin) return new Error(ErrorCodes.NotAllowed);

        var emailAddress = request.Email.Trim();
        var phone = PhoneNumbers.Normalize(request.Phone);
        var check = await CheckAvailableAsync(emailAddress, request.Username.Trim(), phone, null, cancellationToken);
        if (!check.Succeeded) return check.Error!;

        var user = new AuthUser
        {
            UserName = request.Username.Trim(),
            Email = emailAddress,
            PhoneNumber = request.Phone.Trim(),
            NormalizedPhone = phone,
            FullName = request.Name.Trim(),
            Age = request.Age,
            PhotoUrl = string.IsNullOrWhiteSpace(request.PhotoUrl) ? null : request.PhotoUrl.Trim(),
            PreferredLanguage = AccountMapping.NormalizeLanguage(request.Language),
            TwoFactorMethod = role == AuthRoles.Owner ? TwoFactorMethod.Email : TwoFactorMethod.None,
            TwoFactorEnabled = role == AuthRoles.Owner,
        };

        var created = await users.CreateAsync(user, request.Password);
        if (!created.Succeeded) return created.ToError();

        var roleResult = await users.AddToRoleAsync(user, role);
        if (!roleResult.Succeeded)
        {
            await HardDeleteAsync(user);
            return roleResult.ToError();
        }

        try { await SendConfirmationCodeAsync(user, cancellationToken); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { }
        return user;
    }

    public async Task<Result> SendConfirmationCodeAsync(string emailAddress, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByEmailAsync(emailAddress.Trim());
        return user is null ? Result.Success() : await SendConfirmationCodeAsync(user, cancellationToken);
    }

    public async Task<Result> SendConfirmationCodeAsync(AuthUser user, CancellationToken cancellationToken = default)
    {
        if (user.EmailConfirmed || string.IsNullOrWhiteSpace(user.Email)) return Result.Success();
        var issued = await codes.IssueAsync(user, CodePurpose.EmailConfirmation, user.Email, cancellationToken);
        return issued.Succeeded ? Result.Success() : issued.Error!;
    }

    public async Task<Result<AuthUser>> ConfirmEmailAsync(string emailAddress, string code, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByEmailAsync(emailAddress.Trim());
        return user is null ? new Error(ErrorCodes.CodeExpired) : await ConfirmAsync(user, code, cancellationToken);
    }

    public async Task<Result<AuthUser>> ConfirmEmailAsync(Guid userId, string code, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        return user is null ? new Error(ErrorCodes.CodeExpired) : await ConfirmAsync(user, code, cancellationToken);
    }

    private async Task<Result<AuthUser>> ConfirmAsync(AuthUser user, string code, CancellationToken cancellationToken)
    {
        if (user.EmailConfirmed) return user;
        var verified = await codes.VerifyAsync(user.Id, CodePurpose.EmailConfirmation, code, cancellationToken);
        if (!verified.Succeeded) return verified.Error!;

        user.EmailConfirmed = true;
        label.Set(AuditActions.EmailConfirmed);
        var updated = await users.UpdateAsync(user);
        return updated.Succeeded ? user : updated.ToError();
    }

    public async Task<Result<SignInCheck>> CheckSignInAsync(string identifier, string password, CancellationToken cancellationToken = default)
    {
        identifier = identifier.Trim();
        var user = identifier.Contains('@')
            ? await users.FindByEmailAsync(identifier) ?? await users.FindByNameAsync(identifier)
            : await users.FindByNameAsync(identifier) ?? await users.FindByEmailAsync(identifier);
        if (user is null)
        {
            await audit.RecordAsync(AuditActions.SignInFailed, "AuthUser", null, note: "unknown account", cancellationToken: cancellationToken);
            return new Error(ErrorCodes.InvalidCredentials);
        }

        var password_ = await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        if (password_.IsLockedOut)
        {
            await audit.RecordAsync(AuditActions.SignInBlocked, "AuthUser", user.Id.ToString(), note: "locked out", cancellationToken: cancellationToken);
            return new Error(ErrorCodes.LockedOut, Until: user.LockoutEnd);
        }
        if (!password_.Succeeded)
        {
            await audit.RecordAsync(AuditActions.SignInFailed, "AuthUser", user.Id.ToString(), note: "wrong password", cancellationToken: cancellationToken);
            return new Error(ErrorCodes.InvalidCredentials);
        }

        var status = await StatusErrorAsync(user);
        if (status is not null)
        {
            await audit.RecordAsync(AuditActions.SignInBlocked, "AuthUser", user.Id.ToString(), note: user.Status.ToString(), cancellationToken: cancellationToken);
            return status;
        }

        var method = await RequiredTwoFactorAsync(user);
        return new SignInCheck(user, !user.EmailConfirmed, method);
    }

    public async Task<Result<AuthUser>> EnsureCanSignInAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.Unauthorized);
        if (!user.EmailConfirmed) return new Error(ErrorCodes.EmailNotVerified);
        var status = await StatusErrorAsync(user);
        return status is null ? user : status;
    }

    public async Task RecordSignInAsync(AuthUser user, string method, CancellationToken cancellationToken = default)
    {
        user.LastSignInAt = time.GetUtcNow();
        await users.UpdateAsync(user);
        await audit.RecordAsync(AuditActions.SignIn, "AuthUser", user.Id.ToString(), note: method, cancellationToken: cancellationToken);
    }

    public async Task<AuthUser?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await users.FindByIdAsync(userId.ToString());

    public async Task<AccountSummary?> GetSummaryAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        return user is null ? null : user.ToSummary(await users.GetRolesAsync(user));
    }

    public async Task<Result<AccountSummary>> UpdateProfileAsync(Guid userId, ProfileUpdate request, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.NotFound);

        var username = request.Username.Trim();
        var phone = PhoneNumbers.Normalize(request.Phone);
        var usernameChanged = !string.Equals(user.UserName, username, StringComparison.OrdinalIgnoreCase);
        var phoneChanged = phone != user.NormalizedPhone;
        var check = await CheckAvailableAsync(null, usernameChanged ? username : null, phoneChanged ? phone : null, user.Id, cancellationToken);
        if (!check.Succeeded) return check.Error!;

        user.FullName = request.Name.Trim();
        user.UserName = username;
        user.PhoneNumber = request.Phone.Trim();
        user.NormalizedPhone = phone;
        user.Age = request.Age;
        user.PhotoUrl = string.IsNullOrWhiteSpace(request.PhotoUrl) ? null : request.PhotoUrl.Trim();
        var updated = await users.UpdateAsync(user);
        return updated.Succeeded ? user.ToSummary(await users.GetRolesAsync(user)) : updated.ToError();
    }

    public async Task<Result> SetLanguageAsync(Guid userId, string language, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.NotFound);
        var value = AccountMapping.NormalizeLanguage(language);
        if (user.PreferredLanguage == value) return Result.Success();
        user.PreferredLanguage = value;
        var updated = await users.UpdateAsync(user);
        return updated.Succeeded ? Result.Success() : updated.ToError();
    }

    public async Task<Result> StartEmailChangeAsync(Guid userId, string newEmail, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.NotFound);
        newEmail = newEmail.Trim();
        if (string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase)) return new Error(ErrorCodes.EmailTaken);
        var check = await CheckAvailableAsync(newEmail, null, null, user.Id, cancellationToken);
        if (!check.Succeeded) return check.Error!;
        var issued = await codes.IssueAsync(user, CodePurpose.EmailChange, newEmail, cancellationToken);
        return issued.Succeeded ? Result.Success() : issued.Error!;
    }

    public async Task<Result<AccountSummary>> ConfirmEmailChangeAsync(Guid userId, string code, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.NotFound);
        var verified = await codes.VerifyAsync(user.Id, CodePurpose.EmailChange, code, cancellationToken);
        if (!verified.Succeeded) return verified.Error!;

        var newEmail = verified.Value;
        var check = await CheckAvailableAsync(newEmail, null, null, user.Id, cancellationToken);
        if (!check.Succeeded) return check.Error!;

        user.Email = newEmail;
        user.EmailConfirmed = true;
        label.Set(AuditActions.EmailChanged);
        var updated = await users.UpdateAsync(user);
        if (!updated.Succeeded) return updated.ToError();
        await users.UpdateSecurityStampAsync(user);
        return user.ToSummary(await users.GetRolesAsync(user));
    }

    public async Task<Result> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.NotFound);
        label.Set(AuditActions.PasswordChanged);
        var changed = await users.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!changed.Succeeded) label.Clear();
        return changed.Succeeded ? Result.Success() : changed.ToError();
    }

    public async Task<Result> SendPasswordResetAsync(string emailAddress, string resetPageUrl, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByEmailAsync(emailAddress.Trim());
        if (user is null || !user.EmailConfirmed || user.Status == AccountStatus.Banned) return Result.Success();

        var token = await users.GeneratePasswordResetTokenAsync(user);
        var link = QueryHelpers.AddQueryString(resetPageUrl, new Dictionary<string, string?>
        {
            ["userId"] = user.Id.ToString(),
            ["token"] = Encode(token),
            ["lang"] = user.PreferredLanguage,
        });
        var message = AuthEmails.PasswordReset(user.PreferredLanguage, user.FullName, link);
        await email.SendAsync(user.Email!, message.Subject, message.Html, cancellationToken);
        return Result.Success();
    }

    public async Task<Result> ResetPasswordAsync(Guid userId, string token, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        var decoded = Decode(token);
        if (user is null || decoded is null) return new Error(ErrorCodes.ResetInvalid);

        label.Set(AuditActions.PasswordReset);
        var reset = await users.ResetPasswordAsync(user, decoded, newPassword);
        if (!reset.Succeeded)
        {
            label.Clear();
            return reset.ToError();
        }
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        return Result.Success();
    }

    public async Task<Result<AccountSummary>> InviteAsync(AccountInvitation request, string role, string acceptPageUrl, CancellationToken cancellationToken = default)
    {
        if (role is not (AuthRoles.Owner or AuthRoles.SuperAdmin)) return new Error(ErrorCodes.NotAllowed);
        var emailAddress = request.Email.Trim();
        var phone = PhoneNumbers.Normalize(request.Phone);
        var check = await CheckAvailableAsync(emailAddress, request.Username.Trim(), phone, null, cancellationToken);
        if (!check.Succeeded) return check.Error!;

        var user = new AuthUser
        {
            UserName = request.Username.Trim(),
            Email = emailAddress,
            PhoneNumber = request.Phone.Trim(),
            NormalizedPhone = phone,
            FullName = request.Name.Trim(),
            Age = request.Age,
            PhotoUrl = string.IsNullOrWhiteSpace(request.PhotoUrl) ? null : request.PhotoUrl.Trim(),
            PreferredLanguage = AccountMapping.NormalizeLanguage(request.Language),
            IsInvited = true,
            TwoFactorMethod = role == AuthRoles.Owner ? TwoFactorMethod.Email : TwoFactorMethod.None,
            TwoFactorEnabled = role == AuthRoles.Owner,
        };

        var created = await users.CreateAsync(user);
        if (!created.Succeeded) return created.ToError();
        label.Set(AuditActions.Invited, role);
        var roleResult = await users.AddToRoleAsync(user, role);
        if (!roleResult.Succeeded)
        {
            await HardDeleteAsync(user);
            return roleResult.ToError();
        }

        var token = await users.GenerateUserTokenAsync(user, InvitationTokens.ProviderName, InvitationTokens.Purpose);
        var link = QueryHelpers.AddQueryString(acceptPageUrl, new Dictionary<string, string?>
        {
            ["userId"] = user.Id.ToString(),
            ["token"] = Encode(token),
            ["lang"] = user.PreferredLanguage,
        });
        var message = AuthEmails.Invitation(user.PreferredLanguage, user.FullName, role, link);
        await email.SendAsync(emailAddress, message.Subject, message.Html, cancellationToken);
        return user.ToSummary([role]);
    }

    public async Task<Result<AuthUser>> AcceptInvitationAsync(Guid userId, string token, string password, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        var decoded = Decode(token);
        if (user is null || decoded is null || !user.IsInvited || await users.HasPasswordAsync(user))
            return new Error(ErrorCodes.InvitationInvalid);
        if (!await users.VerifyUserTokenAsync(user, InvitationTokens.ProviderName, InvitationTokens.Purpose, decoded))
            return new Error(ErrorCodes.InvitationInvalid);

        var added = await users.AddPasswordAsync(user, password);
        if (!added.Succeeded) return added.ToError();

        user.IsInvited = false;
        label.Set(AuditActions.InvitationAccepted);
        await users.UpdateAsync(user);

        try { await SendConfirmationCodeAsync(user, cancellationToken); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested) { }
        return user;
    }

    public async Task<Result> DeleteOwnAccountAsync(Guid userId, string password, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null) return new Error(ErrorCodes.NotFound);
        if (await users.IsInRoleAsync(user, AuthRoles.SuperAdmin)) return new Error(ErrorCodes.NotAllowed);
        if (!await users.CheckPasswordAsync(user, password)) return new Error(ErrorCodes.PasswordWrong);

        await users.UpdateSecurityStampAsync(user);
        label.Set(AuditActions.Deleted, "by the account owner");
        var deleted = await users.DeleteAsync(user);
        return deleted.Succeeded ? Result.Success() : deleted.ToError();
    }

    public async Task<IReadOnlyList<string>> GetRolesAsync(AuthUser user) => [.. await users.GetRolesAsync(user)];

    private async Task<TwoFactorMethod> RequiredTwoFactorAsync(AuthUser user)
    {
        var roles = await users.GetRolesAsync(user);
        if (roles.Contains(AuthRoles.SuperAdmin)) return user.TwoFactorMethod == TwoFactorMethod.Authenticator ? TwoFactorMethod.Authenticator : TwoFactorMethod.None;
        if (roles.Contains(AuthRoles.Owner)) return TwoFactorMethod.Email;
        return user.TwoFactorMethod == TwoFactorMethod.Email ? TwoFactorMethod.Email : TwoFactorMethod.None;
    }

    private async Task<Error?> StatusErrorAsync(AuthUser user)
    {
        switch (user.Status)
        {
            case AccountStatus.Banned:
                return new Error(ErrorCodes.AccountSuspended);
            case AccountStatus.Suspended when user.SuspendedUntil is { } until && until > time.GetUtcNow():
                return new Error(ErrorCodes.AccountSuspended, Until: until);
            case AccountStatus.Suspended:
                user.Status = AccountStatus.Active;
                user.SuspendedUntil = null;
                label.Set(AuditActions.Reinstated, "suspension ended");
                await users.UpdateAsync(user);
                return null;
            default:
                return null;
        }
    }

    private async Task<Result> CheckAvailableAsync(string? emailAddress, string? username, string? normalizedPhone, Guid? exceptUserId, CancellationToken cancellationToken)
    {
        if (emailAddress is not null)
        {
            var normalized = users.NormalizeEmail(emailAddress);
            if (await bans.AnyAsync(b => b.Kind == BanKind.Email && b.Value == normalized, cancellationToken))
                return new Error(ErrorCodes.AccountBanned);
            if (await accounts.EmailInUseAsync(normalized, exceptUserId, cancellationToken))
                return new Error(ErrorCodes.EmailTaken);
        }
        if (username is not null)
        {
            var normalized = users.NormalizeName(username);
            if (await accounts.UserNameInUseAsync(normalized, exceptUserId, cancellationToken))
                return new Error(ErrorCodes.UsernameTaken);
        }
        if (normalizedPhone is not null &&
            await bans.AnyAsync(b => b.Kind == BanKind.Phone && b.Value == normalizedPhone, cancellationToken))
            return new Error(ErrorCodes.PhoneBlocked);
        return Result.Success();
    }

    private Task HardDeleteAsync(AuthUser user) => accounts.HardDeleteAsync(user.Id);

    private static string Encode(string token) => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    private static string? Decode(string token)
    {
        try { return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token)); }
        catch (FormatException) { return null; }
    }
}
