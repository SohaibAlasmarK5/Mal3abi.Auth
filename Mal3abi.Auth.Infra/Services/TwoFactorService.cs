using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.Infra.Services;

/// <summary>
/// Two-step verification by role (reference section 16): an authenticator app for admins, an
/// email code for court owners, and an optional email code for players.
/// </summary>
public sealed class TwoFactorService(
    UserManager<AuthUser> users,
    IVerificationCodeService codes,
    IAuditService audit,
    AuditLabel label) : ITwoFactorService
{
    public async Task<Result> SendEmailCodeAsync(AuthUser user, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(user.Email)) return new Error(ErrorCodes.NotAllowed);
        var issued = await codes.IssueAsync(user, CodePurpose.TwoFactor, user.Email, cancellationToken);
        return issued.Succeeded ? Result.Success() : issued.Error!;
    }

    public async Task<Result> VerifyAsync(AuthUser user, string code, CancellationToken cancellationToken = default)
    {
        var method = await RequiredMethodAsync(user);
        if (method == TwoFactorMethod.Email)
        {
            var verified = await codes.VerifyAsync(user.Id, CodePurpose.TwoFactor, code, cancellationToken);
            if (verified.Succeeded) return Result.Success();
            await audit.RecordAsync(AuditActions.TwoFactorFailed, "AuthUser", user.Id.ToString(), note: verified.Error!.Code, cancellationToken: cancellationToken);
            return verified.Error;
        }

        if (method == TwoFactorMethod.Authenticator)
        {
            if (await users.IsLockedOutAsync(user)) return new Error(ErrorCodes.TwoFactorLocked, Until: user.LockoutEnd);
            var digits = VerificationCodeService.NormalizeDigits(code);
            if (await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, digits))
            {
                await users.ResetAccessFailedCountAsync(user);
                return Result.Success();
            }
            await users.AccessFailedAsync(user);
            await audit.RecordAsync(AuditActions.TwoFactorFailed, "AuthUser", user.Id.ToString(), note: "authenticator", cancellationToken: cancellationToken);
            return await users.IsLockedOutAsync(user)
                ? new Error(ErrorCodes.TwoFactorLocked, Until: user.LockoutEnd)
                : new Error(ErrorCodes.CodeWrong);
        }

        return Result.Success();
    }

    public async Task<AuthenticatorSetup> GetAuthenticatorSetupAsync(AuthUser user, string issuer)
    {
        var key = await users.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await users.ResetAuthenticatorKeyAsync(user);
            key = await users.GetAuthenticatorKeyAsync(user) ?? string.Empty;
        }
        var account = Uri.EscapeDataString(user.Email ?? user.UserName ?? "account");
        var issuerText = Uri.EscapeDataString(issuer);
        var uri = $"otpauth://totp/{issuerText}:{account}?secret={key}&issuer={issuerText}&digits=6";
        return new AuthenticatorSetup(FormatKey(key), uri);
    }

    public async Task<Result> EnableAuthenticatorAsync(AuthUser user, string code, CancellationToken cancellationToken = default)
    {
        var digits = VerificationCodeService.NormalizeDigits(code);
        if (!await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, digits))
            return new Error(ErrorCodes.CodeWrong);

        user.TwoFactorMethod = TwoFactorMethod.Authenticator;
        user.TwoFactorEnabled = true;
        label.Set(AuditActions.TwoFactorEnabled, "authenticator");
        var updated = await users.UpdateAsync(user);
        return updated.Succeeded ? Result.Success() : updated.ToError();
    }

    public async Task<Result> SetEmailTwoFactorAsync(AuthUser user, bool enabled, CancellationToken cancellationToken = default)
    {
        var roles = await users.GetRolesAsync(user);
        if (roles.Contains(AuthRoles.SuperAdmin) || roles.Contains(AuthRoles.Owner)) return new Error(ErrorCodes.NotAllowed);
        if (!user.EmailConfirmed) return new Error(ErrorCodes.EmailNotVerified);

        var method = enabled ? TwoFactorMethod.Email : TwoFactorMethod.None;
        if (user.TwoFactorMethod == method) return Result.Success();
        user.TwoFactorMethod = method;
        user.TwoFactorEnabled = enabled;
        label.Set(enabled ? AuditActions.TwoFactorEnabled : AuditActions.TwoFactorDisabled, "email");
        var updated = await users.UpdateAsync(user);
        return updated.Succeeded ? Result.Success() : updated.ToError();
    }

    public async Task<TwoFactorMethod> RequiredMethodAsync(AuthUser user)
    {
        var roles = await users.GetRolesAsync(user);
        if (roles.Contains(AuthRoles.SuperAdmin)) return TwoFactorMethod.Authenticator;
        if (roles.Contains(AuthRoles.Owner)) return TwoFactorMethod.Email;
        return user.TwoFactorMethod == TwoFactorMethod.Email ? TwoFactorMethod.Email : TwoFactorMethod.None;
    }

    private static string FormatKey(string key)
    {
        var chunks = Enumerable.Range(0, (key.Length + 3) / 4).Select(i => key.Substring(i * 4, Math.Min(4, key.Length - i * 4)));
        return string.Join(' ', chunks).ToLowerInvariant();
    }
}
