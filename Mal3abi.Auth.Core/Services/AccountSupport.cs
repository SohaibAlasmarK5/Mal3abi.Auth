using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.Core.Services;

public sealed class AuditLabel
{
    public string? Action { get; private set; }
    public string? Note { get; private set; }

    public void Set(string action, string? note = null)
    {
        Action = action;
        Note = note;
    }

    public void Clear()
    {
        Action = null;
        Note = null;
    }
}

public static class InvitationTokens
{
    public const string ProviderName = "Invitation";
    public const string Purpose = "accept-invitation";
}

public static class AccountMapping
{
    public static AccountSummary ToSummary(this AuthUser user, IEnumerable<string> roles) => new(
        user.Id,
        user.FullName,
        user.UserName ?? string.Empty,
        user.Email ?? string.Empty,
        user.PhoneNumber ?? string.Empty,
        user.Age,
        user.PhotoUrl,
        AuthRoles.ToPublic(roles),
        user.EmailConfirmed,
        user.TwoFactorMethod != TwoFactorMethod.None,
        user.TwoFactorMethod.ToString().ToLowerInvariant(),
        user.Status.ToString().ToLowerInvariant(),
        user.SuspendedUntil,
        user.StatusReason,
        user.WarningCount,
        user.IsDeleted,
        user.CreatedAt,
        user.LastSignInAt);

    public static Error ToError(this IdentityResult result)
    {
        var codes = result.Errors.Select(e => e.Code).ToList();
        var details = result.Errors.Select(e => e.Description).ToList();
        if (codes.Contains(nameof(IdentityErrorDescriber.DuplicateEmail))) return new Error(ErrorCodes.EmailTaken, details);
        if (codes.Contains(nameof(IdentityErrorDescriber.DuplicateUserName))) return new Error(ErrorCodes.UsernameTaken, details);
        if (codes.Contains(nameof(IdentityErrorDescriber.PasswordMismatch))) return new Error(ErrorCodes.PasswordWrong);
        if (codes.Contains(nameof(IdentityErrorDescriber.InvalidToken))) return new Error(ErrorCodes.ResetInvalid);
        return new Error(ErrorCodes.ValidationFailed, details);
    }

    public static string NormalizeLanguage(string? language) => language?.Trim().ToLowerInvariant() == "en" ? "en" : "ar";
}
