using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Accounts;

public sealed record RegisterAccount(
    string Name,
    string Username,
    string Email,
    string Phone,
    int Age,
    string? PhotoUrl,
    string Password,
    string Role,
    string Language);

public sealed record ProfileUpdate(string Name, string Username, string Phone, int Age, string? PhotoUrl);

public sealed record AccountInvitation(string Name, string Username, string Email, string Phone, int Age, string? PhotoUrl, string Language = "ar");

/// <summary>
/// The account as Mal3abi.BE and the website see it. The first ten fields keep the shape BE
/// already reads (AuthCenterAccount); the rest are additions.
/// </summary>
public sealed record AccountSummary(
    Guid Id,
    string Name,
    string Username,
    string Email,
    string Phone,
    int? Age,
    string? PhotoUrl,
    string Role,
    bool EmailConfirmed,
    bool TwoFactorEnabled,
    string TwoFactorMethod,
    string Status,
    DateTimeOffset? SuspendedUntil,
    string? StatusReason,
    int WarningCount,
    bool IsDeleted,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSignInAt);

public sealed record AccountQuery(string? Role = null, string? Search = null, string? Status = null, bool IncludeDeleted = false, int Page = 1, int PageSize = 25);

/// <summary>What sign-in needs next after the password was checked.</summary>
public sealed record SignInCheck(AuthUser User, bool NeedsEmailConfirmation, TwoFactorMethod TwoFactor);

public sealed record AuthenticatorSetup(string SharedKey, string AuthenticatorUri);

public sealed record StatusChange(string Reason, DateTimeOffset? Until = null);

public interface IAccountService
{
    Task<Result<AuthUser>> RegisterAsync(RegisterAccount request, CancellationToken cancellationToken = default);

    /// <summary>Sends a confirmation code to an unconfirmed account. Unknown emails succeed silently.</summary>
    Task<Result> SendConfirmationCodeAsync(string email, CancellationToken cancellationToken = default);
    Task<Result> SendConfirmationCodeAsync(AuthUser user, CancellationToken cancellationToken = default);
    Task<Result<AuthUser>> ConfirmEmailAsync(string email, string code, CancellationToken cancellationToken = default);
    Task<Result<AuthUser>> ConfirmEmailAsync(Guid userId, string code, CancellationToken cancellationToken = default);

    /// <summary>Checks the password, lockout and account status. Does not sign in.</summary>
    Task<Result<SignInCheck>> CheckSignInAsync(string identifier, string password, CancellationToken cancellationToken = default);

    /// <summary>Status check used on every token request: suspended, banned or deleted accounts fail.</summary>
    Task<Result<AuthUser>> EnsureCanSignInAsync(Guid userId, CancellationToken cancellationToken = default);
    Task RecordSignInAsync(AuthUser user, string method, CancellationToken cancellationToken = default);

    Task<AuthUser?> FindAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<AccountSummary?> GetSummaryAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<Result<AccountSummary>> UpdateProfileAsync(Guid userId, ProfileUpdate request, CancellationToken cancellationToken = default);
    Task<Result> SetLanguageAsync(Guid userId, string language, CancellationToken cancellationToken = default);

    Task<Result> StartEmailChangeAsync(Guid userId, string newEmail, CancellationToken cancellationToken = default);
    Task<Result<AccountSummary>> ConfirmEmailChangeAsync(Guid userId, string code, CancellationToken cancellationToken = default);
    Task<Result> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, CancellationToken cancellationToken = default);

    /// <summary>Sends a reset link to a confirmed account. Unknown emails succeed silently.</summary>
    Task<Result> SendPasswordResetAsync(string email, string resetPageUrl, CancellationToken cancellationToken = default);
    Task<Result> ResetPasswordAsync(Guid userId, string token, string newPassword, CancellationToken cancellationToken = default);

    Task<Result<AccountSummary>> InviteAsync(AccountInvitation request, string role, string acceptPageUrl, CancellationToken cancellationToken = default);
    Task<Result<AuthUser>> AcceptInvitationAsync(Guid userId, string token, string password, CancellationToken cancellationToken = default);

    /// <summary>The user hides their own account (soft delete).</summary>
    Task<Result> DeleteOwnAccountAsync(Guid userId, string password, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetRolesAsync(AuthUser user);
}

public interface ITwoFactorService
{
    /// <summary>Sends the email two-step code (owners, and players who turned it on).</summary>
    Task<Result> SendEmailCodeAsync(AuthUser user, CancellationToken cancellationToken = default);

    /// <summary>Checks an email or authenticator code, by the user's method. Wrong codes count toward lockout.</summary>
    Task<Result> VerifyAsync(AuthUser user, string code, CancellationToken cancellationToken = default);

    Task<AuthenticatorSetup> GetAuthenticatorSetupAsync(AuthUser user, string issuer);
    Task<Result> EnableAuthenticatorAsync(AuthUser user, string code, CancellationToken cancellationToken = default);

    /// <summary>Players may turn email two-step on or off. Owners and admins cannot turn it off.</summary>
    Task<Result> SetEmailTwoFactorAsync(AuthUser user, bool enabled, CancellationToken cancellationToken = default);

    /// <summary>The method a user must use, by role: admins the app, owners email, players their choice.</summary>
    Task<TwoFactorMethod> RequiredMethodAsync(AuthUser user);
}

public interface IAccountAdminService
{
    Task<PagedResult<AccountSummary>> ListAsync(AccountQuery query, CancellationToken cancellationToken = default);
    Task<AccountSummary?> GetAsync(Guid userId, bool includeDeleted = false, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AccountSummary>> GetManyAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AccountSummary>> ListSuperAdminsAsync(CancellationToken cancellationToken = default);

    Task<Result<AccountSummary>> WarnAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default);
    Task<Result<AccountSummary>> SuspendAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default);
    Task<Result<AccountSummary>> BanAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default);
    Task<Result<AccountSummary>> ReinstateAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default);
    Task<Result> SoftDeleteAsync(Guid userId, string reason, CancellationToken cancellationToken = default);
    Task<Result<AccountSummary>> RestoreAsync(Guid userId, CancellationToken cancellationToken = default);
}
