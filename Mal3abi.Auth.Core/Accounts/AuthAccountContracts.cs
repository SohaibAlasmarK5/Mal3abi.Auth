namespace Mal3abi.Auth.Core.Accounts;

public sealed record PlayerRegistration(
    string Name,
    string Username,
    string Email,
    string Phone,
    int Age,
    string? PhotoUrl,
    string Password);

public sealed record ProfileUpdate(
    string Name,
    string Username,
    string Phone,
    int Age,
    string? PhotoUrl);

public sealed record AccountInvitation(
    string Name,
    string Username,
    string Email,
    string Phone,
    int Age,
    string? PhotoUrl);

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
    bool TwoFactorEnabled);

public sealed record AccountOperation(bool Succeeded, string? Error = null)
{
    public static AccountOperation Success() => new(true);
    public static AccountOperation Failure(string error) => new(false, error);
}

public interface IAuthEmailSender
{
    Task SendAsync(string email, string subject, string htmlBody, CancellationToken cancellationToken = default);
}

public interface IAuthAccountService
{
    Task<AccountOperation> RegisterPlayerAsync(PlayerRegistration request, string confirmationBaseUrl, string? returnUrl = null, CancellationToken cancellationToken = default);
    Task<AccountOperation> ConfirmEmailAsync(Guid userId, string token, CancellationToken cancellationToken = default);
    Task ResendConfirmationAsync(string email, string confirmationBaseUrl, CancellationToken cancellationToken = default);
    Task<AccountSummary?> GetProfileAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<AccountOperation> UpdateProfileAsync(Guid userId, ProfileUpdate request, CancellationToken cancellationToken = default);
    Task<AccountOperation> StartEmailChangeAsync(Guid userId, string email, string confirmationBaseUrl, CancellationToken cancellationToken = default);
    Task<AccountOperation> ConfirmEmailChangeAsync(Guid userId, string email, string token, CancellationToken cancellationToken = default);
    Task<AccountOperation> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, CancellationToken cancellationToken = default);
    Task SendPasswordResetAsync(string email, string resetBaseUrl, CancellationToken cancellationToken = default);
    Task<AccountOperation> ResetPasswordAsync(Guid userId, string token, string newPassword, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AccountSummary>> ListSuperAdminsAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AccountSummary>> ListAccountsAsync(CancellationToken cancellationToken = default);
    Task<AccountOperation> InviteOwnerAsync(AccountInvitation request, string invitationBaseUrl, CancellationToken cancellationToken = default);
    Task<AccountOperation> InviteSuperAdminAsync(AccountInvitation request, string invitationBaseUrl, CancellationToken cancellationToken = default);
    Task<AccountOperation> AcceptInvitationAsync(Guid userId, string passwordToken, string emailToken, string password, CancellationToken cancellationToken = default);
}
