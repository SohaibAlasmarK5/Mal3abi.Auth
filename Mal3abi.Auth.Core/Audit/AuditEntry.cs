using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Audit;

/// <summary>
/// Who did what, when, with the value before and after (reference section 16). Rows are only
/// added, never changed.
/// </summary>
public sealed class AuditEntry : IEntity
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public DateTimeOffset CreatedAt { get; set; }

    public Guid? ActorId { get; set; }
    public string ActorName { get; set; } = string.Empty;
    public string? IpAddress { get; set; }

    /// <summary>For example "account.updated", "account.suspended", "signin.failed".</summary>
    public string Action { get; set; } = string.Empty;

    public string EntityType { get; set; } = string.Empty;
    public string? EntityId { get; set; }

    /// <summary>JSON of the changed values before and after.</summary>
    public string? Before { get; set; }
    public string? After { get; set; }
    public string? Note { get; set; }
}

public static class AuditActions
{
    public const string SignIn = "signin.succeeded";
    public const string SignInFailed = "signin.failed";
    public const string SignInBlocked = "signin.blocked";
    public const string TwoFactorFailed = "two_factor.failed";
    public const string TwoFactorEnabled = "two_factor.enabled";
    public const string TwoFactorDisabled = "two_factor.disabled";
    public const string Registered = "account.registered";
    public const string EmailConfirmed = "account.email_confirmed";
    public const string EmailChanged = "account.email_changed";
    public const string PasswordChanged = "account.password_changed";
    public const string PasswordReset = "account.password_reset";
    public const string Invited = "account.invited";
    public const string InvitationAccepted = "account.invitation_accepted";
    public const string Warned = "account.warned";
    public const string Suspended = "account.suspended";
    public const string Banned = "account.banned";
    public const string Reinstated = "account.reinstated";
    public const string Deleted = "account.deleted";
    public const string Restored = "account.restored";
    public const string PurgedUnconfirmed = "account.purged_unconfirmed";
}

public sealed record AuditQuery(
    Guid? EntityId = null,
    Guid? ActorId = null,
    string? Action = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Page = 1,
    int PageSize = 50);

public sealed record AuditEntryView(
    Guid Id,
    DateTimeOffset CreatedAt,
    Guid? ActorId,
    string ActorName,
    string? IpAddress,
    string Action,
    string EntityType,
    string? EntityId,
    string? Before,
    string? After,
    string? Note);

public interface IAuditService
{
    /// <summary>Adds an entry and saves it at once (security events happen outside other changes).</summary>
    Task RecordAsync(string action, string entityType, string? entityId, object? before = null, object? after = null, string? note = null, CancellationToken cancellationToken = default);

    Task<PagedResult<AuditEntryView>> SearchAsync(AuditQuery query, CancellationToken cancellationToken = default);
}
