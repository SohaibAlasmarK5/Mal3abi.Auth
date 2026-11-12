using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Bans;

public enum BanKind
{
    Email = 1,
    Phone = 2,
}

/// <summary>
/// An email or phone that may not register again after a permanent ban (reference section 9).
/// Lifting the ban hides the row (soft delete), so it can be traced and restored.
/// </summary>
[Audited]
public sealed class BannedIdentifier : SoftDeletableEntity
{
    public BanKind Kind { get; set; }

    /// <summary>Upper-case email, or digits-only phone.</summary>
    public string Value { get; set; } = string.Empty;

    public Guid? UserId { get; set; }
    public string Reason { get; set; } = string.Empty;
}
