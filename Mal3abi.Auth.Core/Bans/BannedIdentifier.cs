using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Bans;

public enum BanKind
{
    Email = 1,
    Phone = 2,
}

[Audited]
public sealed class BannedIdentifier : SoftDeletableEntity
{
    public BanKind Kind { get; set; }

    public string Value { get; set; } = string.Empty;

    public Guid? UserId { get; set; }
    public string Reason { get; set; } = string.Empty;
}
