using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.Core.Accounts;

[Audited]
public sealed class AuthUser : IdentityUser<Guid>, IEntity, IAuditable, ISoftDeletable
{
    public AuthUser() => Id = Guid.CreateVersion7();

    public string FullName { get; set; } = string.Empty;
    public int? Age { get; set; }
    public string? PhotoUrl { get; set; }

    public string? NormalizedPhone { get; set; }

    public string PreferredLanguage { get; set; } = "ar";

    public TwoFactorMethod TwoFactorMethod { get; set; } = TwoFactorMethod.None;

    public AccountStatus Status { get; set; } = AccountStatus.Active;
    public DateTimeOffset? SuspendedUntil { get; set; }
    public string? StatusReason { get; set; }
    public int WarningCount { get; set; }

    public bool IsInvited { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
    public DateTimeOffset? LastSignInAt { get; set; }
}

public enum TwoFactorMethod
{
    None = 0,
    Email = 1,
    Authenticator = 2,
}

public enum AccountStatus
{
    Active = 0,
    Suspended = 1,
    Banned = 2,
}

public static class AuthRoles
{
    public const string Player = "Player";
    public const string Owner = "Owner";
    public const string SuperAdmin = "SuperAdmin";

    public static readonly string[] All = [Player, Owner, SuperAdmin];

    public static string ToPublic(IEnumerable<string> roles)
    {
        var list = roles.ToList();
        if (list.Contains(SuperAdmin, StringComparer.OrdinalIgnoreCase)) return "superadmin";
        if (list.Contains(Owner, StringComparer.OrdinalIgnoreCase)) return "owner";
        return "player";
    }

    public static string? FromPublic(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "player" => Player,
        "owner" => Owner,
        "superadmin" => SuperAdmin,
        _ => null,
    };
}

public static class PhoneNumbers
{
    public static string? Normalize(string? phone)
    {
        if (string.IsNullOrWhiteSpace(phone)) return null;
        var digits = new string(phone.Where(char.IsAsciiDigit).ToArray());
        if (digits.StartsWith("00", StringComparison.Ordinal)) digits = digits[2..];
        if (digits.Length == 10 && digits.StartsWith('0')) digits = "962" + digits[1..];
        return digits.Length == 0 ? null : digits;
    }
}
