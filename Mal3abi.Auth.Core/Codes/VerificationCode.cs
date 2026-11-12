using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Codes;

public enum CodePurpose
{
    EmailConfirmation = 1,
    EmailChange = 2,
    TwoFactor = 3,
}

/// <summary>A six-digit email code. Only a hash is stored.</summary>
public sealed class VerificationCode : Entity
{
    public Guid UserId { get; set; }
    public CodePurpose Purpose { get; set; }
    public string CodeHash { get; set; } = string.Empty;

    /// <summary>The address the code was sent to (the new address for an email change).</summary>
    public string SentTo { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset? UsedAt { get; set; }

    /// <summary>Replaced by a newer code before it was used.</summary>
    public bool Superseded { get; set; }
}

public static class CodeRules
{
    public const int Digits = 6;
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    public const int MaxAttempts = 5;
    public static readonly TimeSpan ResendAfter = TimeSpan.FromMinutes(1);
    public const int MaxPerHour = 5;
    public static readonly TimeSpan UnconfirmedAccountLifetime = TimeSpan.FromDays(7);
}

public sealed record IssuedCode(string SentTo, DateTimeOffset ExpiresAt);

public interface IVerificationCodeService
{
    /// <summary>
    /// Creates a code, replaces any earlier one for the same purpose, and emails it.
    /// Fails with code_too_soon (retry after) or code_hourly_limit.
    /// </summary>
    Task<Result<IssuedCode>> IssueAsync(Accounts.AuthUser user, CodePurpose purpose, string sendTo, CancellationToken cancellationToken = default);

    /// <summary>Checks a code. Returns the address it was sent to. Fails with code_wrong, code_expired or code_attempts.</summary>
    Task<Result<string>> VerifyAsync(Guid userId, CodePurpose purpose, string code, CancellationToken cancellationToken = default);

    /// <summary>Seconds until a new code may be sent (0 when allowed now).</summary>
    Task<int> SecondsUntilResendAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default);
}
