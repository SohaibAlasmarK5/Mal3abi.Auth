using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Codes;

public enum CodePurpose
{
    EmailConfirmation = 1,
    EmailChange = 2,
    TwoFactor = 3,
}

public sealed class VerificationCode : Entity
{
    public Guid UserId { get; set; }
    public CodePurpose Purpose { get; set; }
    public string CodeHash { get; set; } = string.Empty;

    public string SentTo { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset? UsedAt { get; set; }

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
    Task<Result<IssuedCode>> IssueAsync(Accounts.AuthUser user, CodePurpose purpose, string sendTo, CancellationToken cancellationToken = default);

    Task<Result<string>> VerifyAsync(Guid userId, CodePurpose purpose, string code, CancellationToken cancellationToken = default);

    Task<int> SecondsUntilResendAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default);
}
