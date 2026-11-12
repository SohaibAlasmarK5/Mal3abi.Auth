using System.Security.Cryptography;
using System.Text;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Core.Common;
using Microsoft.Extensions.Configuration;

namespace Mal3abi.Auth.Core.Services;

public sealed class VerificationCodeService(
    IVerificationCodeRepository codes,
    IUnitOfWork unitOfWork,
    IEmailSender email,
    IConfiguration configuration,
    TimeProvider time) : IVerificationCodeService
{
    public async Task<Result<IssuedCode>> IssueAsync(AuthUser user, CodePurpose purpose, string sendTo, CancellationToken cancellationToken = default)
    {
        var now = time.GetUtcNow();
        var recent = await codes.GetSentSinceAsync(user.Id, purpose, now.AddHours(-1), cancellationToken);

        var last = recent.FirstOrDefault();
        if (last is not null && now - last.CreatedAt < CodeRules.ResendAfter)
        {
            var wait = (int)Math.Ceiling((CodeRules.ResendAfter - (now - last.CreatedAt)).TotalSeconds);
            return new Error(ErrorCodes.CodeTooSoon, RetryAfterSeconds: Math.Max(1, wait));
        }
        if (recent.Count >= CodeRules.MaxPerHour)
        {
            var wait = (int)Math.Ceiling((recent[^1].CreatedAt.AddHours(1) - now).TotalSeconds);
            return new Error(ErrorCodes.CodeHourlyLimit, RetryAfterSeconds: Math.Max(1, wait));
        }

        foreach (var active in recent.Where(c => c.UsedAt is null && !c.Superseded)) active.Superseded = true;

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var entity = new VerificationCode
        {
            UserId = user.Id,
            Purpose = purpose,
            CodeHash = Hash(user.Id, purpose, code),
            SentTo = sendTo,
            ExpiresAt = now + CodeRules.Lifetime,
        };
        codes.Add(entity);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        var message = AuthEmails.Code(user.PreferredLanguage, purpose, user.FullName, code);
        await email.SendAsync(sendTo, message.Subject, message.Html, cancellationToken);
        return new IssuedCode(sendTo, entity.ExpiresAt);
    }

    public async Task<Result<string>> VerifyAsync(Guid userId, CodePurpose purpose, string code, CancellationToken cancellationToken = default)
    {
        var now = time.GetUtcNow();
        var current = await codes.GetCurrentAsync(userId, purpose, cancellationToken);

        if (current is null || current.UsedAt is not null || current.ExpiresAt <= now)
            return new Error(ErrorCodes.CodeExpired);
        if (current.FailedAttempts >= CodeRules.MaxAttempts)
            return new Error(ErrorCodes.CodeAttempts);

        var normalized = NormalizeDigits(code);
        var expected = Convert.FromHexString(current.CodeHash);
        var supplied = Convert.FromHexString(Hash(userId, purpose, normalized));
        if (normalized.Length != CodeRules.Digits || !CryptographicOperations.FixedTimeEquals(expected, supplied))
        {
            current.FailedAttempts++;
            await unitOfWork.SaveChangesAsync(cancellationToken);
            return new Error(current.FailedAttempts >= CodeRules.MaxAttempts ? ErrorCodes.CodeAttempts : ErrorCodes.CodeWrong);
        }

        current.UsedAt = now;
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return current.SentTo;
    }

    public async Task<int> SecondsUntilResendAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default)
    {
        var last = await codes.GetLastSentAtAsync(userId, purpose, cancellationToken);
        if (last is null) return 0;
        var wait = CodeRules.ResendAfter - (time.GetUtcNow() - last.Value);
        return wait > TimeSpan.Zero ? (int)Math.Ceiling(wait.TotalSeconds) : 0;
    }

    public static string NormalizeDigits(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (ch is >= '0' and <= '9') builder.Append(ch);
            else if (ch is >= '٠' and <= '٩') builder.Append((char)('0' + (ch - '٠')));
            else if (ch is >= '۰' and <= '۹') builder.Append((char)('0' + (ch - '۰')));
        }
        return builder.ToString();
    }

    private string Hash(Guid userId, CodePurpose purpose, string code)
    {
        var secret = configuration["Codes:Secret"] ?? configuration["Authentication:ClientSecret"]
            ?? throw new InvalidOperationException("Set Codes:Secret (or Authentication:ClientSecret).");
        var data = Encoding.UTF8.GetBytes($"{userId:N}:{(int)purpose}:{code}");
        return Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), data));
    }
}
