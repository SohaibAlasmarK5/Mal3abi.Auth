namespace Mal3abi.Auth.Core.Common;

/// <summary>
/// A failure with a stable code. The API turns it into problem+json; the pages turn the code
/// into Arabic or English text. Details hold messages that are already localized (Identity rules).
/// </summary>
public sealed record Error(
    string Code,
    IReadOnlyList<string>? Details = null,
    int? RetryAfterSeconds = null,
    DateTimeOffset? Until = null);

public class Result
{
    protected Result(Error? error) => Error = error;

    public Error? Error { get; }
    public bool Succeeded => Error is null;

    public static Result Success() => new(null);
    public static Result Failure(Error error) => new(error);
    public static Result Failure(string code) => new(new Error(code));
    public static Result<T> Success<T>(T value) => Result<T>.Success(value);

    public static implicit operator Result(Error error) => Failure(error);
}

public sealed class Result<T> : Result
{
    private readonly T? value;

    private Result(T? value, Error? error) : base(error) => this.value = value;

    public T Value => Succeeded ? value! : throw new InvalidOperationException("A failed result has no value.");

    public static Result<T> Success(T value) => new(value, null);
    public static new Result<T> Failure(Error error) => new(default, error);

    public static implicit operator Result<T>(T value) => Success(value);
    public static implicit operator Result<T>(Error error) => Failure(error);
}

/// <summary>Error codes shared with the website and Mal3abi.BE. Do not rename.</summary>
public static class ErrorCodes
{
    public const string ValidationFailed = "validation_failed";
    public const string Unauthorized = "unauthorized";
    public const string Forbidden = "forbidden";
    public const string NotFound = "not_found";
    public const string CsrfInvalid = "csrf_invalid";
    public const string ServerError = "server_error";
    public const string RateLimited = "rate_limited";

    public const string InvalidCredentials = "invalid_credentials";
    public const string LockedOut = "locked_out";
    public const string EmailNotVerified = "email_not_verified";
    public const string AccountSuspended = "account_suspended";
    public const string AccountBanned = "account_banned";
    public const string EmailTaken = "email_taken";
    public const string UsernameTaken = "username_taken";
    public const string PhoneBlocked = "phone_blocked";

    public const string CodeWrong = "code_wrong";
    public const string CodeExpired = "code_expired";
    public const string CodeAttempts = "code_attempts";
    public const string CodeTooSoon = "code_too_soon";
    public const string CodeHourlyLimit = "code_hourly_limit";

    public const string TwoFactorRequired = "two_factor_required";
    public const string TwoFactorLocked = "two_factor_locked";
    public const string InvitationInvalid = "invitation_invalid";
    public const string ResetInvalid = "reset_invalid";
    public const string PasswordWrong = "password_wrong";
    public const string NotAllowed = "not_allowed";
}
