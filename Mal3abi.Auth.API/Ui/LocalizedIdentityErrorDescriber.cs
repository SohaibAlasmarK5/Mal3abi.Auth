using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.API.Ui;

/// <summary>Identity validation messages (password rules, duplicates) in the request's language.</summary>
public sealed class LocalizedIdentityErrorDescriber(IHttpContextAccessor http) : IdentityErrorDescriber
{
    private string Text(string code) => Ui()?.T("identity." + code) ?? code;
    private string Text(string code, object arg) => Ui()?.T("identity." + code, arg) ?? code;
    private AuthUi? Ui() => http.HttpContext is { } context ? AuthUi.For(context.Request) : null;

    private IdentityError Make(string code) => new() { Code = code, Description = Text(code) };
    private IdentityError Make(string code, object arg) => new() { Code = code, Description = Text(code, arg) };

    public override IdentityError DefaultError() => Make(nameof(DefaultError));
    public override IdentityError ConcurrencyFailure() => Make(nameof(ConcurrencyFailure));
    public override IdentityError PasswordMismatch() => Make(nameof(PasswordMismatch));
    public override IdentityError InvalidToken() => Make(nameof(InvalidToken));
    public override IdentityError RecoveryCodeRedemptionFailed() => Make(nameof(RecoveryCodeRedemptionFailed));
    public override IdentityError LoginAlreadyAssociated() => Make(nameof(LoginAlreadyAssociated));
    public override IdentityError InvalidUserName(string? userName) => Make(nameof(InvalidUserName), userName ?? "");
    public override IdentityError InvalidEmail(string? email) => Make(nameof(InvalidEmail), email ?? "");
    public override IdentityError DuplicateUserName(string userName) => Make(nameof(DuplicateUserName), userName);
    public override IdentityError DuplicateEmail(string email) => Make(nameof(DuplicateEmail), email);
    public override IdentityError InvalidRoleName(string? role) => Make(nameof(InvalidRoleName), role ?? "");
    public override IdentityError DuplicateRoleName(string role) => Make(nameof(DuplicateRoleName), role);
    public override IdentityError UserAlreadyHasPassword() => Make(nameof(UserAlreadyHasPassword));
    public override IdentityError UserLockoutNotEnabled() => Make(nameof(UserLockoutNotEnabled));
    public override IdentityError UserAlreadyInRole(string role) => Make(nameof(UserAlreadyInRole), role);
    public override IdentityError UserNotInRole(string role) => Make(nameof(UserNotInRole), role);
    public override IdentityError PasswordTooShort(int length) => Make(nameof(PasswordTooShort), length);
    public override IdentityError PasswordRequiresUniqueChars(int uniqueChars) => Make(nameof(PasswordRequiresUniqueChars), uniqueChars);
    public override IdentityError PasswordRequiresNonAlphanumeric() => Make(nameof(PasswordRequiresNonAlphanumeric));
    public override IdentityError PasswordRequiresDigit() => Make(nameof(PasswordRequiresDigit));
    public override IdentityError PasswordRequiresLower() => Make(nameof(PasswordRequiresLower));
    public override IdentityError PasswordRequiresUpper() => Make(nameof(PasswordRequiresUpper));
}
