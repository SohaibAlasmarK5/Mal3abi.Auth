using Mal3abi.Auth.API.Http;

namespace Mal3abi.Auth.API.Endpoints;

public sealed class RegisterRequest : IValidatedRequest
{
    public string Name { get; init; } = "";
    public string Username { get; init; } = "";
    public string Email { get; init; } = "";
    public string Phone { get; init; } = "";
    public int? Age { get; init; }
    public string? PhotoUrl { get; init; }
    public string Password { get; init; } = "";

    public string? Role { get; init; }

    public void Validate(FieldErrors errors) => errors
        .Required(nameof(Name), Name, "register.name", 120)
        .Username(nameof(Username), Username, "register.username")
        .Email(nameof(Email), Email, "register.email")
        .Phone(nameof(Phone), Phone, "register.phone")
        .Age(nameof(Age), Age)
        .OptionalUrl(nameof(PhotoUrl), PhotoUrl, "register.photo")
        .Password(nameof(Password), Password, "register.password");
}

public sealed class EmailRequest : IValidatedRequest
{
    public string Email { get; init; } = "";
    public void Validate(FieldErrors errors) => errors.Email(nameof(Email), Email, "register.email");
}

public sealed class ConfirmEmailRequest : IValidatedRequest
{
    public string Email { get; init; } = "";
    public string Code { get; init; } = "";

    public void Validate(FieldErrors errors) => errors
        .Email(nameof(Email), Email, "register.email")
        .Required(nameof(Code), Code, "confirm.label", 12);
}

public sealed class CodeRequest : IValidatedRequest
{
    public string Code { get; init; } = "";
    public void Validate(FieldErrors errors) => errors.Required(nameof(Code), Code, "twostep.label", 12);
}

public sealed class ResetPasswordRequest : IValidatedRequest
{
    public Guid UserId { get; init; }
    public string Token { get; init; } = "";
    public string Password { get; init; } = "";

    public void Validate(FieldErrors errors) => errors
        .Required(nameof(Token), Token, "reset.title", 4096)
        .Password(nameof(Password), Password, "reset.password");
}

public sealed class ProfileRequest : IValidatedRequest
{
    public string Name { get; init; } = "";
    public string Username { get; init; } = "";
    public string Phone { get; init; } = "";
    public int? Age { get; init; }
    public string? PhotoUrl { get; init; }

    public void Validate(FieldErrors errors) => errors
        .Required(nameof(Name), Name, "register.name", 120)
        .Username(nameof(Username), Username, "register.username")
        .Phone(nameof(Phone), Phone, "register.phone")
        .Age(nameof(Age), Age)
        .OptionalUrl(nameof(PhotoUrl), PhotoUrl, "register.photo");
}

public sealed class ChangePasswordRequest : IValidatedRequest
{
    public string CurrentPassword { get; init; } = "";
    public string NewPassword { get; init; } = "";

    public void Validate(FieldErrors errors) => errors
        .Password(nameof(CurrentPassword), CurrentPassword, "login.password")
        .Password(nameof(NewPassword), NewPassword, "reset.password");
}

public sealed class PasswordRequest : IValidatedRequest
{
    public string Password { get; init; } = "";
    public void Validate(FieldErrors errors) => errors.Password(nameof(Password), Password, "login.password");
}

public sealed class ToggleRequest
{
    public bool Enabled { get; init; }
}

public sealed class LanguageRequest
{
    public string Language { get; init; } = "ar";
}

public sealed class InviteRequest : IValidatedRequest
{
    public string Name { get; init; } = "";
    public string Username { get; init; } = "";
    public string Email { get; init; } = "";
    public string Phone { get; init; } = "";
    public int? Age { get; init; }
    public string? PhotoUrl { get; init; }
    public string? Language { get; init; }

    public void Validate(FieldErrors errors) => errors
        .Required(nameof(Name), Name, "register.name", 120)
        .Username(nameof(Username), Username, "register.username")
        .Email(nameof(Email), Email, "register.email")
        .Phone(nameof(Phone), Phone, "register.phone")
        .Age(nameof(Age), Age)
        .OptionalUrl(nameof(PhotoUrl), PhotoUrl, "register.photo");
}

public sealed class StatusRequest : IValidatedRequest
{
    public string Reason { get; init; } = "";

    public DateTimeOffset? Until { get; init; }

    public void Validate(FieldErrors errors) => errors.Required(nameof(Reason), Reason, "admin.reason", 500);
}

public sealed class ProfileLookupRequest
{
    public List<Guid> UserIds { get; init; } = [];
}
