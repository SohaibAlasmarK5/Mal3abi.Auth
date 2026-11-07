#nullable enable
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.Core.Accounts;

public sealed class AuthUser : IdentityUser<Guid>
{
    public string FullName { get; set; } = string.Empty;
    public int? Age { get; set; }
    public string? PhotoUrl { get; set; }
}