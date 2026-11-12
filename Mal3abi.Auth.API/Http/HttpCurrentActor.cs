using System.Security.Claims;
using Mal3abi.Auth.Core.Common;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Mal3abi.Auth.API.Http;

public sealed class HttpCurrentActor(IHttpContextAccessor http) : ICurrentActor
{
    public const string ActorHeader = "X-Mal3abi-Actor-Id";
    public const string IntegrationItem = "mal3abi.integration";

    public Guid? UserId
    {
        get
        {
            var context = http.HttpContext;
            if (context is null) return null;
            if (context.Items.ContainsKey(IntegrationItem))
                return Guid.TryParse(context.Request.Headers[ActorHeader], out var onBehalf) ? onBehalf : null;
            return context.User.GetUserId();
        }
    }

    public string Name
    {
        get
        {
            var context = http.HttpContext;
            if (context is null) return "system";
            if (context.Items.ContainsKey(IntegrationItem)) return "Mal3abi.BE";
            return context.User.FindFirstValue(ClaimTypes.Name) ?? context.User.FindFirstValue(Claims.PreferredUsername)
                ?? context.User.FindFirstValue(Claims.Name) ?? "anonymous";
        }
    }

    public string? IpAddress => http.HttpContext?.Connection.RemoteIpAddress?.ToString();
}

public static class PrincipalExtensions
{
    public static Guid? GetUserId(this ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue(Claims.Subject);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    public static bool HasMfa(this ClaimsPrincipal principal) =>
        principal.HasClaim(c => c.Type == AuthClaims.Amr && c.Value == AuthClaims.Mfa);

    public static bool IsSuperAdmin(this ClaimsPrincipal principal) =>
        principal.HasClaim(c => (c.Type == ClaimTypes.Role || c.Type == Claims.Role) &&
                                string.Equals(c.Value, "superadmin", StringComparison.OrdinalIgnoreCase));
}

public static class AuthClaims
{
    public const string Amr = "amr";
    public const string Mfa = "mfa";
    public const string Pwd = "pwd";
}
