using System.Security.Claims;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Mal3abi.Auth.API.Controllers;

public sealed class ConnectController(UserManager<AuthUser> users, IConfiguration configuration) : Controller
{
    [AcceptVerbs("GET", "POST")]
    [Route("connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> AuthorizeEndpoint()
    {
        var request = Microsoft.AspNetCore.OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerRequest(HttpContext);
        if (request is null) return BadRequest("Invalid OpenID Connect request.");

        var returnUrl = $"{Request.PathBase}{Request.Path}{Request.QueryString}";
        if (User.Identity?.IsAuthenticated != true)
            return Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, IdentityConstants.ApplicationScheme);

        var user = await users.GetUserAsync(User);
        if (user is null)
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, IdentityConstants.ApplicationScheme);
        }

        var roleList = await users.GetRolesAsync(user);
        if (roleList.Contains("SuperAdmin", StringComparer.OrdinalIgnoreCase) && !user.TwoFactorEnabled)
        {
            var requiredUrl = $"/account/security?required=true&returnUrl={Uri.EscapeDataString(returnUrl)}";
            return Redirect(requiredUrl);
        }

        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, user.Id.ToString()));
        identity.AddClaim(new Claim("auth_center", "true"));
        identity.AddClaim(new Claim(Claims.Name, user.FullName));
        identity.AddClaim(new Claim(Claims.PreferredUsername, user.UserName ?? string.Empty));
        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            identity.AddClaim(new Claim(Claims.Email, user.Email));
            identity.AddClaim(new Claim(Claims.EmailVerified, user.EmailConfirmed ? "true" : "false"));
        }
        var publicRole = roleList.Contains("SuperAdmin", StringComparer.OrdinalIgnoreCase)
            ? "superadmin"
            : roleList.Any(role => role.Equals("owner", StringComparison.OrdinalIgnoreCase) || role.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                ? "owner"
                : "player";
        identity.AddClaim(new Claim(Claims.Role, publicRole));

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());
        principal.SetResources("mal3abi-api");
        principal.SetDestinations(claim =>
        {
            if (claim.Type == Claims.Subject) return [Destinations.AccessToken, Destinations.IdentityToken];
            if (claim.Type == "auth_center") return [Destinations.AccessToken, Destinations.IdentityToken];
            if (claim.Type is Claims.Name or Claims.PreferredUsername && principal.HasScope(Scopes.Profile))
                return [Destinations.AccessToken, Destinations.IdentityToken];
            if (claim.Type is Claims.Email or Claims.EmailVerified && principal.HasScope(Scopes.Email))
                return [Destinations.AccessToken, Destinations.IdentityToken];
            if (claim.Type == Claims.Role && principal.HasScope(Scopes.Roles))
                return [Destinations.AccessToken, Destinations.IdentityToken];
            return [];
        });

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [AcceptVerbs("GET", "POST")]
    [Route("connect/logout")]
    public IActionResult Logout([FromQuery] string? post_logout_redirect_uri)
    {
        var destination = IsRegisteredLogoutUrl(post_logout_redirect_uri) ? post_logout_redirect_uri : "/";
        return SignOut(new AuthenticationProperties { RedirectUri = destination }, IdentityConstants.ApplicationScheme, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private bool IsRegisteredLogoutUrl(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return false;
        var allowed = configuration.GetSection("Authentication:PostLogoutRedirectUris").Get<string[]>() ?? ["https://localhost:44393/signout-callback-oidc"];
        return allowed.Any(candidate => Uri.TryCreate(candidate, UriKind.Absolute, out var allowedUri) && Uri.Compare(uri, allowedUri, UriComponents.AbsoluteUri, UriFormat.SafeUnescaped, StringComparison.Ordinal) == 0);
    }
}

