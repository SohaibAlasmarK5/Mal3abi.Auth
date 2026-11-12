using System.Security.Claims;
using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Mal3abi.Auth.API.Endpoints;

/// <summary>
/// OpenID Connect endpoints for Mal3abi.BE (client "mal3abi-api"): authorize, token and logout.
/// Claims stay as BE reads them: sub, name, preferred_username, email, email_verified,
/// role (player, owner or superadmin) and auth_center.
/// </summary>
public static class ConnectEndpoints
{
    public static void MapConnectEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], (Delegate)AuthorizeAsync).DisableAntiforgery().ExcludeFromDescription();
        app.MapPost("/connect/token", (Delegate)TokenAsync).DisableAntiforgery().ExcludeFromDescription();
        app.MapMethods("/connect/logout", [HttpMethods.Get, HttpMethods.Post], (Delegate)LogoutAsync).DisableAntiforgery().ExcludeFromDescription();
    }

    private static async Task<IResult> AuthorizeAsync(HttpContext context, IAccountService accounts, ITwoFactorService twoFactor)
    {
        var request = context.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("Not an OpenID Connect request.");
        var returnUrl = context.Request.PathBase + context.Request.Path + QueryString.Create(
            context.Request.HasFormContentType
                ? context.Request.Form.Select(pair => KeyValuePair.Create(pair.Key, (string?)pair.Value.ToString()))
                : context.Request.Query.Select(pair => KeyValuePair.Create(pair.Key, (string?)pair.Value.ToString())));

        var cookie = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!cookie.Succeeded || cookie.Principal?.GetUserId() is not { } userId)
            return Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, [IdentityConstants.ApplicationScheme]);

        // Suspended, banned, hidden or unconfirmed accounts sign in again, and the sign-in page explains why.
        var check = await accounts.EnsureCanSignInAsync(userId);
        if (!check.Succeeded)
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
            return Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, [IdentityConstants.ApplicationScheme]);
        }

        var user = check.Value;
        var required = await twoFactor.RequiredMethodAsync(user);
        if (required == TwoFactorMethod.Authenticator && user.TwoFactorMethod != TwoFactorMethod.Authenticator)
            return Results.Redirect("/account/security?required=true&returnUrl=" + Uri.EscapeDataString(returnUrl));

        var hasMfa = cookie.Principal.HasMfa();
        if (required != TwoFactorMethod.None && !hasMfa)
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
            return Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, [IdentityConstants.ApplicationScheme]);
        }

        var principal = BuildPrincipal(user, await accounts.GetRolesAsync(user), hasMfa, request.GetScopes(), ["mal3abi-api"]);
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> TokenAsync(HttpContext context, IAccountService accounts)
    {
        var request = context.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("Not an OpenID Connect request.");
        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            return Forbid(Errors.UnsupportedGrantType, "This grant type is not supported.");

        var stored = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (stored.Principal?.GetClaim(Claims.Subject) is not { } subject || !Guid.TryParse(subject, out var userId))
            return Forbid(Errors.InvalidGrant, "The token is no longer valid.");

        // Checked on every refresh, so a suspension or ban ends access within one access-token lifetime.
        var check = await accounts.EnsureCanSignInAsync(userId);
        if (!check.Succeeded)
            return Forbid(Errors.InvalidGrant, "The account can no longer sign in.");

        var principal = BuildPrincipal(check.Value, await accounts.GetRolesAsync(check.Value), stored.Principal.HasMfa(),
            stored.Principal.GetScopes(), stored.Principal.GetResources());
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> LogoutAsync(HttpContext context)
    {
        await context.SignOutAsync(IdentityConstants.ApplicationScheme);
        // OpenIddict checks post_logout_redirect_uri against the client's registered addresses.
        return Results.SignOut(new AuthenticationProperties { RedirectUri = "/account/login?signedOut=true" },
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    public static ClaimsPrincipal BuildPrincipal(AuthUser user, IEnumerable<string> roles, bool withTwoFactor,
        IEnumerable<string> scopes, IEnumerable<string> resources)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, user.Id.ToString())
            .SetClaim("auth_center", "true")
            .SetClaim(Claims.Name, user.FullName)
            .SetClaim(Claims.PreferredUsername, user.UserName ?? string.Empty)
            .SetClaim(Claims.Email, user.Email ?? string.Empty)
            .SetClaim(Claims.EmailVerified, user.EmailConfirmed ? "true" : "false")
            .SetClaim(Claims.Role, AuthRoles.ToPublic(roles))
            .SetClaim(Claims.Locale, user.PreferredLanguage)
            .SetClaim(AuthClaims.Amr, withTwoFactor ? AuthClaims.Mfa : AuthClaims.Pwd);
        // Scopes first: the destinations below depend on them.
        identity.SetScopes(scopes);
        identity.SetResources(resources);

        identity.SetDestinations(claim => claim.Type switch
        {
            Claims.Subject or "auth_center" or AuthClaims.Amr => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Name or Claims.PreferredUsername or Claims.Locale when identity.HasScope(Scopes.Profile) => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Email or Claims.EmailVerified when identity.HasScope(Scopes.Email) => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Role when identity.HasScope(Scopes.Roles) => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken],
        });
        return new ClaimsPrincipal(identity);
    }

    private static IResult Forbid(string error, string description) => Results.Forbid(
        new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }),
        [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}
