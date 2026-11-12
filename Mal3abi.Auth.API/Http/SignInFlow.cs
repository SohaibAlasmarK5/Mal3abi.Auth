using System.Security.Claims;
using System.Text.Json;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.API.Http;

public sealed record PendingSignIn(Guid UserId, string Step, bool RememberMe, string? ReturnUrl, DateTimeOffset ExpiresAt)
{
    public const string ConfirmEmail = "confirm";
    public const string TwoStep = "two-step";
}

public sealed class SignInFlow(
    IHttpContextAccessor http,
    IDataProtectionProvider dataProtection,
    SignInManager<AuthUser> signInManager,
    IAccountService accounts,
    IConfiguration configuration,
    TimeProvider time)
{
    private const string CookieName = "Mal3abi.Auth.Pending";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);
    private readonly IDataProtector protector = dataProtection.CreateProtector("Mal3abi.Auth.PendingSignIn.v1");

    private HttpContext Context => http.HttpContext ?? throw new InvalidOperationException("No HTTP request.");

    public void SetPending(Guid userId, string step, bool rememberMe, string? returnUrl)
    {
        var state = new PendingSignIn(userId, step, rememberMe, SafeReturnUrl(returnUrl), time.GetUtcNow() + Lifetime);
        Context.Response.Cookies.Append(CookieName, protector.Protect(JsonSerializer.Serialize(state)), new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            IsEssential = true,
            MaxAge = Lifetime,
            Path = "/account",
        });
    }

    public PendingSignIn? GetPending(string step)
    {
        var raw = Context.Request.Cookies[CookieName];
        if (string.IsNullOrEmpty(raw)) return null;
        try
        {
            var state = JsonSerializer.Deserialize<PendingSignIn>(protector.Unprotect(raw));
            return state is not null && state.Step == step && state.ExpiresAt > time.GetUtcNow() ? state : null;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or JsonException)
        {
            return null;
        }
    }

    public void ClearPending() => Context.Response.Cookies.Delete(CookieName, new CookieOptions { Path = "/account", Secure = true });

    public async Task CompleteAsync(AuthUser user, bool rememberMe, bool withTwoFactor)
    {
        Claim[] claims = [new(AuthClaims.Amr, withTwoFactor ? AuthClaims.Mfa : AuthClaims.Pwd)];
        await signInManager.SignInWithClaimsAsync(user, rememberMe, claims);
        await accounts.RecordSignInAsync(user, withTwoFactor ? AuthClaims.Mfa : AuthClaims.Pwd);
        await accounts.SetLanguageAsync(user.Id, AuthUi.For(Context.Request).Lang);
        ClearPending();
    }

    public string Destination(string? returnUrl) => SafeReturnUrl(returnUrl) ?? WebsiteUrl(AuthUi.For(Context.Request).Lang);

    public string WebsiteUrl(string lang) => (configuration["Website:Url"] ?? "http://localhost:3000").TrimEnd('/') + "/" + lang;

    public static string? SafeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)) return null;
        if (returnUrl[0] != '/' || returnUrl.StartsWith("//", StringComparison.Ordinal) || returnUrl.StartsWith("/\\", StringComparison.Ordinal)) return null;
        return returnUrl;
    }
}
