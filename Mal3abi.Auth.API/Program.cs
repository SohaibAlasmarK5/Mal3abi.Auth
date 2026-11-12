using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Mal3abi.Auth.API.Endpoints;
using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Common;
using Mal3abi.Auth.Infra;
using Mal3abi.Auth.Infra.Data;
using Mal3abi.Auth.Infra.Seeding;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
var issuer = configuration["Authentication:Issuer"] ?? "https://localhost:44493/";

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentActor, HttpCurrentActor>();
builder.Services.AddScoped<SignInFlow>();

builder.Services.AddAuthInfrastructure(configuration)
    .AddErrorDescriber<LocalizedIdentityErrorDescriber>();

builder.Services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.FromMinutes(5));

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/account/login";
    options.LogoutPath = "/account/logout";
    options.AccessDeniedPath = "/account/login";
    options.Cookie.Name = "Mal3abi.Auth.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(12);
    options.SlidingExpiration = true;
    options.Events.OnRedirectToLogin = context => ApiOrRedirect(context.HttpContext, context.RedirectUri, ErrorCodes.Unauthorized);
    options.Events.OnRedirectToAccessDenied = context => ApiOrRedirect(context.HttpContext, context.RedirectUri, ErrorCodes.Forbidden);
});

builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");

builder.Services.AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<AuthDbContext>().ReplaceDefaultEntities<Guid>())
    .AddServer(options =>
    {
        options.SetIssuer(new Uri(issuer));
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetEndSessionEndpointUris("connect/logout")
            .SetRevocationEndpointUris("connect/revoke");
        options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow().RequireProofKeyForCodeExchange();
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
            .SetRefreshTokenLifetime(TimeSpan.FromDays(30))
            .DisableSlidingRefreshTokenExpiration();
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

        if (builder.Environment.IsDevelopment())
        {
            options.AddDevelopmentSigningCertificate().AddDevelopmentEncryptionCertificate();
        }
        else
        {
            options.AddSigningCertificate(LoadCertificate(configuration, "Signing"));
            options.AddEncryptionCertificate(LoadCertificate(configuration, "Encryption"));
        }

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication().AddPolicyScheme(Policies.ApiScheme, "Cookie or bearer token", options =>
    options.ForwardDefaultSelector = context =>
        context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme
            : IdentityConstants.ApplicationScheme);

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(Policies.Account, policy => policy
        .AddAuthenticationSchemes(Policies.ApiScheme)
        .RequireAuthenticatedUser())
    .AddPolicy(Policies.SuperAdmin, policy => policy
        .AddAuthenticationSchemes(Policies.ApiScheme)
        .RequireAuthenticatedUser()
        .RequireAssertion(context => context.User.IsSuperAdmin() && context.User.HasMfa()));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(RateLimits.Accounts, context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1) }));
    options.OnRejected = async (context, token) =>
        await context.HttpContext.Problem(ErrorCodes.RateLimited).ExecuteAsync(context.HttpContext);
});

builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
{
    if (context.ProblemDetails.Extensions.ContainsKey("code")) return;
    var code = context.ProblemDetails.Status switch
    {
        401 => ErrorCodes.Unauthorized,
        403 => ErrorCodes.Forbidden,
        404 => ErrorCodes.NotFound,
        429 => ErrorCodes.RateLimited,
        >= 500 => ErrorCodes.ServerError,
        _ => ErrorCodes.ValidationFailed,
    };
    context.ProblemDetails.Extensions["code"] = code;
    context.ProblemDetails.Extensions["message"] = AuthUi.For(context.HttpContext.Request).Error(new Error(code));
});

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Account/Security");
});
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
{
    var feature = context.Features.Get<IExceptionHandlerFeature>();
    app.Logger.LogError(feature?.Error, "Unhandled error on {Path}", context.Request.Path);
    if (context.Request.Path.StartsWithSegments("/api"))
        await context.Problem(ErrorCodes.ServerError).ExecuteAsync(context);
    else
        context.Response.Redirect("/account/login?error=server_error");
}));
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
app.UseStatusCodePages();
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment()) app.MapOpenApi();
app.MapGet("/", () => Results.Redirect("/account/login")).ExcludeFromDescription();
app.MapGet("/health", () => Results.Ok(new { status = "ok", issuer })).ExcludeFromDescription();
app.MapConnectEndpoints();
app.MapAccountEndpoints();
app.MapAdminEndpoints();
app.MapIntegrationEndpoints();
app.MapRazorPages();

await app.Services.SeedAuthCenterAsync();
app.Run();

static Task ApiOrRedirect(HttpContext context, string redirectUri, string code)
{
    if (context.Request.Path.StartsWithSegments("/api"))
        return context.Problem(code).ExecuteAsync(context);
    context.Response.Redirect(redirectUri);
    return Task.CompletedTask;
}

static X509Certificate2 LoadCertificate(IConfiguration configuration, string kind)
{
    var path = configuration[$"Authentication:{kind}CertificatePath"];
    var password = configuration[$"Authentication:{kind}CertificatePassword"];
    if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(password))
        throw new InvalidOperationException($"Production needs Authentication:{kind}CertificatePath and {kind}CertificatePassword.");
    return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.MachineKeySet);
}

public static class Policies
{
    public const string Account = "account";
    public const string SuperAdmin = "superadmin";
    public const string ApiScheme = "api";
}

public static class RateLimits
{
    public const string Accounts = "accounts";
}

public partial class Program;
