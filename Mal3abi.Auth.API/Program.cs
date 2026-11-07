using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Infra.Accounts;
using Mal3abi.Auth.Infra.Email;
using Mal3abi.Auth.Infra.Extensions;
using Mal3abi.Auth.Infra.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Security.Cryptography.X509Certificates;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["Authentication:Issuer"] ?? "https://localhost:44493/";
var connectionString = builder.Configuration.GetConnectionString("AuthCenter");
if (string.IsNullOrWhiteSpace(connectionString))
    throw new InvalidOperationException("ConnectionStrings:AuthCenter must point to the Authentication Center database.");

builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseSqlServer(connectionString);
    options.UseOpenIddict<Guid>();
});

builder.Services.AddIdentity<AuthUser, IdentityRole<Guid>>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = false;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromMinutes(5));
builder.Services.AddScoped<IAuthAccountService, AuthAccountService>();
builder.Services.AddTransient<IAuthEmailSender, ConfiguredAuthEmailSender>();
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/account/login";
    options.LogoutPath = "/account/logout";
    options.Cookie.Name = "Mal3abi.Auth.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(12);
    options.SlidingExpiration = true;
});

builder.Services.AddAuthorization();

var clientSecret = builder.Configuration["Authentication:ClientSecret"];
if (string.IsNullOrWhiteSpace(clientSecret))
    throw new InvalidOperationException("Authentication:ClientSecret must be set in User Secrets or the production secret store.");

builder.Services.AddOpenIddict()
    .AddCore(options => options
        .UseEntityFrameworkCore()
        .UseDbContext<AuthDbContext>()
        .ReplaceDefaultEntities<Guid>())
    .AddServer(options =>
    {
        options.SetIssuer(new Uri(issuer));
        options.SetAuthorizationEndpointUris("connect/authorize");
        options.SetTokenEndpointUris("connect/token");
        options.SetEndSessionEndpointUris("connect/logout");
        options.SetRevocationEndpointUris("connect/revoke");
        options.AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .RequireProofKeyForCodeExchange()
            .SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
            .SetRefreshTokenLifetime(TimeSpan.FromDays(30))
            .DisableSlidingRefreshTokenExpiration();
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

        if (builder.Environment.IsDevelopment())
        {
            options.AddDevelopmentSigningCertificate();
            options.AddDevelopmentEncryptionCertificate();
        }
        else
        {
            var signingPath = builder.Configuration["Authentication:SigningCertificatePath"];
            var signingPassword = builder.Configuration["Authentication:SigningCertificatePassword"];
            var encryptionPath = builder.Configuration["Authentication:EncryptionCertificatePath"];
            var encryptionPassword = builder.Configuration["Authentication:EncryptionCertificatePassword"];
            if (string.IsNullOrWhiteSpace(signingPath) || string.IsNullOrWhiteSpace(signingPassword) ||
                string.IsNullOrWhiteSpace(encryptionPath) || string.IsNullOrWhiteSpace(encryptionPassword))
                throw new InvalidOperationException("Production requires separate signing and encryption certificates configured through Authentication settings.");
            options.AddSigningCertificate(X509CertificateLoader.LoadPkcs12FromFile(signingPath, signingPassword, X509KeyStorageFlags.MachineKeySet));
            options.AddEncryptionCertificate(X509CertificateLoader.LoadPkcs12FromFile(encryptionPath, encryptionPassword, X509KeyStorageFlags.MachineKeySet));
        }

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough();
    });

var app = builder.Build();

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages();
app.MapGet("/health", () => Results.Ok(new { status = "ok", issuer }));

await app.Services.SeedRolesAndSuperAdminAsync();
await EnsureMal3abiApiClientAsync(app.Services, clientSecret, builder.Configuration);

app.Run();

static async Task EnsureMal3abiApiClientAsync(IServiceProvider services, string secret, IConfiguration configuration)
{
    await using var scope = services.CreateAsyncScope();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    var existingApplication = await manager.FindByClientIdAsync("mal3abi-api");

    var descriptor = new OpenIddictApplicationDescriptor
    {
        ClientId = "mal3abi-api",
        ClientSecret = secret,
        DisplayName = "Mal3abi Web Application",
        ClientType = ClientTypes.Confidential,
        ConsentType = ConsentTypes.Implicit
    };
    var redirectUris = configuration.GetSection("Authentication:RedirectUris").Get<string[]>()
        ?? ["https://localhost:44393/signin-oidc"];
    var logoutUris = configuration.GetSection("Authentication:PostLogoutRedirectUris").Get<string[]>()
        ?? ["https://localhost:44393/signout-callback-oidc"];
    foreach (var uri in redirectUris) descriptor.RedirectUris.Add(new Uri(uri));
    foreach (var uri in logoutUris) descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
    descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
    descriptor.Permissions.Add(Permissions.Endpoints.Token);
    descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
    descriptor.Permissions.Add(Permissions.Endpoints.Revocation);
    descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
    descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
    descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
    descriptor.Permissions.Add(Permissions.Scopes.Email);
    descriptor.Permissions.Add(Permissions.Scopes.Profile);
    descriptor.Permissions.Add(Permissions.Prefixes.Scope + Scopes.Roles);
    if (existingApplication is null)
        await manager.CreateAsync(descriptor);
    else
        await manager.UpdateAsync(existingApplication, descriptor);
}