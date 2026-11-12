using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Infra.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Mal3abi.Auth.Infra.Seeding;

public static class AuthSeeder
{
    public static async Task SeedAuthCenterAsync(this IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var provider = scope.ServiceProvider;
        var configuration = provider.GetRequiredService<IConfiguration>();
        var environment = provider.GetRequiredService<IHostEnvironment>();

        if (environment.IsDevelopment() || configuration.GetValue("Database:MigrateOnStartup", false))
            await provider.GetRequiredService<AuthDbContext>().Database.MigrateAsync();

        await SeedRolesAsync(provider.GetRequiredService<RoleManager<IdentityRole<Guid>>>());
        await SeedSuperAdminAsync(provider, configuration, environment);
        await SeedClientAsync(provider.GetRequiredService<IOpenIddictApplicationManager>(), configuration);
    }

    private static async Task SeedRolesAsync(RoleManager<IdentityRole<Guid>> roles)
    {
        foreach (var role in AuthRoles.All)
        {
            if (await roles.RoleExistsAsync(role)) continue;
            Check(await roles.CreateAsync(new IdentityRole<Guid>(role) { Id = Guid.CreateVersion7() }));
        }
    }

    private static async Task SeedSuperAdminAsync(IServiceProvider provider, IConfiguration configuration, IHostEnvironment environment)
    {
        var users = provider.GetRequiredService<UserManager<AuthUser>>();
        var username = configuration["SuperAdmin:UserName"];
        var email = configuration["SuperAdmin:Email"];
        var password = configuration["SuperAdmin:Password"];
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)) return;

        var existing = await users.FindByNameAsync(username) ?? await users.FindByEmailAsync(email);
        if (existing is not null)
        {
            if (!await users.IsInRoleAsync(existing, AuthRoles.SuperAdmin)) Check(await users.AddToRoleAsync(existing, AuthRoles.SuperAdmin));
            return;
        }

        var admin = new AuthUser
        {
            UserName = username,
            Email = email,
            FullName = configuration["SuperAdmin:Name"] ?? "Super Admin",
            EmailConfirmed = true,
        };

        if (environment.IsDevelopment() && password.Length < 8)
        {
            admin.PasswordHash = provider.GetRequiredService<IPasswordHasher<AuthUser>>().HashPassword(admin, password);
            Check(await users.CreateAsync(admin));
        }
        else
        {
            Check(await users.CreateAsync(admin, password));
        }
        Check(await users.AddToRoleAsync(admin, AuthRoles.SuperAdmin));
    }

    private static async Task SeedClientAsync(IOpenIddictApplicationManager manager, IConfiguration configuration)
    {
        var secret = configuration["Authentication:ClientSecret"]
            ?? throw new InvalidOperationException("Authentication:ClientSecret must be set (User Secrets or the production secret store).");
        var clientId = configuration["Authentication:ClientId"] ?? "mal3abi-api";

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            DisplayName = "Mal3abi",
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
        };
        foreach (var uri in configuration.GetSection("Authentication:RedirectUris").Get<string[]>() ?? ["https://localhost:44393/signin-oidc"])
            descriptor.RedirectUris.Add(new Uri(uri));
        foreach (var uri in configuration.GetSection("Authentication:PostLogoutRedirectUris").Get<string[]>() ?? ["https://localhost:44393/signout-callback-oidc"])
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri));

        descriptor.Permissions.UnionWith(
        [
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Revocation,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code,
            Permissions.Scopes.Email,
            Permissions.Scopes.Profile,
            Permissions.Scopes.Roles,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess,
        ]);
        descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);

        var existing = await manager.FindByClientIdAsync(clientId);
        if (existing is null) await manager.CreateAsync(descriptor);
        else await manager.UpdateAsync(existing, descriptor);
    }

    private static void Check(IdentityResult result)
    {
        if (!result.Succeeded) throw new InvalidOperationException(string.Join(" ", result.Errors.Select(e => e.Description)));
    }
}
