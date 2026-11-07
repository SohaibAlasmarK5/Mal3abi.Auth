using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Mal3abi.Auth.Infra.Extensions;

public static class IdentitySeeder
{
    public static async Task SeedRolesAndSuperAdminAsync(this IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AuthUser>>();
        var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
        var environment = scope.ServiceProvider.GetRequiredService<IHostEnvironment>();

        foreach (var role in new[] { AuthRoles.SuperAdmin, AuthRoles.Admin, AuthRoles.User, AuthRoles.Player, AuthRoles.Owner })
        {
            if (await roleManager.RoleExistsAsync(role)) continue;
            var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            if (!result.Succeeded) throw new InvalidOperationException(string.Join(" ", result.Errors.Select(error => error.Description)));
        }

        var username = configuration["SuperAdmin:UserName"] ?? "salasmar";
        var email = configuration["SuperAdmin:Email"];
        var existing = await users.FindByNameAsync(username)
            ?? (string.IsNullOrWhiteSpace(email) ? null : await users.FindByEmailAsync(email));
        if (existing is not null)
        {
            if (!await users.IsInRoleAsync(existing, AuthRoles.SuperAdmin))
            {
                var roleResult = await users.AddToRoleAsync(existing, AuthRoles.SuperAdmin);
                if (!roleResult.Succeeded) throw new InvalidOperationException(string.Join(" ", roleResult.Errors.Select(error => error.Description)));
            }
            return;
        }

        var password = configuration["SuperAdmin:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)) return;
        var superAdmin = new AuthUser { UserName = username, Email = email, FullName = "Super Admin", EmailConfirmed = true };
        var useTemporaryDevelopmentPassword = environment.IsDevelopment() && password == "123456";
        var created = useTemporaryDevelopmentPassword
            ? await users.CreateAsync(superAdmin)
            : await users.CreateAsync(superAdmin, password);
        if (!created.Succeeded) throw new InvalidOperationException(string.Join(" ", created.Errors.Select(error => error.Description)));

        if (useTemporaryDevelopmentPassword)
        {
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<AuthUser>>();
            superAdmin.PasswordHash = hasher.HashPassword(superAdmin, password);
            var saved = await users.UpdateAsync(superAdmin);
            if (!saved.Succeeded)
            {
                await users.DeleteAsync(superAdmin);
                throw new InvalidOperationException(string.Join(" ", saved.Errors.Select(error => error.Description)));
            }
        }

        var assigned = await users.AddToRoleAsync(superAdmin, AuthRoles.SuperAdmin);
        if (!assigned.Succeeded) throw new InvalidOperationException(string.Join(" ", assigned.Errors.Select(error => error.Description)));
    }
}
