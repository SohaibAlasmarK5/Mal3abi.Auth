using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Core.Common;
using Mal3abi.Auth.Infra.Data;
using Mal3abi.Auth.Infra.Email;
using Mal3abi.Auth.Infra.Jobs;
using Mal3abi.Auth.Infra.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Mal3abi.Auth.Infra;

public static class DependencyInjection
{
    /// <summary>Database, Identity stores, repositories, services and background jobs.</summary>
    public static IdentityBuilder AddAuthInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("AuthCenter");
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException("ConnectionStrings:AuthCenter must point to the Auth Center database.");

        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuditLabel>();
        services.AddScoped<AuditSaveChangesInterceptor>();
        services.AddDbContext<AuthDbContext>((provider, options) =>
        {
            options.UseSqlServer(connectionString, sql => sql.EnableRetryOnFailure(3));
            options.UseOpenIddict<Guid>();
            options.AddInterceptors(provider.GetRequiredService<AuditSaveChangesInterceptor>());
        });

        services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
        services.AddScoped<IUnitOfWork, UnitOfWork>();

        services.AddScoped<IVerificationCodeService, VerificationCodeService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAccountService, AccountService>();
        services.AddScoped<ITwoFactorService, TwoFactorService>();
        services.AddScoped<IAccountAdminService, AccountAdminService>();
        services.AddTransient<IEmailSender, SmtpEmailSender>();

        services.AddSingleton<UnconfirmedAccountCleanup>();
        services.AddHostedService(provider => provider.GetRequiredService<UnconfirmedAccountCleanup>());

        services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromMinutes(30));

        return services.AddIdentity<AuthUser, IdentityRole<Guid>>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
                options.SignIn.RequireConfirmedEmail = false; // checked by the Auth Center itself, with codes
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredUniqueChars = 1;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<AuthDbContext>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<InvitationTokenProvider>(InvitationTokenProviderOptions.ProviderName);
    }
}
