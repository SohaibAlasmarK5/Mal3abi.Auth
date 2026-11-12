using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Mal3abi.Auth.Core;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthCore(this IServiceCollection services)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuditLabel>();
        services.AddScoped<IVerificationCodeService, VerificationCodeService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAccountService, AccountService>();
        services.AddScoped<ITwoFactorService, TwoFactorService>();
        services.AddScoped<IAccountAdminService, AccountAdminService>();
        return services;
    }
}
