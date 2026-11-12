using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Mal3abi.Auth.Infra.Identity;

public sealed class InvitationTokenProviderOptions : DataProtectionTokenProviderOptions
{
    public InvitationTokenProviderOptions()
    {
        Name = InvitationTokens.ProviderName;
        TokenLifespan = TimeSpan.FromDays(3);
    }
}

public sealed class InvitationTokenProvider(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<InvitationTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<AuthUser>> logger)
    : DataProtectorTokenProvider<AuthUser>(dataProtectionProvider, options, logger);
