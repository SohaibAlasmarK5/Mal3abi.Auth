using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Codes;

public interface IVerificationCodeRepository : IRepository<VerificationCode>
{
    Task<IReadOnlyList<VerificationCode>> GetSentSinceAsync(Guid userId, CodePurpose purpose, DateTimeOffset since, CancellationToken cancellationToken = default);
    Task<VerificationCode?> GetCurrentAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default);
    Task<DateTimeOffset?> GetLastSentAtAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default);
}
