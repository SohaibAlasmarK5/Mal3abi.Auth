using Mal3abi.Auth.Core.Codes;
using Microsoft.EntityFrameworkCore;

namespace Mal3abi.Auth.Infra.Data;

public sealed class VerificationCodeRepository(AuthDbContext db) : Repository<VerificationCode>(db), IVerificationCodeRepository
{
    public async Task<IReadOnlyList<VerificationCode>> GetSentSinceAsync(Guid userId, CodePurpose purpose, DateTimeOffset since, CancellationToken cancellationToken = default) =>
        await Query()
            .Where(c => c.UserId == userId && c.Purpose == purpose && c.CreatedAt > since)
            .OrderByDescending(c => c.CreatedAt)
            .ToListAsync(cancellationToken);

    public Task<VerificationCode?> GetCurrentAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default) =>
        Query()
            .Where(c => c.UserId == userId && c.Purpose == purpose && !c.Superseded)
            .OrderByDescending(c => c.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

    public Task<DateTimeOffset?> GetLastSentAtAsync(Guid userId, CodePurpose purpose, CancellationToken cancellationToken = default) =>
        QueryNoTracking()
            .Where(c => c.UserId == userId && c.Purpose == purpose)
            .OrderByDescending(c => c.CreatedAt)
            .Select(c => (DateTimeOffset?)c.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);
}
