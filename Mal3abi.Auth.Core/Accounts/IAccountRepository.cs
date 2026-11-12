using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Accounts;

public interface IAccountRepository : IRepository<AuthUser>
{
    Task<bool> EmailInUseAsync(string normalizedEmail, Guid? exceptUserId, CancellationToken cancellationToken = default);
    Task<bool> UserNameInUseAsync(string normalizedUserName, Guid? exceptUserId, CancellationToken cancellationToken = default);
    Task<AuthUser?> FindAsync(Guid userId, bool includeDeleted, CancellationToken cancellationToken = default);
    Task<PagedResult<AuthUser>> SearchAsync(AccountQuery query, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AuthUser>> GetManyAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken = default);
    Task<IReadOnlyDictionary<Guid, IReadOnlyList<string>>> GetRolesAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken = default);
    Task HardDeleteAsync(Guid userId, CancellationToken cancellationToken = default);
}
