using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Common;
using Microsoft.EntityFrameworkCore;

namespace Mal3abi.Auth.Infra.Data;

public sealed class AccountRepository(AuthDbContext db) : Repository<AuthUser>(db), IAccountRepository
{
    public Task<bool> EmailInUseAsync(string normalizedEmail, Guid? exceptUserId, CancellationToken cancellationToken = default) =>
        QueryIncludingDeleted().AnyAsync(u => u.NormalizedEmail == normalizedEmail && (exceptUserId == null || u.Id != exceptUserId), cancellationToken);

    public Task<bool> UserNameInUseAsync(string normalizedUserName, Guid? exceptUserId, CancellationToken cancellationToken = default) =>
        QueryIncludingDeleted().AnyAsync(u => u.NormalizedUserName == normalizedUserName && (exceptUserId == null || u.Id != exceptUserId), cancellationToken);

    public Task<AuthUser?> FindAsync(Guid userId, bool includeDeleted, CancellationToken cancellationToken = default) =>
        (includeDeleted ? QueryIncludingDeleted() : Query()).FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

    public async Task<PagedResult<AuthUser>> SearchAsync(AccountQuery query, CancellationToken cancellationToken = default)
    {
        var accounts = (query.IncludeDeleted ? QueryIncludingDeleted() : Query()).AsNoTracking();

        if (AuthRoles.FromPublic(query.Role) is { } role)
        {
            var normalizedRole = role.ToUpperInvariant();
            var roleUserIds = from userRole in Db.UserRoles
                              join r in Db.Roles on userRole.RoleId equals r.Id
                              where r.NormalizedName == normalizedRole
                              select userRole.UserId;
            accounts = accounts.Where(u => roleUserIds.Contains(u.Id));
        }
        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var term = query.Search.Trim();
            accounts = accounts.Where(u =>
                u.FullName.Contains(term) || u.UserName!.Contains(term) || u.Email!.Contains(term) || u.PhoneNumber!.Contains(term));
        }
        if (Enum.TryParse<AccountStatus>(query.Status, ignoreCase: true, out var status))
            accounts = accounts.Where(u => u.Status == status);

        return await PageAsync(accounts.OrderByDescending(u => u.CreatedAt), query.Page, query.PageSize, cancellationToken);
    }

    public async Task<IReadOnlyList<AuthUser>> GetManyAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken = default) =>
        await QueryNoTracking().Where(u => userIds.Contains(u.Id)).ToListAsync(cancellationToken);

    public async Task<IReadOnlyDictionary<Guid, IReadOnlyList<string>>> GetRolesAsync(IReadOnlyCollection<Guid> userIds, CancellationToken cancellationToken = default)
    {
        var rows = await (from userRole in Db.UserRoles
                          join role in Db.Roles on userRole.RoleId equals role.Id
                          where userIds.Contains(userRole.UserId)
                          select new { userRole.UserId, role.Name })
                         .ToListAsync(cancellationToken);
        return rows.GroupBy(r => r.UserId)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(r => r.Name ?? string.Empty).ToList());
    }

    public Task HardDeleteAsync(Guid userId, CancellationToken cancellationToken = default) =>
        QueryIncludingDeleted().Where(u => u.Id == userId).ExecuteDeleteAsync(cancellationToken);
}
