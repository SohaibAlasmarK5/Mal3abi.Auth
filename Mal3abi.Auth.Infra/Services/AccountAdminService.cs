using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Bans;
using Mal3abi.Auth.Core.Common;
using Mal3abi.Auth.Infra.Data;
using Mal3abi.Auth.Infra.Email;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Mal3abi.Auth.Infra.Services;

/// <summary>
/// Admin actions on accounts: staged penalties (warning, suspension, permanent ban, reference
/// section 9), hiding and restoring. Every change is written to the audit log with its reason.
/// </summary>
public sealed class AccountAdminService(
    AuthDbContext db,
    UserManager<AuthUser> users,
    IRepository<BannedIdentifier> bans,
    IUnitOfWork unitOfWork,
    AuditLabel label,
    ICurrentActor actor,
    IEmailSender email,
    TimeProvider time) : IAccountAdminService
{
    public async Task<PagedResult<AccountSummary>> ListAsync(AccountQuery query, CancellationToken cancellationToken = default)
    {
        IQueryable<AuthUser> accounts = query.IncludeDeleted ? db.Users.IgnoreQueryFilters() : db.Users;

        if (AuthRoles.FromPublic(query.Role) is { } role)
        {
            var normalizedRole = role.ToUpperInvariant();
            var roleUserIds = from userRole in db.UserRoles
                              join r in db.Roles on userRole.RoleId equals r.Id
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

        var page = Math.Max(1, query.Page);
        var pageSize = Math.Clamp(query.PageSize, 1, 200);
        var total = await accounts.CountAsync(cancellationToken);
        var items = await accounts.AsNoTracking()
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken);
        var roles = await RolesForAsync(items.Select(u => u.Id), cancellationToken);
        var summaries = items.Select(u => u.ToSummary(roles.GetValueOrDefault(u.Id, []))).ToList();
        return new PagedResult<AccountSummary>(summaries, page, pageSize, total);
    }

    public async Task<AccountSummary?> GetAsync(Guid userId, bool includeDeleted = false, CancellationToken cancellationToken = default)
    {
        var user = await LoadAsync(userId, includeDeleted, cancellationToken);
        if (user is null) return null;
        var roles = await RolesForAsync([user.Id], cancellationToken);
        return user.ToSummary(roles.GetValueOrDefault(user.Id, []));
    }

    public async Task<IReadOnlyList<AccountSummary>> GetManyAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default)
    {
        var ids = userIds.Distinct().Take(200).ToList();
        var items = await db.Users.AsNoTracking().Where(u => ids.Contains(u.Id)).ToListAsync(cancellationToken);
        var roles = await RolesForAsync(ids, cancellationToken);
        return items.Select(u => u.ToSummary(roles.GetValueOrDefault(u.Id, []))).ToList();
    }

    public async Task<IReadOnlyList<AccountSummary>> ListSuperAdminsAsync(CancellationToken cancellationToken = default)
    {
        var admins = await users.GetUsersInRoleAsync(AuthRoles.SuperAdmin);
        return admins.OrderBy(u => u.FullName).Select(u => u.ToSummary([AuthRoles.SuperAdmin])).ToList();
    }

    public async Task<Result<AccountSummary>> WarnAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default)
    {
        var target = await TargetAsync(userId, cancellationToken);
        if (!target.Succeeded) return target.Error!;
        var user = target.Value;

        user.WarningCount++;
        user.StatusReason = change.Reason;
        label.Set(AuditActions.Warned, change.Reason);
        return await SaveAndNotifyAsync(user, "warn", change, cancellationToken);
    }

    public async Task<Result<AccountSummary>> SuspendAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default)
    {
        if (change.Until is not { } until || until <= time.GetUtcNow()) return new Error(ErrorCodes.ValidationFailed);
        var target = await TargetAsync(userId, cancellationToken);
        if (!target.Succeeded) return target.Error!;
        var user = target.Value;
        if (user.Status == AccountStatus.Banned) return new Error(ErrorCodes.NotAllowed);

        user.Status = AccountStatus.Suspended;
        user.SuspendedUntil = until;
        user.StatusReason = change.Reason;
        label.Set(AuditActions.Suspended, change.Reason);
        return await SaveAndNotifyAsync(user, "suspend", change, cancellationToken, endSessions: true);
    }

    public async Task<Result<AccountSummary>> BanAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default)
    {
        var target = await TargetAsync(userId, cancellationToken);
        if (!target.Succeeded) return target.Error!;
        var user = target.Value;

        user.Status = AccountStatus.Banned;
        user.SuspendedUntil = null;
        user.StatusReason = change.Reason;

        // The same email or phone may not register again.
        if (!string.IsNullOrEmpty(user.NormalizedEmail) &&
            !await bans.AnyAsync(b => b.Kind == BanKind.Email && b.Value == user.NormalizedEmail, cancellationToken))
            bans.Add(new BannedIdentifier { Kind = BanKind.Email, Value = user.NormalizedEmail, UserId = user.Id, Reason = change.Reason });
        if (!string.IsNullOrEmpty(user.NormalizedPhone) &&
            !await bans.AnyAsync(b => b.Kind == BanKind.Phone && b.Value == user.NormalizedPhone, cancellationToken))
            bans.Add(new BannedIdentifier { Kind = BanKind.Phone, Value = user.NormalizedPhone, UserId = user.Id, Reason = change.Reason });

        label.Set(AuditActions.Banned, change.Reason);
        return await SaveAndNotifyAsync(user, "ban", change, cancellationToken, endSessions: true);
    }

    public async Task<Result<AccountSummary>> ReinstateAsync(Guid userId, StatusChange change, CancellationToken cancellationToken = default)
    {
        var target = await TargetAsync(userId, cancellationToken);
        if (!target.Succeeded) return target.Error!;
        var user = target.Value;

        user.Status = AccountStatus.Active;
        user.SuspendedUntil = null;
        user.StatusReason = change.Reason;
        user.LockoutEnd = null;
        foreach (var ban in await bans.ListAsync(b => b.UserId == user.Id, cancellationToken)) bans.Remove(ban);

        label.Set(AuditActions.Reinstated, change.Reason);
        return await SaveAndNotifyAsync(user, "reinstate", change, cancellationToken);
    }

    public async Task<Result> SoftDeleteAsync(Guid userId, string reason, CancellationToken cancellationToken = default)
    {
        var target = await TargetAsync(userId, cancellationToken);
        if (!target.Succeeded) return target.Error!;
        var user = target.Value;

        user.SecurityStamp = Guid.NewGuid().ToString("N");
        label.Set(AuditActions.Deleted, reason);
        db.Users.Remove(user);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }

    public async Task<Result<AccountSummary>> RestoreAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await LoadAsync(userId, includeDeleted: true, cancellationToken);
        if (user is null) return new Error(ErrorCodes.NotFound);
        if (!user.IsDeleted) return await GetAsync(userId, cancellationToken: cancellationToken) is { } summary ? summary : new Error(ErrorCodes.NotFound);

        user.IsDeleted = false;
        user.DeletedAt = null;
        label.Set(AuditActions.Restored);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        var roles = await RolesForAsync([user.Id], cancellationToken);
        return user.ToSummary(roles.GetValueOrDefault(user.Id, []));
    }

    private async Task<Result<AuthUser>> TargetAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (actor.UserId == userId) return new Error(ErrorCodes.NotAllowed);
        var user = await LoadAsync(userId, includeDeleted: false, cancellationToken);
        return user is null ? new Error(ErrorCodes.NotFound) : user;
    }

    private Task<AuthUser?> LoadAsync(Guid userId, bool includeDeleted, CancellationToken cancellationToken) =>
        (includeDeleted ? db.Users.IgnoreQueryFilters() : db.Users).FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

    private async Task<Result<AccountSummary>> SaveAndNotifyAsync(AuthUser user, string action, StatusChange change, CancellationToken cancellationToken, bool endSessions = false)
    {
        // A new security stamp ends cookie sessions; token requests check the status anyway.
        if (endSessions) user.SecurityStamp = Guid.NewGuid().ToString("N");
        await unitOfWork.SaveChangesAsync(cancellationToken);

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            var message = AuthEmails.StatusChanged(user.PreferredLanguage, user.FullName, action, change.Reason, user.SuspendedUntil);
            try { await email.SendAsync(user.Email, message.Subject, message.Html, cancellationToken); }
            catch (Exception) when (!cancellationToken.IsCancellationRequested) { }
        }

        var roles = await RolesForAsync([user.Id], cancellationToken);
        return user.ToSummary(roles.GetValueOrDefault(user.Id, []));
    }

    private async Task<Dictionary<Guid, List<string>>> RolesForAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken)
    {
        var ids = userIds.ToList();
        var rows = await (from userRole in db.UserRoles
                          join role in db.Roles on userRole.RoleId equals role.Id
                          where ids.Contains(userRole.UserId)
                          select new { userRole.UserId, role.Name })
                         .ToListAsync(cancellationToken);
        return rows.GroupBy(r => r.UserId).ToDictionary(g => g.Key, g => g.Select(r => r.Name ?? string.Empty).ToList());
    }
}
