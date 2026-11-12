using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Bans;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.Core.Services;

public sealed class AccountAdminService(
    IAccountRepository accounts,
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
        var page = await accounts.SearchAsync(query, cancellationToken);
        var roles = await accounts.GetRolesAsync(page.Items.Select(u => u.Id).ToList(), cancellationToken);
        return page.Map(u => u.ToSummary(RolesOf(roles, u.Id)));
    }

    public async Task<AccountSummary?> GetAsync(Guid userId, bool includeDeleted = false, CancellationToken cancellationToken = default)
    {
        var user = await accounts.FindAsync(userId, includeDeleted, cancellationToken);
        return user is null ? null : await SummaryAsync(user, cancellationToken);
    }

    public async Task<IReadOnlyList<AccountSummary>> GetManyAsync(IEnumerable<Guid> userIds, CancellationToken cancellationToken = default)
    {
        var ids = userIds.Distinct().Take(200).ToList();
        var items = await accounts.GetManyAsync(ids, cancellationToken);
        var roles = await accounts.GetRolesAsync(ids, cancellationToken);
        return items.Select(u => u.ToSummary(RolesOf(roles, u.Id))).ToList();
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
        accounts.Remove(user);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }

    public async Task<Result<AccountSummary>> RestoreAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await accounts.FindAsync(userId, includeDeleted: true, cancellationToken);
        if (user is null) return new Error(ErrorCodes.NotFound);

        if (user.IsDeleted)
        {
            user.IsDeleted = false;
            user.DeletedAt = null;
            label.Set(AuditActions.Restored);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        return await SummaryAsync(user, cancellationToken);
    }

    private async Task<Result<AuthUser>> TargetAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (actor.UserId == userId) return new Error(ErrorCodes.NotAllowed);
        var user = await accounts.FindAsync(userId, includeDeleted: false, cancellationToken);
        return user is null ? new Error(ErrorCodes.NotFound) : user;
    }

    private async Task<Result<AccountSummary>> SaveAndNotifyAsync(AuthUser user, string action, StatusChange change, CancellationToken cancellationToken, bool endSessions = false)
    {
        if (endSessions) user.SecurityStamp = Guid.NewGuid().ToString("N");
        await unitOfWork.SaveChangesAsync(cancellationToken);

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            var message = AuthEmails.StatusChanged(user.PreferredLanguage, user.FullName, action, change.Reason, user.SuspendedUntil);
            try { await email.SendAsync(user.Email, message.Subject, message.Html, cancellationToken); }
            catch (Exception) when (!cancellationToken.IsCancellationRequested) { }
        }

        return await SummaryAsync(user, cancellationToken);
    }

    private async Task<AccountSummary> SummaryAsync(AuthUser user, CancellationToken cancellationToken)
    {
        var roles = await accounts.GetRolesAsync([user.Id], cancellationToken);
        return user.ToSummary(RolesOf(roles, user.Id));
    }

    private static IReadOnlyList<string> RolesOf(IReadOnlyDictionary<Guid, IReadOnlyList<string>> roles, Guid userId) =>
        roles.TryGetValue(userId, out var list) ? list : [];
}
