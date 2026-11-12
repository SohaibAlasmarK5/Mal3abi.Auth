using System.Text.Json;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.Core.Services;

public sealed class AuditService(IRepository<AuditEntry> entries, IUnitOfWork unitOfWork, ICurrentActor actor, TimeProvider time) : IAuditService
{
    public async Task RecordAsync(string action, string entityType, string? entityId, object? before = null, object? after = null, string? note = null, CancellationToken cancellationToken = default)
    {
        entries.Add(new AuditEntry
        {
            CreatedAt = time.GetUtcNow(),
            ActorId = actor.UserId,
            ActorName = actor.Name,
            IpAddress = actor.IpAddress,
            Action = action,
            EntityType = entityType,
            EntityId = entityId,
            Before = before is null ? null : JsonSerializer.Serialize(before),
            After = after is null ? null : JsonSerializer.Serialize(after),
            Note = note is { Length: > 1000 } ? note[..1000] : note,
        });
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task<PagedResult<AuditEntryView>> SearchAsync(AuditQuery query, CancellationToken cancellationToken = default)
    {
        var rows = entries.QueryNoTracking();
        if (query.EntityId?.ToString() is { } entityId) rows = rows.Where(e => e.EntityId == entityId);
        if (query.ActorId is { } actorId) rows = rows.Where(e => e.ActorId == actorId);
        if (query.Action is { Length: > 0 } action) rows = rows.Where(e => e.Action.StartsWith(action));
        if (query.From is { } from) rows = rows.Where(e => e.CreatedAt >= from);
        if (query.To is { } to) rows = rows.Where(e => e.CreatedAt <= to);

        var page = await entries.PageAsync(rows.OrderByDescending(e => e.CreatedAt), query.Page, query.PageSize, cancellationToken);
        return page.Map(e => new AuditEntryView(e.Id, e.CreatedAt, e.ActorId, e.ActorName, e.IpAddress, e.Action, e.EntityType, e.EntityId, e.Before, e.After, e.Note));
    }
}
