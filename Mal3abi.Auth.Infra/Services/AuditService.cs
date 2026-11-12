using System.Text.Json;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Common;
using Microsoft.EntityFrameworkCore;

namespace Mal3abi.Auth.Infra.Services;

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
        if (query.EntityId is { } entityId) rows = rows.Where(e => e.EntityId == entityId.ToString());
        if (query.ActorId is { } actorId) rows = rows.Where(e => e.ActorId == actorId);
        if (!string.IsNullOrWhiteSpace(query.Action)) rows = rows.Where(e => e.Action.StartsWith(query.Action));
        if (query.From is { } from) rows = rows.Where(e => e.CreatedAt >= from);
        if (query.To is { } to) rows = rows.Where(e => e.CreatedAt <= to);

        var page = await entries.PageAsync(rows.OrderByDescending(e => e.CreatedAt), query.Page, query.PageSize, cancellationToken);
        return page.Map(e => new AuditEntryView(e.Id, e.CreatedAt, e.ActorId, e.ActorName, e.IpAddress, e.Action, e.EntityType, e.EntityId, e.Before, e.After, e.Note));
    }
}
