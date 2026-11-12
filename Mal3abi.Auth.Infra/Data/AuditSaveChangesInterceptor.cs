using System.Reflection;
using System.Text.Json;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Mal3abi.Auth.Infra.Data;

/// <summary>
/// One place for the rules every table follows:
/// fills CreatedAt and UpdatedAt, turns deletes of soft-deletable rows into hiding, and writes
/// an audit row (before and after) for every change to an [Audited] entity or a role assignment.
/// </summary>
public sealed class AuditSaveChangesInterceptor(ICurrentActor actor, TimeProvider time, Services.AuditLabel label) : SaveChangesInterceptor
{
    // Values that change on their own or must never be copied into the log.
    private static readonly HashSet<string> IgnoredProperties =
    [
        "ConcurrencyStamp", "SecurityStamp", "AccessFailedCount", "UpdatedAt", "CreatedAt", "LastSignInAt",
        "NormalizedEmail", "NormalizedUserName", "NormalizedPhone",
    ];

    private static readonly HashSet<string> SecretProperties = ["PasswordHash", "CodeHash"];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is not null) Apply(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        if (eventData.Context is not null) Apply(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    private void Apply(DbContext context)
    {
        var now = time.GetUtcNow();
        var entries = context.ChangeTracker.Entries().ToList();
        var audit = new List<AuditEntry>();

        foreach (var entry in entries)
        {
            if (entry.Entity is AuditEntry) continue;

            var softDelete = false;
            if (entry.State == EntityState.Deleted && entry.Entity is ISoftDeletable deletable)
            {
                entry.State = EntityState.Modified;
                deletable.IsDeleted = true;
                deletable.DeletedAt = now;
                softDelete = true;
            }

            if (entry.Entity is IAuditable auditable)
            {
                if (entry.State == EntityState.Added && auditable.CreatedAt == default) auditable.CreatedAt = now;
                if (entry.State == EntityState.Modified) auditable.UpdatedAt = now;
            }

            var row = ToAuditEntry(entry, softDelete, now);
            if (row is not null) audit.Add(row);
        }

        // A service may have named this save (for example "account.suspended" with the reason).
        if (label.Action is not null)
        {
            var account = audit.FirstOrDefault(a => a.EntityType == "AuthUser" && a.Action != "account.added");
            if (account is not null)
            {
                account.Action = label.Action;
                account.Note = label.Note;
                label.Clear();
            }
        }

        if (audit.Count > 0) context.Set<AuditEntry>().AddRange(audit);
    }

    private AuditEntry? ToAuditEntry(EntityEntry entry, bool softDelete, DateTimeOffset now)
    {
        var type = entry.Entity.GetType();
        var isRole = entry.Entity is IdentityUserRole<Guid>;
        if (!isRole && type.GetCustomAttribute<AuditedAttribute>() is null) return null;
        if (entry.State is not (EntityState.Added or EntityState.Modified or EntityState.Deleted)) return null;

        Dictionary<string, object?>? before = null;
        Dictionary<string, object?>? after = null;

        foreach (var property in entry.Properties)
        {
            var name = property.Metadata.Name;
            if (IgnoredProperties.Contains(name)) continue;
            var secret = SecretProperties.Contains(name);

            switch (entry.State)
            {
                case EntityState.Added:
                    (after ??= [])[name] = secret ? "(set)" : property.CurrentValue;
                    break;
                case EntityState.Deleted:
                    (before ??= [])[name] = secret ? "(set)" : property.OriginalValue;
                    break;
                case EntityState.Modified when property.IsModified && !Equals(property.OriginalValue, property.CurrentValue):
                    (before ??= [])[name] = secret ? "(old)" : property.OriginalValue;
                    (after ??= [])[name] = secret ? "(new)" : property.CurrentValue;
                    break;
            }
        }

        if (before is null && after is null) return null;

        string entityName;
        string? entityId;
        if (entry.Entity is IdentityUserRole<Guid> role)
        {
            entityName = "UserRole";
            entityId = role.UserId.ToString();
        }
        else
        {
            entityName = type.Name;
            entityId = (entry.Entity as IEntity)?.Id.ToString();
        }

        var verb = softDelete ? "deleted" : entry.State switch
        {
            EntityState.Added => "added",
            EntityState.Deleted => "removed",
            _ => "updated",
        };

        return new AuditEntry
        {
            CreatedAt = now,
            ActorId = actor.UserId,
            ActorName = actor.Name,
            IpAddress = actor.IpAddress,
            Action = $"{Short(entityName)}.{verb}",
            EntityType = entityName,
            EntityId = entityId,
            Before = before is null ? null : JsonSerializer.Serialize(before, Json),
            After = after is null ? null : JsonSerializer.Serialize(after, Json),
        };
    }

    private static string Short(string entityName) => entityName switch
    {
        "AuthUser" => "account",
        "UserRole" => "role",
        "BannedIdentifier" => "ban",
        _ => entityName.ToLowerInvariant(),
    };
}
