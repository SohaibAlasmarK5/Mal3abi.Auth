namespace Mal3abi.Auth.Core.Common;

/// <summary>Every stored entity has a Guid key.</summary>
public interface IEntity
{
    Guid Id { get; }
}

/// <summary>CreatedAt and UpdatedAt are filled by the SaveChanges interceptor.</summary>
public interface IAuditable
{
    DateTimeOffset CreatedAt { get; set; }
    DateTimeOffset? UpdatedAt { get; set; }
}

/// <summary>
/// Removing such an entity hides it instead (reference section 16). A global query filter hides
/// rows with IsDeleted, and the interceptor turns a delete into an update.
/// </summary>
public interface ISoftDeletable
{
    bool IsDeleted { get; set; }
    DateTimeOffset? DeletedAt { get; set; }
}

/// <summary>Changes to entities with this attribute are written to the audit log automatically.</summary>
[AttributeUsage(AttributeTargets.Class, Inherited = false)]
public sealed class AuditedAttribute : Attribute;

public abstract class Entity : IEntity, IAuditable
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}

public abstract class SoftDeletableEntity : Entity, ISoftDeletable
{
    public bool IsDeleted { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
}
