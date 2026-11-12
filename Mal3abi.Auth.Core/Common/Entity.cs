namespace Mal3abi.Auth.Core.Common;

public interface IEntity
{
    Guid Id { get; }
}

public interface IAuditable
{
    DateTimeOffset CreatedAt { get; set; }
    DateTimeOffset? UpdatedAt { get; set; }
}

public interface ISoftDeletable
{
    bool IsDeleted { get; set; }
    DateTimeOffset? DeletedAt { get; set; }
}

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
