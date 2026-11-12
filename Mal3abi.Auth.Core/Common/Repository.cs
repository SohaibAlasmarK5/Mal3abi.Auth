using System.Linq.Expressions;

namespace Mal3abi.Auth.Core.Common;

/// <summary>
/// Generic repository over one entity type. It covers what every table needs; a specific
/// repository is added only when a query does not fit here. Changes are saved through
/// <see cref="IUnitOfWork"/>, once per operation.
/// </summary>
public interface IRepository<T> where T : class, IEntity
{
    Task<T?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<T?> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<T>> ListAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default);
    Task<bool> AnyAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default);
    Task<int> CountAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default);
    Task<PagedResult<T>> PageAsync(IQueryable<T> query, int page, int pageSize, CancellationToken cancellationToken = default);

    /// <summary>Tracked query for filters, ordering and paging in services.</summary>
    IQueryable<T> Query();

    /// <summary>Read-only query (no change tracking).</summary>
    IQueryable<T> QueryNoTracking();

    /// <summary>Includes soft-deleted rows, for admins and restore.</summary>
    IQueryable<T> QueryIncludingDeleted();

    void Add(T entity);
    void Update(T entity);

    /// <summary>Soft delete for <see cref="ISoftDeletable"/> entities, real delete otherwise.</summary>
    void Remove(T entity);
}

public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int Total)
{
    public PagedResult<TOut> Map<TOut>(Func<T, TOut> map) => new(Items.Select(map).ToList(), Page, PageSize, Total);
}

/// <summary>Who is acting, for the audit log: a signed-in user, Mal3abi.BE, or the system.</summary>
public interface ICurrentActor
{
    Guid? UserId { get; }
    string Name { get; }
    string? IpAddress { get; }
}
