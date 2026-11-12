using System.Linq.Expressions;

namespace Mal3abi.Auth.Core.Common;

public interface IRepository<T> where T : class, IEntity
{
    Task<T?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<T?> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<T>> ListAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default);
    Task<bool> AnyAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default);
    Task<int> CountAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default);
    Task<PagedResult<T>> PageAsync(IQueryable<T> query, int page, int pageSize, CancellationToken cancellationToken = default);

    IQueryable<T> Query();

    IQueryable<T> QueryNoTracking();

    IQueryable<T> QueryIncludingDeleted();

    void Add(T entity);
    void Update(T entity);

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

public interface ICurrentActor
{
    Guid? UserId { get; }
    string Name { get; }
    string? IpAddress { get; }
}
