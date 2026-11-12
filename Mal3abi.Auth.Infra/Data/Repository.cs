using System.Linq.Expressions;
using Mal3abi.Auth.Core.Common;
using Microsoft.EntityFrameworkCore;

namespace Mal3abi.Auth.Infra.Data;

public class Repository<T>(AuthDbContext db) : IRepository<T> where T : class, IEntity
{
    protected AuthDbContext Db { get; } = db;
    protected DbSet<T> Set => Db.Set<T>();

    public Task<T?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        Set.FirstOrDefaultAsync(e => e.Id == id, cancellationToken);

    public Task<T?> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default) =>
        Set.FirstOrDefaultAsync(predicate, cancellationToken);

    public async Task<IReadOnlyList<T>> ListAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default) =>
        predicate is null
            ? await Set.ToListAsync(cancellationToken)
            : await Set.Where(predicate).ToListAsync(cancellationToken);

    public Task<bool> AnyAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default) =>
        Set.AnyAsync(predicate, cancellationToken);

    public Task<int> CountAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default) =>
        predicate is null ? Set.CountAsync(cancellationToken) : Set.CountAsync(predicate, cancellationToken);

    public async Task<PagedResult<T>> PageAsync(IQueryable<T> query, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);
        var total = await query.CountAsync(cancellationToken);
        var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        return new PagedResult<T>(items, page, pageSize, total);
    }

    public IQueryable<T> Query() => Set;
    public IQueryable<T> QueryNoTracking() => Set.AsNoTracking();
    public IQueryable<T> QueryIncludingDeleted() => Set.IgnoreQueryFilters();

    public void Add(T entity) => Set.Add(entity);
    public void Update(T entity) => Set.Update(entity);

    public void Remove(T entity) => Set.Remove(entity);
}

public sealed class UnitOfWork(AuthDbContext db) : IUnitOfWork
{
    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) => db.SaveChangesAsync(cancellationToken);
}
