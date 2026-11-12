using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Infra.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Mal3abi.Auth.Infra.Jobs;

/// <summary>
/// Every hour: deletes accounts that did not confirm their email within seven days, so the
/// email and username are free again (reference section 16), and old codes.
/// </summary>
public sealed class UnconfirmedAccountCleanup(IServiceScopeFactory scopes, TimeProvider time, ILogger<UnconfirmedAccountCleanup> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        do
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Cleanup of unconfirmed accounts failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var now = time.GetUtcNow();
        var cutoff = now - CodeRules.UnconfirmedAccountLifetime;

        var stale = await db.Users.IgnoreQueryFilters()
            .Where(u => !u.EmailConfirmed && u.CreatedAt < cutoff)
            .Select(u => new { u.Id, u.UserName, u.Email })
            .ToListAsync(cancellationToken);

        if (stale.Count > 0)
        {
            var ids = stale.Select(u => u.Id).ToList();
            // Identity tables and codes are removed by cascade.
            await db.Users.IgnoreQueryFilters().Where(u => ids.Contains(u.Id)).ExecuteDeleteAsync(cancellationToken);
            db.AuditEntries.AddRange(stale.Select(u => new AuditEntry
            {
                CreatedAt = now,
                ActorName = "system",
                Action = AuditActions.PurgedUnconfirmed,
                EntityType = "AuthUser",
                EntityId = u.Id.ToString(),
                Before = System.Text.Json.JsonSerializer.Serialize(new { u.UserName, u.Email }),
                Note = "email not confirmed within 7 days",
            }));
            await db.SaveChangesAsync(cancellationToken);
            logger.LogInformation("Deleted {Count} unconfirmed accounts.", stale.Count);
        }

        await db.VerificationCodes.Where(c => c.CreatedAt < now.AddDays(-2)).ExecuteDeleteAsync(cancellationToken);
        return stale.Count;
    }
}
