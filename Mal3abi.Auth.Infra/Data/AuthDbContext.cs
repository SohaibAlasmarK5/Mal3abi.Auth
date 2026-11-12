using System.Linq.Expressions;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Bans;
using Mal3abi.Auth.Core.Codes;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mal3abi.Auth.Infra.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options)
    : IdentityDbContext<AuthUser, IdentityRole<Guid>, Guid>(options)
{
    public DbSet<VerificationCode> VerificationCodes => Set<VerificationCode>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<BannedIdentifier> BannedIdentifiers => Set<BannedIdentifier>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict<Guid>();

        builder.Entity<AuthUser>(user =>
        {
            user.Property(u => u.FullName).HasMaxLength(120).IsRequired();
            user.Property(u => u.PhotoUrl).HasMaxLength(2048);
            user.Property(u => u.PhoneNumber).HasMaxLength(32);
            user.Property(u => u.NormalizedPhone).HasMaxLength(32);
            user.Property(u => u.PreferredLanguage).HasMaxLength(5).HasDefaultValue("ar");
            user.Property(u => u.StatusReason).HasMaxLength(500);
            user.Property(u => u.TwoFactorMethod).HasConversion<string>().HasMaxLength(20);
            user.Property(u => u.Status).HasConversion<string>().HasMaxLength(20);
            user.HasIndex(u => u.NormalizedPhone);
            user.HasIndex(u => new { u.EmailConfirmed, u.CreatedAt });
        });

        builder.Entity<VerificationCode>(code =>
        {
            code.ToTable("VerificationCodes");
            code.Property(c => c.Purpose).HasConversion<string>().HasMaxLength(30);
            code.Property(c => c.CodeHash).HasMaxLength(128).IsRequired();
            code.Property(c => c.SentTo).HasMaxLength(256).IsRequired();
            code.HasIndex(c => new { c.UserId, c.Purpose, c.CreatedAt });
            code.HasOne<AuthUser>().WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<AuditEntry>(entry =>
        {
            entry.ToTable("AuditLog");
            entry.Property(e => e.ActorName).HasMaxLength(256).IsRequired();
            entry.Property(e => e.IpAddress).HasMaxLength(64);
            entry.Property(e => e.Action).HasMaxLength(64).IsRequired();
            entry.Property(e => e.EntityType).HasMaxLength(64).IsRequired();
            entry.Property(e => e.EntityId).HasMaxLength(64);
            entry.Property(e => e.Note).HasMaxLength(1000);
            entry.HasIndex(e => e.CreatedAt);
            entry.HasIndex(e => new { e.EntityId, e.CreatedAt });
            entry.HasIndex(e => new { e.ActorId, e.CreatedAt });
            entry.HasIndex(e => new { e.Action, e.CreatedAt });
        });

        builder.Entity<BannedIdentifier>(ban =>
        {
            ban.ToTable("BannedIdentifiers");
            ban.Property(b => b.Kind).HasConversion<string>().HasMaxLength(10);
            ban.Property(b => b.Value).HasMaxLength(256).IsRequired();
            ban.Property(b => b.Reason).HasMaxLength(500).IsRequired();
            ban.HasIndex(b => new { b.Kind, b.Value });
        });

        foreach (var entityType in builder.Model.GetEntityTypes())
        {
            if (!typeof(ISoftDeletable).IsAssignableFrom(entityType.ClrType)) continue;
            var parameter = Expression.Parameter(entityType.ClrType, "e");
            var filter = Expression.Lambda(
                Expression.Not(Expression.Property(parameter, nameof(ISoftDeletable.IsDeleted))),
                parameter);
            builder.Entity(entityType.ClrType).HasQueryFilter(filter);
        }
    }
}
