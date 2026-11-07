using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Mal3abi.Auth.Infra.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options)
    : IdentityDbContext<AuthUser, IdentityRole<Guid>, Guid>(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.UseOpenIddict<Guid>();
        modelBuilder.Entity<AuthUser>().Property(user => user.FullName).IsRequired();
        modelBuilder.Entity<AuthUser>().Property(user => user.PhotoUrl).HasMaxLength(2048);
        modelBuilder.Entity<AuthUser>().HasIndex(user => user.NormalizedEmail)
            .IsUnique().HasDatabaseName("EmailIndex").HasFilter("[NormalizedEmail] IS NOT NULL");
    }
}