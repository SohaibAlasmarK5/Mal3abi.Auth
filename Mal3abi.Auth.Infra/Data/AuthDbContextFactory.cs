using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Mal3abi.Auth.Infra.Data;

public sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("MAL3ABI_AUTH_DESIGN_CONNECTION")
            ?? "Server=localhost;Database=Mal3abiAuth;Trusted_Connection=True;TrustServerCertificate=True";
        var builder = new DbContextOptionsBuilder<AuthDbContext>();
        builder.UseSqlServer(connection);
        builder.UseOpenIddict<Guid>();
        return new AuthDbContext(builder.Options);
    }
}
