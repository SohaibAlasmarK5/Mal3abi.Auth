using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using System;
using System.IO;
using System.Text.Json;

namespace Mal3abi.Auth.Infra.Data;

public sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    private const string UserSecretsId = "5b484e4d-5893-4551-ba7f-d5cc37d99c66";

    public AuthDbContext CreateDbContext(string[] args)
    {
        var secretsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "UserSecrets", UserSecretsId, "secrets.json");
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__AuthCenter")
            ?? ReadConnectionString(secretsPath)
            ?? "Server=(localdb)\\MSSQLLocalDB;Database=Mal3abiAuthCenter;Trusted_Connection=True;TrustServerCertificate=True";
        var options = new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer(connectionString).Options;
        return new AuthDbContext(options);
    }

    private static string? ReadConnectionString(string path)
    {
        if (!File.Exists(path)) return null;
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        return document.RootElement.TryGetProperty("ConnectionStrings", out var connections) &&
            connections.TryGetProperty("AuthCenter", out var value)
                ? value.GetString()
                : null;
    }
}
