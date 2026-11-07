#nullable enable
using System.Security.Cryptography;
using System.Text;
using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Mvc;

namespace Mal3abi.Auth.API.Controllers;

[ApiController]
[Route("api/integration")]
public sealed class BackendIntegrationController(
    IAuthAccountService accounts,
    IConfiguration configuration,
    IWebHostEnvironment environment) : ControllerBase
{
    private const string SecretHeader = "X-Mal3abi-Integration-Key";

    [HttpGet("accounts")]
    public async Task<IActionResult> Accounts([FromQuery] string? role, [FromQuery] string? q, CancellationToken cancellationToken)
    {
        if (!HasValidSecret()) return Unauthorized();
        var rows = await accounts.ListAccountsAsync(cancellationToken);
        if (!string.IsNullOrWhiteSpace(role)) rows = rows.Where(account => string.Equals(account.Role, role, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (!string.IsNullOrWhiteSpace(q)) rows = rows.Where(account => string.Join(" ", account.Name, account.Username, account.Email, account.Phone).Contains(q, StringComparison.OrdinalIgnoreCase)).ToArray();
        return Ok(rows);
    }

    [HttpGet("accounts/{id:guid}")]
    public async Task<IActionResult> Account(Guid id, CancellationToken cancellationToken)
    {
        if (!HasValidSecret()) return Unauthorized();
        var account = await accounts.GetProfileAsync(id, cancellationToken);
        return account is null ? NotFound() : Ok(account);
    }

    [HttpGet("accounts/superadmins")]
    public async Task<IActionResult> SuperAdmins(CancellationToken cancellationToken)
    {
        if (!HasValidSecret()) return Unauthorized();
        return Ok(await accounts.ListSuperAdminsAsync(cancellationToken));
    }

    [HttpPost("profiles")]
    public async Task<IActionResult> Profiles(ProfileLookupRequest request, CancellationToken cancellationToken)
    {
        if (!HasValidSecret()) return Unauthorized();
        if (request.UserIds is null || request.UserIds.Count > 200) return BadRequest(new { message = "Request up to 200 user IDs at a time." });
        var result = new List<AccountSummary>(request.UserIds.Count);
        foreach (var id in request.UserIds.Distinct())
        {
            var account = await accounts.GetProfileAsync(id, cancellationToken);
            if (account is not null) result.Add(account);
        }
        return Ok(result);
    }

    [HttpPost("accounts/owners")]
    public Task<IActionResult> InviteOwner(InviteAccountRequest request, CancellationToken cancellationToken) =>
        Invite(request, superAdmin: false, cancellationToken);

    [HttpPost("accounts/superadmins")]
    public Task<IActionResult> InviteSuperAdmin(InviteAccountRequest request, CancellationToken cancellationToken) =>
        Invite(request, superAdmin: true, cancellationToken);

    private async Task<IActionResult> Invite(InviteAccountRequest request, bool superAdmin, CancellationToken cancellationToken)
    {
        if (!HasValidSecret()) return Unauthorized();
        var origin = configuration["Authentication:PublicOrigin"] ?? "https://localhost:44493";
        var invitation = new AccountInvitation(request.Name, request.Username, request.Email, request.Phone, request.Age, request.PhotoUrl);
        var result = superAdmin
            ? await accounts.InviteSuperAdminAsync(invitation, origin, cancellationToken)
            : await accounts.InviteOwnerAsync(invitation, origin, cancellationToken);
        return result.Succeeded ? Accepted(new { message = "Invitation sent." }) : BadRequest(new { message = result.Error });
    }

    private bool HasValidSecret()
    {
        var expected = configuration["Authentication:BackendIntegrationSecret"];
        if (string.IsNullOrWhiteSpace(expected) && environment.IsDevelopment())
            expected = configuration["Authentication:ClientSecret"];
        var supplied = Request.Headers[SecretHeader].ToString();
        return !string.IsNullOrWhiteSpace(expected) && !string.IsNullOrWhiteSpace(supplied) &&
            CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(supplied));
    }

    public sealed class ProfileLookupRequest
    {
        public List<Guid> UserIds { get; set; } = [];
    }

    public sealed class InviteAccountRequest
    {
        [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.MaxLength(120)]
        public string Name { get; set; } = string.Empty;
        [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.MinLength(3), System.ComponentModel.DataAnnotations.MaxLength(32), System.ComponentModel.DataAnnotations.RegularExpression("^[A-Za-z0-9_.-]+$")]
        public string Username { get; set; } = string.Empty;
        [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.EmailAddress, System.ComponentModel.DataAnnotations.MaxLength(256)]
        public string Email { get; set; } = string.Empty;
        [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.Phone]
        public string Phone { get; set; } = string.Empty;
        [System.ComponentModel.DataAnnotations.Range(18, 120)]
        public int Age { get; set; }
        [System.ComponentModel.DataAnnotations.Url, System.ComponentModel.DataAnnotations.MaxLength(2048)]
        public string? PhotoUrl { get; set; }
    }
}