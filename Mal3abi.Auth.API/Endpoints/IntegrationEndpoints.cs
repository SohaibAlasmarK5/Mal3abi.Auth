using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.API.Endpoints;

/// <summary>
/// Server-to-server API for Mal3abi.BE, protected by X-Mal3abi-Integration-Key. The routes and
/// JSON shapes of the first six endpoints are the ones BE's AuthCenterClient already calls.
/// BE may name the admin acting with X-Mal3abi-Actor-Id, for the audit log.
/// </summary>
public static class IntegrationEndpoints
{
    public static void MapIntegrationEndpoints(this IEndpointRouteBuilder app)
    {
        var integration = app.MapGroup("/api/integration").WithTags("Integration")
            .AddEndpointFilter<IntegrationKeyFilter>();

        integration.MapGet("/accounts", async (string? role, string? q, IAccountAdminService service, CancellationToken ct) =>
            Results.Ok((await service.ListAsync(new AccountQuery(role, q, PageSize: 200), ct)).Items));

        integration.MapGet("/accounts/superadmins", async (IAccountAdminService service, CancellationToken ct) =>
            Results.Ok(await service.ListSuperAdminsAsync(ct)));

        integration.MapGet("/accounts/{id:guid}", async (Guid id, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            await service.GetAsync(id, cancellationToken: ct) is { } account ? Results.Ok(account) : context.Problem(ErrorCodes.NotFound));

        integration.MapPost("/profiles", async (ProfileLookupRequest request, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            request.UserIds.Count > 200
                ? context.Problem(ErrorCodes.ValidationFailed)
                : Results.Ok(await service.GetManyAsync(request.UserIds, ct)));

        integration.MapPost("/accounts/owners", (InviteRequest request, HttpContext context, IAccountService accounts, IConfiguration configuration, CancellationToken ct) =>
            AdminEndpoints.InviteAsync(request, AuthRoles.Owner, context, accounts, configuration, ct)).Validate<InviteRequest>();

        integration.MapPost("/accounts/superadmins", (InviteRequest request, HttpContext context, IAccountService accounts, IConfiguration configuration, CancellationToken ct) =>
            AdminEndpoints.InviteAsync(request, AuthRoles.SuperAdmin, context, accounts, configuration, ct)).Validate<InviteRequest>();

        // New: BE applies no-show penalties (reference section 9) through these.
        AdminEndpoints.MapStatusActions(integration);
    }
}
