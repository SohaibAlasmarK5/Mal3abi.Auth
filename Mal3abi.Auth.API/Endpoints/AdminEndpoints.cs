using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Audit;
using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.API.Endpoints;

/// <summary>
/// Super admin API (/api/admin): accounts, invitations, penalties, hiding and restoring, and
/// the audit log. Requires the superadmin role and a two-step session.
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/admin").WithTags("Admin")
            .RequireAuthorization(Policies.SuperAdmin)
            .AddEndpointFilter<CsrfFilter>();

        admin.MapGet("/accounts", async (string? role, string? q, string? status, bool? includeDeleted, int? page, int? pageSize, IAccountAdminService service, CancellationToken ct) =>
            Results.Ok(await service.ListAsync(new AccountQuery(role, q, status, includeDeleted ?? false, page ?? 1, pageSize ?? 25), ct)));

        admin.MapGet("/accounts/{id:guid}", async (Guid id, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            await service.GetAsync(id, includeDeleted: true, ct) is { } account ? Results.Ok(account) : context.Problem(ErrorCodes.NotFound));

        admin.MapPost("/accounts/owners", (InviteRequest request, HttpContext context, IAccountService accounts, IConfiguration configuration, CancellationToken ct) =>
            InviteAsync(request, AuthRoles.Owner, context, accounts, configuration, ct)).Validate<InviteRequest>();

        admin.MapPost("/accounts/superadmins", (InviteRequest request, HttpContext context, IAccountService accounts, IConfiguration configuration, CancellationToken ct) =>
            InviteAsync(request, AuthRoles.SuperAdmin, context, accounts, configuration, ct)).Validate<InviteRequest>();

        MapStatusActions(admin);

        admin.MapDelete("/accounts/{id:guid}", async (Guid id, string? reason, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            (await service.SoftDeleteAsync(id, reason ?? string.Empty, ct)).ToHttp(context));

        admin.MapPost("/accounts/{id:guid}/restore", async (Guid id, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            (await service.RestoreAsync(id, ct)).ToHttp(context));

        admin.MapGet("/audit", async (Guid? entityId, Guid? actorId, string? action, DateTimeOffset? from, DateTimeOffset? to, int? page, int? pageSize, IAuditService audit, CancellationToken ct) =>
            Results.Ok(await audit.SearchAsync(new AuditQuery(entityId, actorId, action, from, to, page ?? 1, pageSize ?? 50), ct)));
    }

    /// <summary>warn, suspend, ban and reinstate; shared with the integration API.</summary>
    public static void MapStatusActions(RouteGroupBuilder group)
    {
        group.MapPost("/accounts/{id:guid}/warn", async (Guid id, StatusRequest request, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            (await service.WarnAsync(id, new StatusChange(request.Reason), ct)).ToHttp(context)).Validate<StatusRequest>();

        group.MapPost("/accounts/{id:guid}/suspend", async (Guid id, StatusRequest request, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
        {
            if (request.Until is null)
            {
                var errors = new FieldErrors(AuthUi.For(context.Request));
                errors.Add(nameof(StatusRequest.Until), AuthUi.For(context.Request).T("field.required", AuthUi.For(context.Request).T("admin.until")));
                return errors.Problem(context);
            }
            return (await service.SuspendAsync(id, new StatusChange(request.Reason, request.Until), ct)).ToHttp(context);
        }).Validate<StatusRequest>();

        group.MapPost("/accounts/{id:guid}/ban", async (Guid id, StatusRequest request, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            (await service.BanAsync(id, new StatusChange(request.Reason), ct)).ToHttp(context)).Validate<StatusRequest>();

        group.MapPost("/accounts/{id:guid}/reinstate", async (Guid id, StatusRequest request, HttpContext context, IAccountAdminService service, CancellationToken ct) =>
            (await service.ReinstateAsync(id, new StatusChange(request.Reason), ct)).ToHttp(context)).Validate<StatusRequest>();
    }

    public static async Task<IResult> InviteAsync(InviteRequest request, string role, HttpContext context, IAccountService accounts, IConfiguration configuration, CancellationToken ct)
    {
        var invitation = new AccountInvitation(request.Name, request.Username, request.Email, request.Phone, request.Age ?? 0, request.PhotoUrl,
            request.Language ?? AuthUi.For(context.Request).Lang);
        var result = await accounts.InviteAsync(invitation, role, AccountEndpoints.PublicUrl(context, configuration, "/account/accept-invitation"), ct);
        return result.Succeeded
            ? Results.Accepted(value: new { message = "Invitation sent.", account = result.Value })
            : result.Error!.Problem(context);
    }
}
