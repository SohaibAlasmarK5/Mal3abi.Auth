using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Accounts;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Antiforgery;

namespace Mal3abi.Auth.API.Endpoints;

public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/accounts").WithTags("Accounts").RequireRateLimiting(RateLimits.Accounts);

        group.MapGet("/csrf", (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Ok(new { token = tokens.RequestToken, header = "X-CSRF-TOKEN" });
        });

        group.MapPost("/register", async (RegisterRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
        {
            var result = await accounts.RegisterAsync(new RegisterAccount(
                request.Name, request.Username, request.Email, request.Phone, request.Age ?? 0, request.PhotoUrl,
                request.Password, request.Role ?? "player", AuthUi.For(context.Request).Lang), ct);
            return result.Succeeded
                ? Results.Accepted(value: new { userId = result.Value.Id, email = result.Value.Email, next = "confirm_email" })
                : result.Error!.Problem(context);
        }).Validate<RegisterRequest>();

        group.MapPost("/email/resend", async (EmailRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.SendConfirmationCodeAsync(request.Email, ct)).ToHttp(context)).Validate<EmailRequest>();

        group.MapPost("/email/confirm", async (ConfirmEmailRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
        {
            var result = await accounts.ConfirmEmailAsync(request.Email, request.Code, ct);
            return result.Succeeded ? Results.NoContent() : result.Error!.Problem(context);
        }).Validate<ConfirmEmailRequest>();

        group.MapPost("/password/forgot", async (EmailRequest request, HttpContext context, IAccountService accounts, IConfiguration configuration, CancellationToken ct) =>
            (await accounts.SendPasswordResetAsync(request.Email, PublicUrl(context, configuration, "/account/reset-password"), ct)).ToHttp(context))
            .Validate<EmailRequest>();

        group.MapPost("/password/reset", async (ResetPasswordRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.ResetPasswordAsync(request.UserId, request.Token, request.Password, ct)).ToHttp(context))
            .Validate<ResetPasswordRequest>();

        MapMe(group.MapGroup("/me").RequireAuthorization(Policies.Account).AddEndpointFilter<CsrfFilter>());
    }

    private static void MapMe(RouteGroupBuilder me)
    {
        me.MapGet("/", async (HttpContext context, IAccountService accounts, CancellationToken ct) =>
            await accounts.GetSummaryAsync(UserId(context), ct) is { } summary ? Results.Ok(summary) : context.Problem(ErrorCodes.NotFound));

        me.MapPut("/", async (ProfileRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.UpdateProfileAsync(UserId(context), new ProfileUpdate(request.Name, request.Username, request.Phone, request.Age ?? 0, request.PhotoUrl), ct)).ToHttp(context))
            .Validate<ProfileRequest>();

        me.MapPut("/language", async (LanguageRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.SetLanguageAsync(UserId(context), request.Language, ct)).ToHttp(context));

        me.MapPost("/email", async (EmailRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
        {
            var result = await accounts.StartEmailChangeAsync(UserId(context), request.Email, ct);
            return result.Succeeded ? Results.Accepted(value: new { next = "confirm_new_email" }) : result.Error!.Problem(context);
        }).Validate<EmailRequest>();

        me.MapPost("/email/confirm", async (CodeRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.ConfirmEmailChangeAsync(UserId(context), request.Code, ct)).ToHttp(context)).Validate<CodeRequest>();

        me.MapPost("/password", async (ChangePasswordRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.ChangePasswordAsync(UserId(context), request.CurrentPassword, request.NewPassword, ct)).ToHttp(context))
            .Validate<ChangePasswordRequest>();

        me.MapGet("/two-factor", async (HttpContext context, IAccountService accounts, ITwoFactorService twoFactor) =>
        {
            var user = await accounts.FindAsync(UserId(context));
            if (user is null) return context.Problem(ErrorCodes.NotFound);
            var required = await twoFactor.RequiredMethodAsync(user);
            return Results.Ok(new
            {
                method = user.TwoFactorMethod.ToString().ToLowerInvariant(),
                required = required.ToString().ToLowerInvariant(),
                canChange = (await accounts.GetRolesAsync(user)).All(r => r == AuthRoles.Player),
            });
        });

        me.MapPut("/two-factor/email", async (ToggleRequest request, HttpContext context, IAccountService accounts, ITwoFactorService twoFactor, CancellationToken ct) =>
        {
            var user = await accounts.FindAsync(UserId(context), ct);
            return user is null ? context.Problem(ErrorCodes.NotFound) : (await twoFactor.SetEmailTwoFactorAsync(user, request.Enabled, ct)).ToHttp(context);
        });

        me.MapPost("/two-factor/authenticator/setup", async (HttpContext context, IAccountService accounts, ITwoFactorService twoFactor, IConfiguration configuration) =>
        {
            var user = await accounts.FindAsync(UserId(context));
            if (user is null) return context.Problem(ErrorCodes.NotFound);
            return Results.Ok(await twoFactor.GetAuthenticatorSetupAsync(user, configuration["Authentication:AuthenticatorIssuer"] ?? "Mal3abi"));
        });

        me.MapPost("/two-factor/authenticator/enable", async (CodeRequest request, HttpContext context, IAccountService accounts, ITwoFactorService twoFactor, CancellationToken ct) =>
        {
            var user = await accounts.FindAsync(UserId(context), ct);
            return user is null ? context.Problem(ErrorCodes.NotFound) : (await twoFactor.EnableAuthenticatorAsync(user, request.Code, ct)).ToHttp(context);
        }).Validate<CodeRequest>();

        me.MapDelete("/", async ([Microsoft.AspNetCore.Mvc.FromBody] PasswordRequest request, HttpContext context, IAccountService accounts, CancellationToken ct) =>
            (await accounts.DeleteOwnAccountAsync(UserId(context), request.Password, ct)).ToHttp(context)).Validate<PasswordRequest>();
    }

    public static Guid UserId(HttpContext context) =>
        context.User.GetUserId() ?? throw new InvalidOperationException("The endpoint requires a signed-in user.");

    public static string PublicUrl(HttpContext context, IConfiguration configuration, string path) =>
        (configuration["Authentication:PublicOrigin"] ?? $"{context.Request.Scheme}://{context.Request.Host}").TrimEnd('/') + path;
}
