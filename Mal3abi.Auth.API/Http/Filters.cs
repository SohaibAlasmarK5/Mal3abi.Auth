using System.Security.Cryptography;
using System.Text;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;

namespace Mal3abi.Auth.API.Http;

/// <summary>Mal3abi.BE calls /api/integration with the shared secret in X-Mal3abi-Integration-Key.</summary>
public sealed class IntegrationKeyFilter(IConfiguration configuration, IHostEnvironment environment) : IEndpointFilter
{
    public const string Header = "X-Mal3abi-Integration-Key";

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var expected = configuration["Authentication:BackendIntegrationSecret"];
        if (string.IsNullOrWhiteSpace(expected) && environment.IsDevelopment())
            expected = configuration["Authentication:ClientSecret"];
        var supplied = context.HttpContext.Request.Headers[Header].ToString();

        var valid = !string.IsNullOrWhiteSpace(expected) && !string.IsNullOrWhiteSpace(supplied) &&
            CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(supplied));
        if (!valid) return context.HttpContext.Problem(ErrorCodes.Unauthorized);

        context.HttpContext.Items[HttpCurrentActor.IntegrationItem] = true;
        return await next(context);
    }
}

/// <summary>
/// Calls that change something and ride on the Auth Center cookie must carry the antiforgery
/// token (X-CSRF-TOKEN, from GET /api/accounts/csrf). Bearer-token calls do not need it.
/// </summary>
public sealed class CsrfFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var unsafeMethod = !(HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method) || HttpMethods.IsOptions(http.Request.Method));
        var cookieSession = http.User.Identity is { IsAuthenticated: true, AuthenticationType: var type } && type == IdentityConstants.ApplicationScheme;
        if (unsafeMethod && cookieSession)
        {
            try
            {
                await antiforgery.ValidateRequestAsync(http);
            }
            catch (AntiforgeryValidationException)
            {
                return http.Problem(ErrorCodes.CsrfInvalid);
            }
        }
        return await next(context);
    }
}

/// <summary>Runs a request's own checks before the handler, so handlers only see valid input.</summary>
public interface IValidatedRequest
{
    void Validate(FieldErrors errors);
}

public sealed class ValidationFilter<T> : IEndpointFilter where T : class, IValidatedRequest
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var request = context.Arguments.OfType<T>().FirstOrDefault();
        if (request is null) return context.HttpContext.Problem(ErrorCodes.ValidationFailed);
        var errors = new FieldErrors(Ui.AuthUi.For(context.HttpContext.Request));
        request.Validate(errors);
        return errors.Any ? errors.Problem(context.HttpContext) : await next(context);
    }
}

public static class EndpointExtensions
{
    public static RouteHandlerBuilder Validate<T>(this RouteHandlerBuilder builder) where T : class, IValidatedRequest =>
        builder.AddEndpointFilter<ValidationFilter<T>>();
}
