using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.API.Http;

public static class ApiResults
{
    public static int StatusFor(string code) => code switch
    {
        ErrorCodes.Unauthorized or ErrorCodes.InvalidCredentials => StatusCodes.Status401Unauthorized,
        ErrorCodes.Forbidden or ErrorCodes.NotAllowed or ErrorCodes.AccountSuspended or ErrorCodes.EmailNotVerified
            or ErrorCodes.TwoFactorRequired => StatusCodes.Status403Forbidden,
        ErrorCodes.NotFound => StatusCodes.Status404NotFound,
        ErrorCodes.EmailTaken or ErrorCodes.UsernameTaken => StatusCodes.Status409Conflict,
        ErrorCodes.LockedOut or ErrorCodes.TwoFactorLocked or ErrorCodes.CodeTooSoon or ErrorCodes.CodeHourlyLimit
            or ErrorCodes.RateLimited => StatusCodes.Status429TooManyRequests,
        ErrorCodes.ServerError => StatusCodes.Status500InternalServerError,
        _ => StatusCodes.Status400BadRequest,
    };

    public static IResult Problem(this Error error, HttpContext context, IDictionary<string, string[]>? fieldErrors = null)
    {
        var ui = AuthUi.For(context.Request);
        var message = ui.Error(error);
        var extensions = new Dictionary<string, object?>
        {
            ["code"] = error.Code,
            ["message"] = message,
        };
        if (fieldErrors is { Count: > 0 }) extensions["errors"] = fieldErrors;
        else if (error.Details is { Count: > 0 }) extensions["errors"] = new Dictionary<string, string[]> { [""] = [.. error.Details] };
        if (error.RetryAfterSeconds is { } retry)
        {
            extensions["retryAfter"] = retry;
            context.Response.Headers.RetryAfter = retry.ToString();
        }
        if (error.Until is { } until) extensions["until"] = until;

        return Results.Problem(statusCode: StatusFor(error.Code), title: error.Code, detail: message, extensions: extensions);
    }

    public static IResult Problem(this HttpContext context, string code) => new Error(code).Problem(context);

    public static IResult ToHttp(this Result result, HttpContext context) =>
        result.Succeeded ? Results.NoContent() : result.Error!.Problem(context);

    public static IResult ToHttp<T>(this Result<T> result, HttpContext context) =>
        result.Succeeded ? Results.Ok(result.Value) : result.Error!.Problem(context);
}
