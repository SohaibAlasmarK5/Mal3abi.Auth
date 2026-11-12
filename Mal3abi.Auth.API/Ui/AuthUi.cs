using System.Globalization;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.WebUtilities;

namespace Mal3abi.Auth.API.Ui;

/// <summary>
/// The language of the account pages and API messages, and all their text in Modern Standard
/// Arabic and English. Every new text goes here in both languages.
/// </summary>
public sealed partial class AuthUi
{
    public const string LangCookie = "mal3abi-lang";

    private readonly HttpRequest request;

    private AuthUi(HttpRequest request, string lang)
    {
        this.request = request;
        Lang = lang;
    }

    /// <summary>"ar" (default) or "en".</summary>
    public string Lang { get; }

    public string Dir => Lang == "ar" ? "rtl" : "ltr";

    public string OtherLang => Lang == "ar" ? "en" : "ar";

    /// <summary>
    /// Language order: ?lang=, the OIDC ui_locales hint (also inside the return URL, so the
    /// website's choice carries over), the saved choice, then Arabic. API calls (/api) also look
    /// at Accept-Language before falling back to Arabic. Pages ignore the browser language on
    /// purpose, as the website does.
    /// </summary>
    public static AuthUi For(HttpRequest request)
    {
        if (request.HttpContext.Items.TryGetValue(typeof(AuthUi), out var cached) && cached is AuthUi ui) return ui;

        var lang = Pick(request.Query["lang"])
            ?? Pick(request.Query["ui_locales"])
            ?? Pick(ReturnUrlLocale(request))
            ?? Pick(request.Cookies[LangCookie])
            ?? (request.Path.StartsWithSegments("/api") ? PickAcceptLanguage(request) : null)
            ?? "ar";
        ui = new AuthUi(request, lang);
        request.HttpContext.Items[typeof(AuthUi)] = ui;
        return ui;
    }

    private static string? ReturnUrlLocale(HttpRequest request)
    {
        var returnUrl = request.Query["ReturnUrl"].FirstOrDefault() ?? request.Query["returnUrl"].FirstOrDefault();
        if (string.IsNullOrEmpty(returnUrl) && request.HasFormContentType)
            returnUrl = request.Form["ReturnUrl"].FirstOrDefault();
        if (string.IsNullOrEmpty(returnUrl)) return null;
        var queryStart = returnUrl.IndexOf('?');
        if (queryStart < 0) return null;
        var query = QueryHelpers.ParseQuery(returnUrl[queryStart..]);
        return query.TryGetValue("ui_locales", out var value) ? value.ToString() : null;
    }

    private static string? PickAcceptLanguage(HttpRequest request)
    {
        var header = request.Headers.AcceptLanguage.ToString();
        if (string.IsNullOrWhiteSpace(header)) return null;
        return Pick(string.Join(' ', header.Split(',').Select(part => part.Split(';')[0].Trim())));
    }

    private static string? Pick(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        // ui_locales may hold several tags ("en-GB ar"); the first one we support wins.
        foreach (var tag in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var code = tag.Split('-')[0].ToLowerInvariant();
            if (code is "ar" or "en") return code;
        }
        return null;
    }

    /// <summary>This page in the other language, keeping every other query value.</summary>
    public string SwitchLangUrl()
    {
        var query = QueryHelpers.ParseQuery(request.QueryString.Value)
            .Where(pair => pair.Key != "lang")
            .ToDictionary(pair => pair.Key, pair => (string?)pair.Value.ToString());
        query["lang"] = OtherLang;
        return QueryHelpers.AddQueryString(request.PathBase + request.Path, query);
    }

    public string T(string key) =>
        (Lang == "ar" ? Arabic : English).TryGetValue(key, out var text) ? text : key;

    public string T(string key, object arg) => string.Format(CultureInfo.InvariantCulture, T(key), arg);

    /// <summary>The text for an error code, with its wait time or end date when it has one.</summary>
    public string Error(Error? error)
    {
        if (error is null) return string.Empty;
        switch (error.Code)
        {
            case ErrorCodes.CodeTooSoon:
                return T("err.code_too_soon", error.RetryAfterSeconds ?? 60);
            case ErrorCodes.CodeHourlyLimit:
                return T("err.code_hourly_limit", Math.Max(1, (int)Math.Ceiling((error.RetryAfterSeconds ?? 3600) / 60.0)));
            case ErrorCodes.AccountSuspended when error.Until is { } until:
                return T("err.account_suspended_until", Date(until));
        }
        var key = "err." + error.Code;
        var text = T(key);
        return text == key ? T("err.server_error") : text;
    }

    public string Date(DateTimeOffset value) =>
        value.ToOffset(TimeSpan.FromHours(3)).ToString(Lang == "ar" ? "d/M/yyyy h:mm tt" : "d MMM yyyy, h:mm tt",
            Lang == "ar" ? CultureInfo.GetCultureInfo("ar-JO") : CultureInfo.GetCultureInfo("en-GB"));
}

/// <summary>Settings for the shared six-digit code input (Pages/Shared/_CodeInput.cshtml).</summary>
/// <param name="Name">Form field name the page model binds, for example "Code".</param>
/// <param name="Label">Visible label.</param>
/// <param name="ResendHandler">Page handler that sends a new code; null hides the resend button.</param>
/// <param name="ResendSeconds">Wait before resending is allowed.</param>
/// <param name="State">null, "wrong", "expired" or "attempts".</param>
public sealed record CodeInput(
    string Name,
    string Label,
    string? ResendHandler = null,
    int ResendSeconds = 60,
    string? State = null)
{
    /// <summary>The code input state for an error code, or null when the error is about something else.</summary>
    public static string? StateFor(Error? error) => error?.Code switch
    {
        ErrorCodes.CodeWrong => "wrong",
        ErrorCodes.CodeExpired => "expired",
        ErrorCodes.CodeAttempts => "attempts",
        _ => null,
    };
}
