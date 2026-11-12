using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages;

/// <summary>Shared bits of the account pages: the text helper, messages, field errors and the return URL.</summary>
public abstract class AuthPageModel : PageModel
{
    public AuthUi Ui => AuthUi.For(Request);

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    /// <summary>"wrong", "expired" or "attempts" for the code input, when the last error was about the code.</summary>
    public string? CodeState { get; set; }

    public FieldErrors NewFieldErrors() => new(Ui);

    /// <summary>Shows an error: code problems on the code input, everything else as a message.</summary>
    protected void ShowError(Error? error)
    {
        CodeState = CodeInput.StateFor(error);
        if (CodeState is not null) return;
        ErrorMessage = Ui.Error(error);
        if (error?.Details is { Count: > 0 } details)
            foreach (var detail in details) ModelState.AddModelError(string.Empty, detail);
    }

    /// <summary>Copies field errors into ModelState so the validation summary lists them.</summary>
    protected bool Invalid(FieldErrors errors)
    {
        foreach (var (field, messages) in errors.ToDictionary())
            foreach (var message in messages) ModelState.AddModelError(field, message);
        return errors.Any;
    }
}
