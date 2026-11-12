using Mal3abi.Auth.API.Http;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Common;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Mal3abi.Auth.API.Pages;

public abstract class AuthPageModel : PageModel
{
    public AuthUi Ui => AuthUi.For(Request);

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    public string? CodeState { get; set; }

    public FieldErrors NewFieldErrors() => new(Ui);

    protected void ShowError(Error? error)
    {
        CodeState = CodeInput.StateFor(error);
        if (CodeState is not null) return;
        ErrorMessage = Ui.Error(error);
        if (error?.Details is { Count: > 0 } details)
            foreach (var detail in details) ModelState.AddModelError(string.Empty, detail);
    }

    protected bool Invalid(FieldErrors errors)
    {
        foreach (var (field, messages) in errors.ToDictionary())
            foreach (var message in messages) ModelState.AddModelError(field, message);
        return errors.Any;
    }
}
