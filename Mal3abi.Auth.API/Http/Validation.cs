using System.Net.Mail;
using System.Text.RegularExpressions;
using Mal3abi.Auth.API.Ui;
using Mal3abi.Auth.Core.Common;

namespace Mal3abi.Auth.API.Http;

public sealed partial class FieldErrors(AuthUi ui)
{
    private readonly Dictionary<string, List<string>> errors = [];

    public bool Any => errors.Count > 0;

    public IReadOnlyDictionary<string, string[]> ToDictionary() => errors.ToDictionary(e => e.Key, e => e.Value.ToArray());

    public void Add(string field, string message)
    {
        if (!errors.TryGetValue(field, out var list)) errors[field] = list = [];
        list.Add(message);
    }

    public FieldErrors Required(string field, string? value, string labelKey, int maxLength = 256)
    {
        if (string.IsNullOrWhiteSpace(value)) Add(field, ui.T("field.required", ui.T(labelKey)));
        else if (value.Length > maxLength) Add(field, ui.T("field.tooLong", ui.T(labelKey)));
        return this;
    }

    public FieldErrors Email(string field, string? value, string labelKey)
    {
        Required(field, value, labelKey);
        if (!string.IsNullOrWhiteSpace(value) && !MailAddress.TryCreate(value.Trim(), out _))
            Add(field, ui.T("field.invalid", ui.T(labelKey)));
        return this;
    }

    public FieldErrors Username(string field, string? value, string labelKey)
    {
        Required(field, value, labelKey, 32);
        if (!string.IsNullOrWhiteSpace(value) && !UsernamePattern().IsMatch(value.Trim()))
            Add(field, ui.T("field.invalid", ui.T(labelKey)));
        return this;
    }

    public FieldErrors Phone(string field, string? value, string labelKey)
    {
        Required(field, value, labelKey, 32);
        if (!string.IsNullOrWhiteSpace(value) && !PhonePattern().IsMatch(value.Trim()))
            Add(field, ui.T("field.invalid", ui.T(labelKey)));
        return this;
    }

    public FieldErrors Age(string field, int? value)
    {
        if (value is null or < 13 or > 120) Add(field, ui.T("field.age"));
        return this;
    }

    public FieldErrors OptionalUrl(string field, string? value, string labelKey)
    {
        if (string.IsNullOrWhiteSpace(value)) return this;
        if (value.Length > 2048 || !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            Add(field, ui.T("field.invalid", ui.T(labelKey)));
        return this;
    }

    public FieldErrors Password(string field, string? value, string labelKey) => Required(field, value, labelKey, 128);

    public FieldErrors SamePassword(string field, string? password, string? confirm)
    {
        if (!string.Equals(password, confirm, StringComparison.Ordinal)) Add(field, ui.T("field.passwordsDiffer"));
        return this;
    }

    public IResult Problem(HttpContext context) => new Error(ErrorCodes.ValidationFailed).Problem(context, ToDictionary().ToDictionary());

    [GeneratedRegex("^[A-Za-z0-9._-]{3,32}$")]
    private static partial Regex UsernamePattern();

    [GeneratedRegex(@"^\+?[0-9 ()-]{7,20}$")]
    private static partial Regex PhonePattern();
}
