using System.Net;
using Mal3abi.Auth.Core.Codes;

namespace Mal3abi.Auth.Infra.Email;

/// <summary>The emails the Auth Center sends, in Modern Standard Arabic and English.</summary>
public static class AuthEmails
{
    public sealed record Message(string Subject, string Html);

    public static Message Code(string language, CodePurpose purpose, string name, string code)
    {
        var ar = language != "en";
        var subject = (purpose, ar) switch
        {
            (CodePurpose.EmailConfirmation, true) => "رمز تأكيد بريدك في ملعبي",
            (CodePurpose.EmailConfirmation, false) => "Your Mal3abi email confirmation code",
            (CodePurpose.EmailChange, true) => "رمز تأكيد بريدك الجديد في ملعبي",
            (CodePurpose.EmailChange, false) => "Confirm your new Mal3abi email",
            (_, true) => "رمز الدخول إلى ملعبي",
            (_, false) => "Your Mal3abi sign-in code",
        };
        var intro = (purpose, ar) switch
        {
            (CodePurpose.EmailConfirmation, true) => "استخدم هذا الرمز لتأكيد بريدك الإلكتروني وتفعيل حسابك:",
            (CodePurpose.EmailConfirmation, false) => "Use this code to confirm your email and activate your account:",
            (CodePurpose.EmailChange, true) => "استخدم هذا الرمز لتأكيد بريدك الإلكتروني الجديد:",
            (CodePurpose.EmailChange, false) => "Use this code to confirm your new email:",
            (_, true) => "استخدم هذا الرمز لإكمال تسجيل الدخول:",
            (_, false) => "Use this code to finish signing in:",
        };
        var minutes = (int)CodeRules.Lifetime.TotalMinutes;
        var validity = ar
            ? $"الرمز صالح لمدة {minutes} دقائق. إذا لم تطلبه، تجاهل هذه الرسالة ولا تشاركه مع أحد."
            : $"The code is valid for {minutes} minutes. If you did not ask for it, ignore this email and do not share it.";
        var body = $"""
            <p style="font-size:22px;font-weight:700;letter-spacing:6px;direction:ltr;text-align:center;margin:20px 0">{code}</p>
            <p style="color:#55635B">{Encode(validity)}</p>
            """;
        return new Message(subject, Layout(ar, Greeting(ar, name), Encode(intro), body));
    }

    public static Message Invitation(string language, string name, string role, string link)
    {
        var ar = language != "en";
        var roleText = (role, ar) switch
        {
            ("SuperAdmin", true) => "مديراً عاماً",
            ("SuperAdmin", false) => "a platform admin",
            (_, true) => "صاحب ملعب",
            (_, false) => "a court owner",
        };
        var subject = ar ? "دعوة للانضمام إلى ملعبي" : "Your invitation to Mal3abi";
        var intro = ar
            ? $"دُعيت إلى ملعبي بصفتك {roleText}. أنشئ كلمة مرور لتفعيل حسابك، ثم أكّد بريدك برمز يصلك. الرابط صالح لثلاثة أيام."
            : $"You were invited to Mal3abi as {roleText}. Create a password to activate your account, then confirm your email with a code. The link is valid for three days.";
        return new Message(subject, Layout(ar, Greeting(ar, name), Encode(intro), Button(link, ar ? "تفعيل الحساب" : "Activate account")));
    }

    public static Message PasswordReset(string language, string name, string link)
    {
        var ar = language != "en";
        var subject = ar ? "إعادة تعيين كلمة المرور في ملعبي" : "Reset your Mal3abi password";
        var intro = ar
            ? "طلبت إعادة تعيين كلمة المرور. الرابط صالح لمدة 30 دقيقة. إذا لم تطلب ذلك، تجاهل هذه الرسالة."
            : "You asked to reset your password. The link is valid for 30 minutes. If you did not ask, ignore this email.";
        return new Message(subject, Layout(ar, Greeting(ar, name), Encode(intro), Button(link, ar ? "تعيين كلمة مرور جديدة" : "Set a new password")));
    }

    public static Message StatusChanged(string language, string name, string action, string reason, DateTimeOffset? until)
    {
        var ar = language != "en";
        var date = until?.ToString("yyyy-MM-dd");
        var (subject, text) = (action, ar) switch
        {
            ("warn", true) => ("تنبيه على حسابك في ملعبي", "وصلك تنبيه من إدارة ملعبي. تكرار المخالفة قد يؤدي إلى إيقاف الحساب."),
            ("warn", false) => ("A warning on your Mal3abi account", "Mal3abi has sent you a warning. Repeating it may lead to a suspension."),
            ("suspend", true) => ("إيقاف حسابك مؤقتاً في ملعبي", $"أُوقف حسابك مؤقتاً حتى {date}."),
            ("suspend", false) => ("Your Mal3abi account is suspended", $"Your account is suspended until {date}."),
            ("ban", true) => ("إغلاق حسابك في ملعبي", "أُغلق حسابك نهائياً."),
            ("ban", false) => ("Your Mal3abi account is closed", "Your account has been closed permanently."),
            (_, true) => ("إعادة تفعيل حسابك في ملعبي", "أُعيد تفعيل حسابك ويمكنك تسجيل الدخول."),
            (_, false) => ("Your Mal3abi account is active again", "Your account is active again and you can sign in."),
        };
        var reasonLine = string.IsNullOrWhiteSpace(reason) ? "" : $"<p>{(ar ? "السبب" : "Reason")}: {Encode(reason)}</p>";
        return new Message(subject, Layout(ar, Greeting(ar, name), Encode(text), reasonLine));
    }

    private static string Greeting(bool ar, string name) =>
        string.IsNullOrWhiteSpace(name) ? (ar ? "مرحباً،" : "Hello,") : (ar ? $"مرحباً {Encode(name)}،" : $"Hello {Encode(name)},");

    private static string Button(string link, string text) =>
        $"""<p style="margin:24px 0"><a href="{WebUtility.HtmlEncode(link)}" style="background:#0E7A4B;color:#FFFFFF;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:600">{Encode(text)}</a></p>""";

    private static string Layout(bool ar, string greeting, string intro, string body) => $"""
        <!doctype html>
        <html lang="{(ar ? "ar" : "en")}" dir="{(ar ? "rtl" : "ltr")}">
        <body style="margin:0;background:#F5F7F4;font-family:'IBM Plex Sans Arabic','IBM Plex Sans',Tahoma,Arial,sans-serif;color:#13201A">
          <div style="max-width:520px;margin:24px auto;background:#FFFFFF;border:1px solid #DDE3DE;border-radius:14px;padding:24px">
            <p style="font-size:20px;font-weight:700;color:#0E7A4B;margin:0 0 16px">{(ar ? "ملعبي" : "Mal3abi")}</p>
            <p>{greeting}</p>
            <p>{intro}</p>
            {body}
          </div>
        </body>
        </html>
        """;

    private static string Encode(string value) => WebUtility.HtmlEncode(value);
}
