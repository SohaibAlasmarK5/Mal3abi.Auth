using Microsoft.AspNetCore.WebUtilities;

namespace Mal3abi.Auth.API.Ui;

/// <summary>
/// Presentation only: the language of the account pages and their text in Arabic and English.
/// It changes no sign-in or account behaviour.
/// </summary>
public sealed class AuthUi
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
    /// website's choice carries over), the saved choice, then Arabic. The browser language is
    /// ignored on purpose, as on the website.
    /// </summary>
    public static AuthUi For(HttpRequest request)
    {
        var lang = Pick(request.Query["lang"])
            ?? Pick(request.Query["ui_locales"])
            ?? Pick(ReturnUrlLocale(request))
            ?? Pick(request.Cookies[LangCookie])
            ?? "ar";
        return new AuthUi(request, lang);
    }

    private static string? ReturnUrlLocale(HttpRequest request)
    {
        var returnUrl = request.Query["ReturnUrl"].FirstOrDefault() ?? request.Query["returnUrl"].FirstOrDefault();
        if (string.IsNullOrEmpty(returnUrl)) return null;
        var queryStart = returnUrl.IndexOf('?');
        if (queryStart < 0) return null;
        var query = QueryHelpers.ParseQuery(returnUrl[queryStart..]);
        return query.TryGetValue("ui_locales", out var value) ? value.ToString() : null;
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
            .ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
        query["lang"] = OtherLang;
        return QueryHelpers.AddQueryString(request.PathBase + request.Path, query!);
    }

    public string T(string key) =>
        (Lang == "ar" ? Arabic : English).TryGetValue(key, out var text) ? text : key;

    public string T(string key, object arg) => string.Format(T(key), arg);

    /// <summary>
    /// Messages written by the page models are Arabic. Show the English version when one is
    /// known; otherwise the original text.
    /// </summary>
    public string Server(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return string.Empty;
        if (Lang == "ar") return message;
        return ServerMessagesInEnglish.TryGetValue(message.Trim(), out var english) ? english : message;
    }

    private static readonly Dictionary<string, string> ServerMessagesInEnglish = new()
    {
        ["تم تفعيل حسابك. يمكنك تسجيل الدخول الآن."] = "Your account is active. You can sign in now.",
        ["تأكيد البريد الإلكتروني"] = "Confirm your email",
        ["رابط التأكيد غير صالح أو منتهي الصلاحية."] = "This confirmation link is not valid or has expired.",
        ["تم تأكيد بريدك الإلكتروني"] = "Your email is confirmed",
        ["تعذر تأكيد البريد الإلكتروني"] = "We could not confirm your email",
        ["تم تفعيل حسابك. يمكنك الآن تسجيل الدخول إلى ملعبي."] = "Your account is active. You can now sign in to Mal3abi.",
        ["رمز المصادقة غير صحيح أو انتهت صلاحيته."] = "The verification code is wrong or has expired.",
        ["اسم المستخدم أو كلمة المرور غير صحيحة."] = "The username or password is not correct.",
        ["تم إيقاف تسجيل الدخول مؤقتاً. حاول مرة أخرى لاحقاً."] = "Sign-in is paused for now. Try again later.",
        ["تحقق من بريدك الإلكتروني واضغط على رابط التأكيد لتفعيل الحساب."] = "Check your email and open the confirmation link to activate your account.",
        ["تم تغيير كلمة المرور. يمكنك تسجيل الدخول الآن."] = "Your password is changed. You can sign in now.",
        ["تم تفعيل المصادقة الثنائية."] = "Two-step verification is on.",
        ["رمز المصادقة غير صحيح."] = "The verification code is not correct.",
    };

    private static readonly Dictionary<string, string> Arabic = new()
    {
        ["brand"] = "ملعبي",
        ["accountCenter"] = "مركز الحسابات",
        ["backToSite"] = "العودة إلى موقع ملعبي",
        ["switchLang"] = "English",
        ["switchLangAria"] = "التبديل إلى اللغة الإنجليزية",
        ["themeToggle"] = "التبديل بين الوضع الفاتح والداكن",
        ["titleSuffix"] = "ملعبي",

        ["login.title"] = "تسجيل الدخول",
        ["login.intro"] = "استخدم بريدك الإلكتروني أو اسم المستخدم للمتابعة إلى ملعبي.",
        ["login.identifier"] = "البريد الإلكتروني أو اسم المستخدم",
        ["login.password"] = "كلمة المرور",
        ["login.remember"] = "تذكرني على هذا الجهاز",
        ["login.submit"] = "تسجيل الدخول",
        ["login.forgot"] = "نسيت كلمة المرور؟",
        ["login.noAccount"] = "ليس لديك حساب؟",
        ["login.createPlayer"] = "أنشئ حساب لاعب",
        ["login.twoFactorTitle"] = "التحقق بخطوتين",
        ["login.twoFactorIntro"] = "أدخل الرمز المكوّن من ستة أرقام من تطبيق المصادقة.",
        ["login.twoFactorLabel"] = "رمز التحقق",
        ["login.verify"] = "تأكيد",

        ["register.title"] = "أنشئ حساب لاعب",
        ["register.intro"] = "أدخل بياناتك، ثم أكّد بريدك الإلكتروني لتفعيل الحساب.",
        ["register.name"] = "الاسم الكامل",
        ["register.username"] = "اسم المستخدم",
        ["register.usernameHint"] = "من 3 إلى 32 حرفاً، بالأحرف الإنجليزية والأرقام.",
        ["register.email"] = "البريد الإلكتروني",
        ["register.phone"] = "رقم الهاتف",
        ["register.age"] = "العمر",
        ["register.photo"] = "رابط الصورة (اختياري)",
        ["register.password"] = "كلمة المرور",
        ["register.passwordHint"] = "8 أحرف على الأقل.",
        ["register.submit"] = "إنشاء الحساب",
        ["register.haveAccount"] = "لديك حساب بالفعل؟",
        ["register.signIn"] = "سجّل الدخول",
        ["register.ownerQuestion"] = "صاحب ملعب؟",
        ["register.ownerLink"] = "تعرّف على ملعبي لأصحاب الملاعب",

        ["invite.title"] = "فعّل حسابك",
        ["invite.intro"] = "أنشئ كلمة مرور لتفعيل الحساب الذي دُعيت إليه.",
        ["invite.password"] = "كلمة المرور",
        ["invite.confirm"] = "تأكيد كلمة المرور",
        ["invite.submit"] = "تفعيل الحساب",
        ["invite.signIn"] = "الذهاب إلى تسجيل الدخول",

        ["confirm.title"] = "تأكيد البريد الإلكتروني",
        ["confirm.goToLogin"] = "الذهاب إلى تسجيل الدخول",

        ["forgot.title"] = "استعادة كلمة المرور",
        ["forgot.intro"] = "أدخل بريدك الإلكتروني. إذا كان الحساب مؤكداً فسنرسل إليك رابط إعادة التعيين.",
        ["forgot.email"] = "البريد الإلكتروني",
        ["forgot.submit"] = "إرسال الرابط",
        ["forgot.sent"] = "إذا كان هناك حساب مؤكد بهذا البريد، فسيصلك رابط إعادة التعيين خلال دقائق.",
        ["forgot.back"] = "العودة إلى تسجيل الدخول",

        ["reset.title"] = "تعيين كلمة مرور جديدة",
        ["reset.password"] = "كلمة المرور الجديدة",
        ["reset.confirm"] = "تأكيد كلمة المرور",
        ["reset.submit"] = "حفظ كلمة المرور",
        ["reset.signIn"] = "الذهاب إلى تسجيل الدخول",

        ["security.title"] = "التحقق بخطوتين",
        ["security.intro"] = "يجب على مدراء المنصة تفعيل التحقق بخطوتين قبل الدخول إلى لوحة الإدارة.",
        ["security.enabled"] = "التحقق بخطوتين مفعّل على هذا الحساب.",
        ["security.addKey"] = "أضف هذا المفتاح في تطبيق مصادقة مثل Microsoft Authenticator أو Google Authenticator، ثم أدخل الرمز الذي يظهر فيه.",
        ["security.keyLabel"] = "مفتاح الإعداد",
        ["security.codeLabel"] = "الرمز المكوّن من ستة أرقام",
        ["security.submit"] = "تفعيل التحقق بخطوتين",

        ["code.hint"] = "أدخل الأرقام الستة. يمكنك لصق الرمز كاملاً.",
        ["code.resend"] = "إعادة إرسال الرمز",
        ["code.resendIn"] = "إعادة الإرسال بعد {0} ثانية",
        ["code.expired"] = "انتهت صلاحية الرمز. اطلب رمزاً جديداً.",
        ["code.attempts"] = "استنفدت المحاولات المسموحة. اطلب رمزاً جديداً.",
        ["code.wrong"] = "الرمز غير صحيح. تحقق منه وأعد المحاولة.",
    };

    private static readonly Dictionary<string, string> English = new()
    {
        ["brand"] = "Mal3abi",
        ["accountCenter"] = "Account center",
        ["backToSite"] = "Back to the Mal3abi website",
        ["switchLang"] = "العربية",
        ["switchLangAria"] = "Switch to Arabic",
        ["themeToggle"] = "Switch between light and dark mode",
        ["titleSuffix"] = "Mal3abi",

        ["login.title"] = "Sign in",
        ["login.intro"] = "Use your email or username to continue to Mal3abi.",
        ["login.identifier"] = "Email or username",
        ["login.password"] = "Password",
        ["login.remember"] = "Remember me on this device",
        ["login.submit"] = "Sign in",
        ["login.forgot"] = "Forgot your password?",
        ["login.noAccount"] = "No account yet?",
        ["login.createPlayer"] = "Create a player account",
        ["login.twoFactorTitle"] = "Two-step verification",
        ["login.twoFactorIntro"] = "Enter the six-digit code from your authenticator app.",
        ["login.twoFactorLabel"] = "Verification code",
        ["login.verify"] = "Verify",

        ["register.title"] = "Create a player account",
        ["register.intro"] = "Enter your details, then confirm your email to activate the account.",
        ["register.name"] = "Full name",
        ["register.username"] = "Username",
        ["register.usernameHint"] = "3 to 32 characters, English letters and digits.",
        ["register.email"] = "Email",
        ["register.phone"] = "Phone number",
        ["register.age"] = "Age",
        ["register.photo"] = "Photo link (optional)",
        ["register.password"] = "Password",
        ["register.passwordHint"] = "At least 8 characters.",
        ["register.submit"] = "Create account",
        ["register.haveAccount"] = "Already have an account?",
        ["register.signIn"] = "Sign in",
        ["register.ownerQuestion"] = "Own a court?",
        ["register.ownerLink"] = "Learn about Mal3abi for court owners",

        ["invite.title"] = "Activate your account",
        ["invite.intro"] = "Create a password to activate the account you were invited to.",
        ["invite.password"] = "Password",
        ["invite.confirm"] = "Confirm password",
        ["invite.submit"] = "Activate account",
        ["invite.signIn"] = "Go to sign in",

        ["confirm.title"] = "Confirm your email",
        ["confirm.goToLogin"] = "Go to sign in",

        ["forgot.title"] = "Reset your password",
        ["forgot.intro"] = "Enter your email. If the account is confirmed, we will send you a reset link.",
        ["forgot.email"] = "Email",
        ["forgot.submit"] = "Send the link",
        ["forgot.sent"] = "If a confirmed account uses this email, a reset link will arrive within minutes.",
        ["forgot.back"] = "Back to sign in",

        ["reset.title"] = "Set a new password",
        ["reset.password"] = "New password",
        ["reset.confirm"] = "Confirm password",
        ["reset.submit"] = "Save password",
        ["reset.signIn"] = "Go to sign in",

        ["security.title"] = "Two-step verification",
        ["security.intro"] = "Platform admins must turn on two-step verification before opening the admin dashboard.",
        ["security.enabled"] = "Two-step verification is on for this account.",
        ["security.addKey"] = "Add this key to an authenticator app such as Microsoft Authenticator or Google Authenticator, then enter the code it shows.",
        ["security.keyLabel"] = "Setup key",
        ["security.codeLabel"] = "Six-digit code",
        ["security.submit"] = "Turn on two-step verification",

        ["code.hint"] = "Enter the six digits. You can paste the whole code.",
        ["code.resend"] = "Resend the code",
        ["code.resendIn"] = "Resend in {0} seconds",
        ["code.expired"] = "This code has expired. Ask for a new one.",
        ["code.attempts"] = "You have used all the allowed attempts. Ask for a new code.",
        ["code.wrong"] = "The code is not correct. Check it and try again.",
    };
}

/// <summary>Settings for the shared six-digit code input (Pages/Shared/_CodeInput.cshtml).</summary>
/// <param name="Name">Form field name the page model binds, for example "Input.AuthenticatorCode".</param>
/// <param name="Label">Visible label.</param>
/// <param name="ResendHandler">Page handler that sends a new code; null hides the resend button.</param>
/// <param name="ResendSeconds">Wait before resending is allowed.</param>
/// <param name="State">null, "wrong", "expired" or "attempts".</param>
public sealed record CodeInput(
    string Name,
    string Label,
    string? ResendHandler = null,
    int ResendSeconds = 60,
    string? State = null);
