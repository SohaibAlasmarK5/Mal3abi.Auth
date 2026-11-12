# Mal3abi Auth Center

The account center for Mal3abi: registration, sign-in, roles, email verification by code,
two-step verification, court owner sign-up, invitations, bans, soft delete and the audit log.
.NET 10, ASP.NET Identity, OpenIddict (OpenID Connect server), SQL Server with its own database.
Jira epic: KAN-42.

## Projects

| Project | Holds |
|---|---|
| `Mal3abi.Auth.Core` | Entities and contracts only: `Entity`, `IRepository<T>`, `IUnitOfWork`, `Result`/`Error`/`ErrorCodes`, `AuthUser`, service interfaces. |
| `Mal3abi.Auth.Infra` | EF Core (`AuthDbContext`, migrations), the generic `Repository<T>`, `UnitOfWork`, the audit interceptor, services, email, the cleanup job, seeding. |
| `Mal3abi.Auth.API` | Minimal API endpoints (`Endpoints/`), OIDC endpoints, Razor account pages (`Pages/Account`), the text helper `Ui/AuthUi` (Arabic and English). |

## Rules the code follows

- **Repository and unit of work.** Services use `IRepository<T>` (generic, one per entity) and save
  once per operation with `IUnitOfWork`. A specific repository is added only for a query that does
  not fit. Identity users and roles stay on `UserManager`, which already is a repository.
- **One place for common rules.** `AuditSaveChangesInterceptor` fills `CreatedAt`/`UpdatedAt`,
  turns deletes of `ISoftDeletable` rows into hiding, and writes an audit row (before and after) for
  every change to an `[Audited]` entity or role assignment. A service names the action and reason
  with `AuditLabel` (for example `account.suspended`). Security events (sign-in, failed sign-in,
  wrong two-step code) are written with `IAuditService`.
- **Errors.** Services return `Result`/`Error` with a stable code from `ErrorCodes`. The API turns
  them into problem+json with `code`, `message` (in the request language) and `errors`. Pages show
  the same text from `AuthUi`.
- **Text.** Every page, API message, Identity error and email exists in Arabic and English
  (`Ui/AuthUi.Text.cs`, `Infra/Email/AuthEmails.cs`). Language order: `?lang=`, OIDC `ui_locales`,
  cookie `mal3abi-lang`, then Arabic (APIs also read `Accept-Language`).

## Product rules (docs/reference.html, sections 2, 5, 9, 16)

- Email code for every new account (player, owner, invited admin): 6 digits, 10 minutes, 5 wrong
  attempts, resend after 1 minute, 5 codes per hour. Codes are stored as an HMAC.
- Accounts not confirmed within 7 days are deleted (hourly job), freeing the email and username.
- Two-step by role: super admins use an authenticator app (set up on first sign-in, required before
  any token is issued), court owners get an email code on every sign-in, players may turn the email
  code on.
- Court owners sign up themselves at `/account/register?as=owner`. Court approval is in Mal3abi.BE.
- Penalties: warning, suspension until a date, permanent ban (blocks the same email and phone).
  Suspended and banned accounts cannot sign in or refresh tokens (`account_suspended`).
- Hiding instead of deleting, with restore for admins. Hidden accounts keep their email reserved.

## Endpoints

- OIDC: `/connect/authorize`, `/connect/token`, `/connect/logout`, `/connect/revoke`. Client
  `mal3abi-api` (code flow + PKCE, refresh tokens). Claims: `sub`, `name`, `preferred_username`,
  `email`, `email_verified`, `role` (player, owner, superadmin), `auth_center`, `locale`, `amr`.
- `/api/accounts`: `register`, `email/resend`, `email/confirm`, `password/forgot`, `password/reset`,
  `csrf`, and `/me` (profile, language, email change by code, password, two-step, delete).
  Cookie calls that change something need `X-CSRF-TOKEN`; bearer-token calls do not.
- `/api/admin` (super admin with a two-step session): accounts, invitations, `warn`, `suspend`,
  `ban`, `reinstate`, hide, `restore`, `audit`.
- `/api/integration` (Mal3abi.BE, header `X-Mal3abi-Integration-Key`, optional
  `X-Mal3abi-Actor-Id` for the audit log): the same routes BE already calls, plus the penalties.
- OpenAPI document in Development: `/openapi/v1.json`.

## Run locally

Secrets (User Secrets of `Mal3abi.Auth.API`): `ConnectionStrings:AuthCenter`,
`Authentication:ClientSecret`, `Authentication:BackendIntegrationSecret`, `SuperAdmin:UserName`,
`SuperAdmin:Email`, `SuperAdmin:Password`, optional `Codes:Secret` and `Email:Smtp:*`.

```bash
dotnet run --project Mal3abi.Auth.API --launch-profile https
```

In Development, migrations are applied on startup, and emails (with their codes) are written to the
console when SMTP is not set. Elsewhere set `Database:MigrateOnStartup` or run
`dotnet tool run dotnet-ef database update --project Mal3abi.Auth.Infra --startup-project Mal3abi.Auth.Infra`
with the right connection.

New migration:

```bash
dotnet tool run dotnet-ef migrations add <Name> --project Mal3abi.Auth.Infra --startup-project Mal3abi.Auth.Infra --output-dir Data/Migrations
```
