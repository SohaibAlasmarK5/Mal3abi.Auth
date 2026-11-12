using System.Net;
using System.Net.Mail;
using Mal3abi.Auth.Core.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Mal3abi.Auth.Infra.Email;

/// <summary>
/// Sends through SMTP (Email:Smtp:*). In Development without SMTP settings, the email is written
/// to the log instead, so codes can be read from the console.
/// </summary>
public sealed class SmtpEmailSender(IConfiguration configuration, IHostEnvironment environment, ILogger<SmtpEmailSender> logger) : IEmailSender
{
    public async Task SendAsync(string to, string subject, string htmlBody, CancellationToken cancellationToken = default)
    {
        var host = configuration["Email:Smtp:Host"];
        if (string.IsNullOrWhiteSpace(host))
        {
            if (!environment.IsDevelopment())
                throw new InvalidOperationException("Set Email:Smtp:Host and Email:FromAddress before running outside Development.");
            logger.LogWarning("Development email to {To}: {Subject}\n{Body}", to, subject, htmlBody);
            return;
        }

        var fromAddress = configuration["Email:FromAddress"]
            ?? throw new InvalidOperationException("Email:FromAddress is required when SMTP is set.");
        using var message = new MailMessage
        {
            From = new MailAddress(fromAddress, configuration["Email:FromName"] ?? "Mal3abi"),
            Subject = subject,
            Body = htmlBody,
            IsBodyHtml = true,
        };
        message.To.Add(new MailAddress(to));

        using var client = new SmtpClient(host, configuration.GetValue("Email:Smtp:Port", 587))
        {
            EnableSsl = configuration.GetValue("Email:Smtp:EnableSsl", true),
            DeliveryMethod = SmtpDeliveryMethod.Network,
        };
        var username = configuration["Email:Smtp:Username"];
        if (!string.IsNullOrWhiteSpace(username))
            client.Credentials = new NetworkCredential(username, configuration["Email:Smtp:Password"]);
        await client.SendMailAsync(message, cancellationToken);
    }
}
