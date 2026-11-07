#nullable enable

using Mal3abi.Auth.Core.Accounts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Mail;

namespace Mal3abi.Auth.Infra.Email;

public sealed class ConfiguredAuthEmailSender(IConfiguration configuration, IWebHostEnvironment environment, ILogger<ConfiguredAuthEmailSender> logger) : IAuthEmailSender
{
    public async Task SendAsync(string email, string subject, string htmlBody, CancellationToken cancellationToken = default)
    {
        var host = configuration["Email:Smtp:Host"];
        if (string.IsNullOrWhiteSpace(host))
        {
            if (!environment.IsDevelopment())
                throw new InvalidOperationException("Email delivery must be configured using Email:Smtp settings before production use.");

            logger.LogWarning("Development email to {Email}: {Subject}\n{Body}", email, subject, htmlBody);
            return;
        }

        var port = configuration.GetValue("Email:Smtp:Port", 587);
        var fromAddress = configuration["Email:FromAddress"];
        var fromName = configuration["Email:FromName"] ?? "Mal3abi";
        if (string.IsNullOrWhiteSpace(fromAddress))
            throw new InvalidOperationException("Email:FromAddress is required when SMTP delivery is enabled.");

        using var message = new MailMessage
        {
            From = new MailAddress(fromAddress, fromName),
            Subject = subject,
            Body = htmlBody,
            IsBodyHtml = true
        };
        message.To.Add(new MailAddress(email));

        using var client = new SmtpClient(host, port)
        {
            EnableSsl = configuration.GetValue("Email:Smtp:EnableSsl", true),
            DeliveryMethod = SmtpDeliveryMethod.Network
        };
        var username = configuration["Email:Smtp:Username"];
        var password = configuration["Email:Smtp:Password"];
        if (!string.IsNullOrWhiteSpace(username))
            client.Credentials = new NetworkCredential(username, password);
        await client.SendMailAsync(message, cancellationToken);
    }
}
