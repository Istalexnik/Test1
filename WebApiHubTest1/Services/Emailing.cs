using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Microsoft.Extensions.Configuration;

namespace WebApiHubTest1.Services
{
    public class Emailing
    {
        private readonly string _email;
        private readonly string _password;

        public Emailing(IConfiguration configuration)
        {
            _email = configuration["EmailSettings:Email"]
                ?? throw new InvalidOperationException("Email is not configured.");
            _password = configuration["EmailSettings:Password"]
                ?? throw new InvalidOperationException("Email password is not configured.");
        }

        public async Task SendEmailAsync(string recipientEmail, string subject, string body)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("WebApiHub", _email));
            message.To.Add(MailboxAddress.Parse(recipientEmail));
            message.Subject = subject;

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = body
            };
            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();

            try
            {
                // For demo purposes, accept all SSL certificates
                client.ServerCertificateValidationCallback = (s, c, h, e) => true;

                await client.ConnectAsync("smtp.gmail.com", 587, SecureSocketOptions.StartTls);

                // Note: Only needed if the SMTP server requires authentication
                await client.AuthenticateAsync(_email, _password);

                await client.SendAsync(message);
                await client.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                // Handle exception or rethrow
                throw new InvalidOperationException("Failed to send email.", ex);
            }
        }
    }
}
