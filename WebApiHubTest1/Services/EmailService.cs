using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Microsoft.Extensions.Configuration;

namespace WebApiHubTest1.Services
{
    public class EmailService
    {
        private readonly string _email;
        private readonly string _password;

        public enum EmailTemplateType
        {
            EmailConfirmation,
            PasswordReset,
            EmailChange,
            EmailChangeNotification
        }

        private readonly Dictionary<EmailTemplateType, string> _templates = new()
        {
            { EmailTemplateType.EmailConfirmation, @"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: auto; padding: 20px;'>
                        <h2 style='color: #333;'>Welcome to Our App!</h2>
                        <p>Thank you for registering. Please use the following code to confirm your email address:</p>
                        <div style='font-size: 24px; font-weight: bold; margin: 20px 0;'>
                            {{ConfirmationCode}}
                        </div>
                        <p>This code will expire in 15 minutes.</p>
                        <p>If you did not register, please ignore this email.</p>
                        <p>Best regards,<br/>Our App Team</p>
                    </div>
                </body>
                </html>" },

            { EmailTemplateType.PasswordReset, @"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: auto; padding: 20px;'>
                        <h2 style='color: #333;'>Password Reset Request</h2>
                        <p>You have requested to reset your password. Please use the following code to reset your password:</p>
                        <div style='font-size: 24px; font-weight: bold; margin: 20px 0;'>
                            {{ResetCode}}
                        </div>
                        <p>This code will expire in 15 minutes.</p>
                        <p>If you did not request a password reset, please ignore this email.</p>
                        <p>Best regards,<br/>Our App Team</p>
                    </div>
                </body>
                </html>" },

            { EmailTemplateType.EmailChange, @"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: auto; padding: 20px;'>
                        <h2 style='color: #333;'>Confirm Your Email Change</h2>
                        <p>You have requested to change your email address. Please use the following code to confirm the change:</p>
                        <div style='font-size: 24px; font-weight: bold; margin: 20px 0;'>
                            {{ConfirmationCode}}
                        </div>
                        <p>This code will expire in 15 minutes.</p>
                        <p>If you did not request this change, please contact support immediately.</p>
                        <p>Best regards,<br/>Our App Team</p>
                    </div>
                </body>
                </html>" },

            { EmailTemplateType.EmailChangeNotification, @"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: auto; padding: 20px;'>
                        <h2 style='color: #333;'>Email Change Requested</h2>
                        <p>We received a request to change the email address associated with your account to <strong>{{NewEmail}}</strong>.</p>
                        <p>If you initiated this request, no further action is needed.</p>
                        <p><strong>If you did not request this change, please contact our support team immediately.</strong></p>
                        <p>Best regards,<br/>Our App Team</p>
                    </div>
                </body>
                </html>" }
        };

        public EmailService(IConfiguration configuration)
        {
            _email = configuration["EmailSettings:Email"]
                ?? throw new InvalidOperationException("Email is not configured.");
            _password = configuration["EmailSettings:Password"]
                ?? throw new InvalidOperationException("Email password is not configured.");
        }

        /// <summary>
        /// Sends an email using the specified template and placeholders.
        /// </summary>
        /// <param name="recipientEmail">Recipient's email address.</param>
        /// <param name="subject">Subject of the email.</param>
        /// <param name="templateType">Type of the email template.</param>
        /// <param name="placeholders">Dictionary containing placeholder keys and their corresponding values.</param>
        public async Task SendEmailAsync(string recipientEmail, string subject, EmailTemplateType templateType, Dictionary<string, string> placeholders)
        {
            var body = GenerateEmailBody(templateType, placeholders);

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

        /// <summary>
        /// Generates the email body by replacing placeholders with actual values.
        /// </summary>
        /// <param name="templateType">Type of the email template.</param>
        /// <param name="placeholders">Dictionary containing placeholder keys and their corresponding values.</param>
        /// <returns>Generated email body as a string.</returns>
        private string GenerateEmailBody(EmailTemplateType templateType, Dictionary<string, string> placeholders)
        {
            if (!_templates.TryGetValue(templateType, out var template))
            {
                throw new ArgumentException("Invalid email template type.", nameof(templateType));
            }

            foreach (var placeholder in placeholders)
            {
                template = template.Replace($"{{{{{placeholder.Key}}}}}", placeholder.Value);
            }

            return template;
        }
    }
}
