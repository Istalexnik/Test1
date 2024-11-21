using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace WebApiHubTest1.Services;
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

        public void SendEmail(string recipientEmail, string subject, string body)
        {
            using (MailMessage mailMessage = new MailMessage(_email, recipientEmail))
            {
                mailMessage.Subject = subject;
                mailMessage.Body = body;
                mailMessage.IsBodyHtml = true;

                NetworkCredential networkCredential = new NetworkCredential(_email, _password);
                SmtpClient smtp = new SmtpClient
                {
                    Host = "smtp.gmail.com",
                    Port = 587,
                    EnableSsl = true,
                    Credentials = networkCredential
                };

                smtp.Send(mailMessage);
            }
        }
    }

