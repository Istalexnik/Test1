namespace WebApiHubTest1.Services;

public class EmailTemplateService
{
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

    /// <summary>
    /// Generates the email body by replacing placeholders with actual values.
    /// </summary>
    /// <param name="templateType">Type of the email template.</param>
    /// <param name="placeholders">Dictionary containing placeholder keys and their corresponding values.</param>
    /// <returns>Generated email body as a string.</returns>
    public string GenerateEmailBody(EmailTemplateType templateType, Dictionary<string, string> placeholders)
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

