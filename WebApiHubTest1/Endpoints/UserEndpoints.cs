using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApiHubTest1.Models;
using WebApiHubTest1.Services;


namespace WebApiHubTest1.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/register", async (RegisterRequest request, UserService userService, Emailing emailing, ILogger<Program> logger) =>
        {
            var validationResults = new List<ValidationResult>();
            var validationContext = new ValidationContext(request);

            if (!Validator.TryValidateObject(request, validationContext, validationResults, true))
            {
                return Results.BadRequest(new
                {
                    Message = "Validation failed",
                    Errors = validationResults.Select(vr => vr.ErrorMessage)
                });
            }

            try
            {
                await userService.RegisterUserAsync(request);

                // Generate confirmation code
                var confirmationCode = new Random().Next(100000, 999999).ToString();

                // Set code expiration time (e.g., 15 minutes from now)
                var codeExpiresAt = DateTime.Now.AddMinutes(15);

                // Save confirmation code and expiration time
                await userService.SetEmailConfirmationCodeAsync(request.Email, confirmationCode, codeExpiresAt);

                // Send email with the code
                var emailBody = GetEmailConfirmationHtmlTemplate(confirmationCode);
                await emailing.SendEmailAsync(request.Email, "Email Confirmation", emailBody);

                return Results.Created("/register", "User registered successfully. Please check your email to confirm your account.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while registering user.");
                if (ex.Message == "User already exists.")
                {
                    return Results.BadRequest("User already exists.");
                }
                else
                {
                    return Results.Problem("An error occurred during registration.", statusCode: StatusCodes.Status500InternalServerError);
                }
            }
        })
        .WithName("RegisterUser")
        .WithTags("User");






        endpoints.MapPost("/login", async (LoginRequest request, UserService userService, JwtService jwtService, ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return Results.BadRequest("Email and password are required.");
            }

            try
            {
                if (!await userService.ValidateUserAsync(request))
                {
                    return Results.Unauthorized();
                }

                // Check if email is confirmed
                if (!await userService.IsEmailConfirmedAsync(request.Email))
                {
                    return Results.BadRequest("Email is not confirmed. Please confirm your email before logging in.");
                }

                // Get the user's ID 
                int userId = await userService.GetUserIdAsync(request.Email);

                // Revoke all existing refresh tokens for the user
                await userService.RevokeAllRefreshTokensAsync(userId);

                // Generate JWT access token
                var tokenString = jwtService.GenerateToken(request.Email);
                logger.LogInformation($"{tokenString}");

                // Generate refresh token
                var refreshToken = jwtService.GenerateRefreshToken();
                logger.LogInformation($"{refreshToken.Token}");

                // Save refresh token
                await userService.SaveRefreshTokenAsync(userId, refreshToken);

                return Results.Ok(new
                {
                    AccessToken = tokenString,
                    RefreshToken = refreshToken.Token
                });
            }
            catch
            {
                return Results.Problem("An error occurred during login.", statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("Login")
        .WithTags("User");




        endpoints.MapGet("/Dashboard", (ClaimsPrincipal user) =>
        {
            var email = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "Anonymous";
            return Results.Ok(new UserInfoResponse { Email = email });

        })
        .RequireAuthorization()
        .WithName("Dashboard")
        .WithTags("User");




        endpoints.MapPost("/refresh-token", async (RefreshTokenRequest request, UserService userService, JwtService jwtService, ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return Results.BadRequest("Refresh token is required.");
            }

            var storedToken = await userService.GetRefreshTokenAsync(request.RefreshToken);

            if (storedToken == null || storedToken.ExpiresAt <= DateTime.Now || storedToken.RevokedAt != null)
            {
                return Results.Unauthorized(); // We'll fix the message in the next point
            }

            // Generate a new refresh token
            var newRefreshToken = jwtService.GenerateRefreshToken();
            logger.LogInformation($"{newRefreshToken}");

            // Revoke the old refresh token
            await userService.RevokeRefreshTokenAsync(storedToken.Token, newRefreshToken.Token);

            // Save the new refresh token
            await userService.SaveRefreshTokenAsync(storedToken.UserId, newRefreshToken);

            // Get the user's email
            var email = await userService.GetEmailByIdAsync(storedToken.UserId);

            // Generate new access token
            var newAccessToken = jwtService.GenerateToken(email);

            return Results.Ok(new
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken.Token
            });
        })
        .WithName("RefreshToken")
        .WithTags("User");



        endpoints.MapPost("/confirm-email", async (ConfirmEmailRequest request, UserService userService) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.ConfirmationCode))
            {
                return Results.BadRequest("Email and confirmation code are required.");
            }

            var result = await userService.ConfirmEmailAsync(request.Email, request.ConfirmationCode);

            if (result)
            {
                return Results.Ok("Email confirmed successfully.");
            }
            else
            {
                return Results.BadRequest("Invalid confirmation code or code has expired.");
            }
        })
.WithName("ConfirmEmail")
.WithTags("User");



        endpoints.MapPost("/resend-confirmation-code", async (ResendConfirmationCodeRequest request, UserService userService, Emailing emailing) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email))
            {
                return Results.BadRequest("Email is required.");
            }

            // Check if user exists
            if (!await userService.IsUserExistsAsync(request.Email))
            {
                // Return generic response
                return Results.Ok("If an account with that email exists, a new confirmation code has been sent.");
            }

            // Generate new confirmation code
            var confirmationCode = new Random().Next(100000, 999999).ToString();

            // Set code expiration time
            var codeExpiresAt = DateTime.UtcNow.AddMinutes(15);

            // Save confirmation code and expiration time
            await userService.SetEmailConfirmationCodeAsync(request.Email, confirmationCode, codeExpiresAt);

            // Send email with the code
            var emailBody = GetEmailConfirmationHtmlTemplate(confirmationCode);
            await emailing.SendEmailAsync(request.Email, "Email Confirmation", emailBody);

            return Results.Ok("If an account with that email exists, a new confirmation code has been sent.");
        })
        .WithName("ResendConfirmationCode")
        .WithTags("User");


        endpoints.MapPost("/forgot-password", async (ForgotPasswordRequest request, UserService userService, Emailing emailing) =>
        {
            if (!await userService.IsUserExistsAsync(request.Email))
            {
                // For security, return the same response whether the email exists or not
                return Results.Ok("If an account with that email exists, a password reset code has been sent.");
            }

            // Generate reset code
            var resetCode = new Random().Next(100000, 999999).ToString();

            // Set code expiration time (e.g., 15 minutes from now)
            var codeExpiresAt = DateTime.UtcNow.AddMinutes(15);

            // Save reset code and expiration time
            await userService.SetPasswordResetCodeAsync(request.Email, resetCode, codeExpiresAt);

            // Send email with the code
            var emailBody = GetPasswordResetHtmlTemplate(resetCode);
            await emailing.SendEmailAsync(request.Email, "Password Reset Code", emailBody);

            return Results.Ok("If an account with that email exists, a password reset code has been sent.");
        })
.WithName("ForgotPassword")
.WithTags("User");



        endpoints.MapPost("/reset-password", async (ResetPasswordRequest request, UserService userService, Encryption encryption) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code) || string.IsNullOrWhiteSpace(request.NewPassword))
            {
                return Results.BadRequest("Email, code, and new password are required.");
            }

            var result = await userService.ResetPasswordAsync(request.Email, request.Code, request.NewPassword);

            if (result)
            {
                return Results.Ok("Password has been reset successfully.");
            }
            else
            {
                return Results.BadRequest("Invalid code or code has expired.");
            }
        })
.WithName("ResetPassword")
.WithTags("User");



        endpoints.MapPost("/change-email", [Authorize] async (ChangeEmailRequest request, UserService userService, Emailing emailing, ClaimsPrincipal user) =>
        {
            var currentEmail = user.Identity?.Name;

            if (string.IsNullOrWhiteSpace(currentEmail))
            {
                return Results.Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(request.NewEmail))
            {
                return Results.BadRequest("New email is required.");
            }

            if (await userService.IsUserExistsAsync(request.NewEmail))
            {
                return Results.BadRequest("The new email is already in use.");
            }

            // Generate confirmation code
            var confirmationCode = new Random().Next(100000, 999999).ToString();

            // Set code expiration time
            var codeExpiresAt = DateTime.UtcNow.AddMinutes(15);

            // Save new email, confirmation code, and expiration time
            await userService.SetEmailChangeCodeAsync(currentEmail, request.NewEmail, confirmationCode, codeExpiresAt);

            // Send email with the code to the new email address
            var newEmailBody = GetEmailChangeHtmlTemplate(confirmationCode);
            await emailing.SendEmailAsync(request.NewEmail, "Email Change Confirmation", newEmailBody);

            // Send notification to the old email address
            var oldEmailBody = GetEmailChangeNotificationHtmlTemplate(request.NewEmail);
            await emailing.SendEmailAsync(currentEmail, "Email Change Requested", oldEmailBody);

            return Results.Ok("A confirmation code has been sent to your new email address. Please use it to confirm the change. A notification has been sent to your current email.");
        })
        .WithName("ChangeEmail")
        .WithTags("User");





        endpoints.MapPost("/confirm-email-change", [Authorize] async (ConfirmEmailChangeRequest request, UserService userService, ClaimsPrincipal user) =>
        {
            var currentEmail = user.Identity?.Name;

            if (string.IsNullOrWhiteSpace(currentEmail))
            {
                return Results.Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(request.Code))
            {
                return Results.BadRequest("Confirmation code is required.");
            }

            var result = await userService.ConfirmEmailChangeAsync(currentEmail, request.Code);

            if (result)
            {
                return Results.Ok("Email address has been changed successfully.");
            }
            else
            {
                return Results.BadRequest("Invalid code or code has expired.");
            }
        })
.WithName("ConfirmEmailChange")
.WithTags("User");




    }






    // Add this method to provide the HTML email template
    private static string GetEmailConfirmationHtmlTemplate(string confirmationCode)
    {
        return $@"
        <html>
        <body style='font-family: Arial, sans-serif;'>
            <div style='max-width: 600px; margin: auto; padding: 20px;'>
                <h2 style='color: #333;'>Welcome to Our App!</h2>
                <p>Thank you for registering. Please use the following code to confirm your email address:</p>
                <div style='font-size: 24px; font-weight: bold; margin: 20px 0;'>
                    {confirmationCode}
                </div>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not register, please ignore this email.</p>
                <p>Best regards,<br/>Our App Team</p>
            </div>
        </body>
        </html>
        ";
    }


    private static string GetPasswordResetHtmlTemplate(string resetCode)
    {
        return $@"
    <html>
    <body style='font-family: Arial, sans-serif;'>
        <div style='max-width: 600px; margin: auto; padding: 20px;'>
            <h2 style='color: #333;'>Password Reset Request</h2>
            <p>You have requested to reset your password. Please use the following code to reset your password:</p>
            <div style='font-size: 24px; font-weight: bold; margin: 20px 0;'>
                {resetCode}
            </div>
            <p>This code will expire in 15 minutes.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <p>Best regards,<br/>Our App Team</p>
        </div>
    </body>
    </html>
    ";
    }



    private static string GetEmailChangeHtmlTemplate(string confirmationCode)
    {
        return $@"
    <html>
    <body style='font-family: Arial, sans-serif;'>
        <div style='max-width: 600px; margin: auto; padding: 20px;'>
            <h2 style='color: #333;'>Confirm Your Email Change</h2>
            <p>You have requested to change your email address. Please use the following code to confirm the change:</p>
            <div style='font-size: 24px; font-weight: bold; margin: 20px 0;'>
                {confirmationCode}
            </div>
            <p>This code will expire in 15 minutes.</p>
            <p>If you did not request this change, please contact support immediately.</p>
            <p>Best regards,<br/>Our App Team</p>
        </div>
    </body>
    </html>
    ";
    }



    private static string GetEmailChangeNotificationHtmlTemplate(string newEmail)
    {
        return $@"
    <html>
    <body style='font-family: Arial, sans-serif;'>
        <div style='max-width: 600px; margin: auto; padding: 20px;'>
            <h2 style='color: #333;'>Email Change Requested</h2>
            <p>We received a request to change the email address associated with your account to <strong>{newEmail}</strong>.</p>
            <p>If you initiated this request, no further action is needed.</p>
            <p><strong>If you did not request this change, please contact our support team immediately.</strong></p>
            <p>Best regards,<br/>Our App Team</p>
        </div>
    </body>
    </html>
    ";
    }




}


