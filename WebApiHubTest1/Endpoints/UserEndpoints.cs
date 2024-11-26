// UserEndpoints.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using WebApiHubTest1.Models;
using WebApiHubTest1.Services;

namespace WebApiHubTest1.Endpoints
{
    public static class UserEndpoints
    {
        public static void MapUserEndpoints(this IEndpointRouteBuilder endpoints)
        {
            // Register Endpoint
            endpoints.MapPost("/register", async (RegisterRequest request, UserService userService, EmailService emailService, ILogger<Program> logger) =>
            {
                try
                {
                    await userService.RegisterUserAsync(request);

                    // Generate confirmation code
                    var confirmationCode = new Random().Next(100000, 999999).ToString();

                    // Set code expiration time (e.g., 15 minutes from now)
                    var codeExpiresAt = DateTime.Now.AddMinutes(15);

                    // Save confirmation code and expiration time
                    await userService.SetEmailConfirmationCodeAsync(request.Email, confirmationCode, codeExpiresAt);

                    // Prepare placeholders for the template
                    var placeholders = new Dictionary<string, string>
                    {
                        { "ConfirmationCode", confirmationCode }
                    };

                    // Send email with the code using EmailService
                    await emailService.SendEmailAsync(
                        recipientEmail: request.Email,
                        subject: "Email Confirmation",
                        templateType: EmailService.EmailTemplateType.EmailConfirmation,
                        placeholders: placeholders
                    );

                    logger.LogInformation($"Sent confirmation code to {request.Email}");

                    return Results.Created("/register", "User registered successfully. Please check your email to confirm your account.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during registration.");
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

            // Login Endpoint
            endpoints.MapPost("/login", async (LoginRequest request, UserService userService, JwtService jwtService, ILogger<Program> logger) =>
            {
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
                    logger.LogInformation($"Generated Access Token for {request.Email}");

                    // Generate refresh token
                    var refreshToken = jwtService.GenerateRefreshToken();
                    logger.LogInformation($"Generated Refresh Token for {request.Email}");

                    // Save refresh token
                    await userService.SaveRefreshTokenAsync(userId, refreshToken);

                    return Results.Ok(new
                    {
                        AccessToken = tokenString,
                        RefreshToken = refreshToken.Token
                    });
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during login.");
                    return Results.Problem("An error occurred during login.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("Login")
            .WithTags("User");

            // Dashboard Endpoint
            endpoints.MapGet("/dashboard", [Authorize] (ClaimsPrincipal user) =>
            {
                var email = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "Anonymous";
                return Results.Ok(new UserInfoResponse { Email = email });
            })
            .WithName("Dashboard")
            .WithTags("User");

            // Refresh Token Endpoint
            endpoints.MapPost("/refresh-token", async (RefreshTokenRequest request, UserService userService, JwtService jwtService, ILogger<Program> logger) =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(request.RefreshToken))
                    {
                        return Results.BadRequest("Refresh token is required.");
                    }

                    var storedToken = await userService.GetRefreshTokenAsync(request.RefreshToken);

                    if (storedToken == null || storedToken.ExpiresAt <= DateTime.Now || storedToken.RevokedAt != null)
                    {
                        return Results.Unauthorized();
                    }

                    // Generate a new refresh token
                    var newRefreshToken = jwtService.GenerateRefreshToken();
                    logger.LogInformation($"Generated New Refresh Token for User ID: {storedToken.UserId}");

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
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during token refresh.");
                    return Results.Problem("An error occurred during token refresh.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("RefreshToken")
            .WithTags("User");

            // Confirm Email Endpoint
            endpoints.MapPost("/confirm-email", async (ConfirmEmailRequest request, UserService userService, ILogger<Program> logger) =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.ConfirmationCode))
                    {
                        return Results.BadRequest("Email and confirmation code are required.");
                    }

                    // Check if the email is blocked
                    if (await userService.IsBlockedAsync(request.Email))
                    {
                        return Results.BadRequest("Too many failed attempts. You cannot request a new code for 24 hours.");
                    }

                    var result = await userService.ConfirmEmailAsync(request.Email, request.ConfirmationCode);

                    if (result)
                    {
                        logger.LogInformation($"Email confirmed successfully for: {request.Email}");
                        return Results.Ok("Email confirmed successfully.");
                    }
                    else
                    {
                        logger.LogWarning($"Email confirmation failed for: {request.Email} with code: {request.ConfirmationCode}");
                        return Results.BadRequest("Invalid confirmation code or code has expired.");
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during email confirmation.");
                    return Results.Problem("An error occurred during email confirmation.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("ConfirmEmail")
            .WithTags("User");

            // Resend Confirmation Code Endpoint
            endpoints.MapPost("/resend-confirmation-code", async (ResendConfirmationCodeRequest request, UserService userService, EmailService emailService, ILogger<Program> logger) =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(request.Email))
                    {
                        return Results.BadRequest("Email is required.");
                    }

                    // Check if the email is blocked
                    if (await userService.IsBlockedAsync(request.Email))
                    {
                        return Results.BadRequest("Too many failed attempts. You cannot request a new code for 24 hours.");
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
                    var codeExpiresAt = DateTime.Now.AddMinutes(15);

                    // Save confirmation code and expiration time
                    await userService.SetEmailConfirmationCodeAsync(request.Email, confirmationCode, codeExpiresAt);

                    // Prepare placeholders for the template
                    var placeholders = new Dictionary<string, string>
                    {
                        { "ConfirmationCode", confirmationCode }
                    };

                    // Send email with the code using EmailService
                    await emailService.SendEmailAsync(
                        recipientEmail: request.Email,
                        subject: "Email Confirmation",
                        templateType: EmailService.EmailTemplateType.EmailConfirmation,
                        placeholders: placeholders
                    );

                    logger.LogInformation($"Resent confirmation code to {request.Email}");

                    return Results.Ok("If an account with that email exists, a new confirmation code has been sent.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during resending confirmation code.");
                    return Results.Problem("An error occurred during resending confirmation code.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("ResendConfirmationCode")
            .WithTags("User");

            // Forgot Password Endpoint
            endpoints.MapPost("/forgot-password", async (ForgotPasswordRequest request, UserService userService, EmailService emailService, ILogger<Program> logger) =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(request.Email))
                    {
                        return Results.BadRequest("Email is required.");
                    }

                    // Check if the email is blocked
                    if (await userService.IsBlockedAsync(request.Email))
                    {
                        return Results.BadRequest("Too many failed attempts. You cannot request a new code for 24 hours.");
                    }

                    // Check if user exists
                    if (!await userService.IsUserExistsAsync(request.Email))
                    {
                        // For security, return the same response whether the email exists or not
                        return Results.Ok("If an account with that email exists, a password reset code has been sent.");
                    }

                    // Generate reset code
                    var resetCode = new Random().Next(100000, 999999).ToString();

                    // Set code expiration time (e.g., 15 minutes from now)
                    var codeExpiresAt = DateTime.Now.AddMinutes(15);

                    // Save reset code and expiration time
                    await userService.SetPasswordResetCodeAsync(request.Email, resetCode, codeExpiresAt);

                    // Prepare placeholders for the template
                    var placeholders = new Dictionary<string, string>
                    {
                        { "ResetCode", resetCode }
                    };

                    // Send email with the code using EmailService
                    await emailService.SendEmailAsync(
                        recipientEmail: request.Email,
                        subject: "Password Reset Code",
                        templateType: EmailService.EmailTemplateType.PasswordReset,
                        placeholders: placeholders
                    );

                    logger.LogInformation($"Sent password reset code to {request.Email}");

                    return Results.Ok("If an account with that email exists, a password reset code has been sent.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during forgot password process.");
                    return Results.Problem("An error occurred during password reset process.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("ForgotPassword")
            .WithTags("User");

            // Reset Password Endpoint
            endpoints.MapPost("/reset-password", async (ResetPasswordRequest request, UserService userService, ILogger<Program> logger) =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code) || string.IsNullOrWhiteSpace(request.NewPassword))
                    {
                        return Results.BadRequest("Email, code, and new password are required.");
                    }

                    var result = await userService.ResetPasswordAsync(request.Email, request.Code, request.NewPassword);

                    if (result)
                    {
                        logger.LogInformation($"Password reset successfully for {request.Email}");
                        return Results.Ok("Password has been reset successfully.");
                    }
                    else
                    {
                        logger.LogWarning($"Password reset failed for {request.Email} with code {request.Code}");
                        return Results.BadRequest("Invalid code or code has expired.");
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during password reset.");
                    return Results.Problem("An error occurred during password reset.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("ResetPassword")
            .WithTags("User");

            // Change Email Endpoint
            endpoints.MapPost("/change-email", [Authorize] async (ChangeEmailRequest request, UserService userService, EmailService emailService, ClaimsPrincipal user, ILogger<Program> logger) =>
            {
                try
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
                    var codeExpiresAt = DateTime.Now.AddMinutes(15);

                    // Save new email, confirmation code, and expiration time
                    await userService.SetEmailChangeCodeAsync(currentEmail, request.NewEmail, confirmationCode, codeExpiresAt);

                    // Prepare placeholders for the email change confirmation template
                    var placeholdersConfirmation = new Dictionary<string, string>
                    {
                        { "ConfirmationCode", confirmationCode }
                    };

                    // Send email to the new email address
                    await emailService.SendEmailAsync(
                        recipientEmail: request.NewEmail,
                        subject: "Email Change Confirmation",
                        templateType: EmailService.EmailTemplateType.EmailChange,
                        placeholders: placeholdersConfirmation
                    );

                    // Prepare placeholders for the notification to the old email address
                    var placeholdersNotification = new Dictionary<string, string>
                    {
                        { "NewEmail", request.NewEmail }
                    };

                    // Send notification to the old email address
                    await emailService.SendEmailAsync(
                        recipientEmail: currentEmail,
                        subject: "Email Change Requested",
                        templateType: EmailService.EmailTemplateType.EmailChangeNotification,
                        placeholders: placeholdersNotification
                    );

                    logger.LogInformation($"Email change requested from {currentEmail} to {request.NewEmail}");

                    return Results.Ok("A confirmation code has been sent to your new email address. Please use it to confirm the change. A notification has been sent to your current email.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during email change.");
                    return Results.Problem("An error occurred during email change.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("ChangeEmail")
            .WithTags("User");

            // Confirm Email Change Endpoint
            endpoints.MapPost("/confirm-email-change", [Authorize] async (ConfirmEmailChangeRequest request, UserService userService, ClaimsPrincipal user, ILogger<Program> logger) =>
            {
                try
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
                        logger.LogInformation($"Email changed from {currentEmail} to new email.");
                        return Results.Ok("Email address has been changed successfully.");
                    }
                    else
                    {
                        logger.LogWarning($"Email change confirmation failed for {currentEmail} with code {request.Code}");
                        return Results.BadRequest("Invalid code or code has expired.");
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during email change confirmation.");
                    return Results.Problem("An error occurred during email change confirmation.", statusCode: StatusCodes.Status500InternalServerError);
                }
            })
            .WithName("ConfirmEmailChange")
            .WithTags("User");
        }
    }
}
