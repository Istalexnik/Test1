using Microsoft.AspNetCore.Authorization;
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
        endpoints.MapPost("/register", async (RegisterRequest request, UserService userService, ILogger<Program> logger, HttpContext context) =>
        {
            var validationResults = new List<ValidationResult>();
            var validationContext = new ValidationContext(request);

            if (!Validator.TryValidateObject(request, validationContext, validationResults, true))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new
                {
                    Message = "Validation failed",
                    Errors = validationResults.Select(vr => vr.ErrorMessage)
                });
                return;
            }

            try
            {
                await userService.RegisterUserAsync(request);
                context.Response.StatusCode = StatusCodes.Status201Created;
                await context.Response.WriteAsync("User registered successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while registering user.");
                if (ex.Message == "User already exists.")
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("User already exists.");
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    await context.Response.WriteAsync("An error occurred during registration.");
                }
            }
        })
        .WithName("RegisterUser")
        .WithTags("User");





        endpoints.MapPost("/login", async (LoginRequest request, UserService userService, JwtService jwtService, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                return Results.BadRequest("Username and password are required.");
            }

            try
            {
                if (!await userService.ValidateUserAsync(request))
                {
                    return Results.Unauthorized();
                }

                // Generate JWT token using JwtService
                var tokenString = jwtService.GenerateToken(request.Username);

                return Results.Ok(new { Token = tokenString });
            }
            catch (Exception)
            {
                return Results.Problem("An error occurred during login.", statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("Login")
        .WithTags("User");



        endpoints.MapGet("/userinfo", (ClaimsPrincipal user) =>
        {
            var username = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "Anonymous";
            return Results.Ok(new UserInfoResponse { Username = username });

        })
        .RequireAuthorization()
        .WithName("GetUserInfo")
        .WithTags("User");




    }
}

