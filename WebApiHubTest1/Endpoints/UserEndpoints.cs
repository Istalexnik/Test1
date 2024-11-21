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
        endpoints.MapPost("/register", async (RegisterRequest request, UserService userService, HttpContext context) =>
        {
            var validationResults = new List<ValidationResult>();
            var validationContext = new ValidationContext(request);

            if (!Validator.TryValidateObject(request, validationContext, validationResults, true))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Validation failed: " + string.Join(", ", validationResults.Select(vr => vr.ErrorMessage)));
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

        endpoints.MapPost("/login", async (LoginRequest request, UserService userService, IConfiguration configuration, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Username and password are required.");
                return;
            }

            try
            {
                if (!await userService.ValidateUserAsync(request))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("Invalid username or password.");
                    return;
                }

                // Generate JWT token
                var jwtSettings = configuration.GetSection("JwtSettings");
                var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!));
                var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, request.Username)
                    // Add additional claims if necessary
                };

                var tokenOptions = new JwtSecurityToken(
                    issuer: jwtSettings["Issuer"],
                    audience: jwtSettings["Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpiryMinutes"])),
                    signingCredentials: signingCredentials
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.WriteAsJsonAsync(new { Token = tokenString });
            }
            catch
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("An error occurred during login.");
            }
        })
        .WithName("Login")
        .WithTags("User");

        endpoints.MapGet("/userinfo", [Authorize] (ClaimsPrincipal user) =>
        {
            var username = user.Identity?.Name;
            return Results.Ok(new { Username = username });
        })
        .WithName("GetUserInfo")
        .WithTags("User")
        .RequireAuthorization();
    }
}

