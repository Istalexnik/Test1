using WebApiHubTest1.Models;
using WebApiHubTest1.Services;

namespace WebApiHubTest1.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/register", async (RegisterRequest request, UserService userService, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Username and password are required.");
                return;
            }

            if (await userService.IsUserExistsAsync(request.Username))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("User already exists.");
                return;
            }

            await userService.RegisterUserAsync(request);
            context.Response.StatusCode = StatusCodes.Status201Created;
            await context.Response.WriteAsync("User registered successfully.");
        });

        endpoints.MapPost("/login", async (LoginRequest request, UserService userService, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Username and password are required.");
                return;
            }

            if (!await userService.ValidateUserAsync(request))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Invalid username or password.");
                return;
            }

            context.Response.StatusCode = StatusCodes.Status200OK;
            await context.Response.WriteAsync("Login successful.");
        });
    }
}
