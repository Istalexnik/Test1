using WebApiHubTest1.Data;
using WebApiHubTest1.Models;
using WebApiHubTest1.Services;

namespace WebApiHubTest1
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthorization();

            builder.Services.AddSingleton<Emailing>();      // Singleton for stateless email service
            builder.Services.AddSingleton<Encryption>();   // Singleton for reusable encryption logic
            builder.Services.AddScoped<DBTools>();        // Scoped for per-request database operations

            // Add connection string from appsettings.json
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

            // Register UserService with Dependency Injection
            builder.Services.AddSingleton(new UserService(connectionString!));

            var app = builder.Build();


            app.MapPost("/register", async (RegisterRequest request, UserService userService, HttpContext context) =>
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

            app.MapPost("/login", async (LoginRequest request, UserService userService, HttpContext context) =>
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

            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.Run();
        }
    }
}
