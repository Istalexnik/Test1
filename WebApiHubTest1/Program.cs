using WebApiHubTest1.Data;
using WebApiHubTest1.Endpoints;
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
            builder.Services.AddLogging();

            builder.Services.AddSingleton<Emailing>();      // Singleton for stateless email service
            builder.Services.AddSingleton<Encryption>();   // Singleton for reusable encryption logic
            builder.Services.AddScoped<DBTools>();        // Scoped for per-request database operations


            // Add connection string from appsettings.json
            var connectionString = builder.Configuration.GetConnectionString("WebApiHubTest1Connection");

            // Register UserService with Dependency Injection
            builder.Services.AddSingleton<UserService>(sp =>
            {
                var encryption = sp.GetRequiredService<Encryption>();
                var logger = sp.GetRequiredService<ILogger<UserService>>(); // Resolve ILogger
                return new UserService(connectionString!, logger, encryption); // Pass dependencies
            });

            var app = builder.Build();

            // Map the endpoints
            app.MapUserEndpoints();

            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.Run();
        }
    }
}
