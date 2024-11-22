using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
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
            builder.Services.AddSingleton<Encryption>();    // Singleton for reusable encryption logic
            builder.Services.AddScoped<DBTools>();          // Scoped for per-request database operations

            // Add connection string from appsettings.json
            var connectionString = builder.Configuration.GetConnectionString("WebApiHubTest1Connection");

            // Register UserService with Dependency Injection
            builder.Services.AddSingleton<UserService>(sp =>
            {
                var encryption = sp.GetRequiredService<Encryption>();
                var logger = sp.GetRequiredService<ILogger<UserService>>(); // Resolve ILogger
                return new UserService(connectionString!, logger, encryption); // Pass dependencies
            });

            // Register JwtService
            builder.Services.AddSingleton<JwtService>();

            // Get JWT settings from configuration
            var jwtSettings = builder.Configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey is missing in configuration.");

            // Configure Authentication and JWT
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                var key = Encoding.UTF8.GetBytes(secretKey);

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings["Issuer"],
                    ValidAudience = jwtSettings["Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
            });

            // Add Swagger services
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "MyWebApi", Version = "v1" });

                // Configure Swagger to use Bearer tokens
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme.\r\n\r\n" +
                                  "Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\n" +
                                  "Example: \"Bearer eyJhbGciOi...\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                           new OpenApiSecurityScheme
                           {
                               Reference = new OpenApiReference
                              {
                                 Type = ReferenceType.SecurityScheme,
                                 Id = "Bearer"
                              }
                           },
                           new string[] {}
                        }
                    });
            });

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            // Map the endpoints
            app.MapUserEndpoints();

            app.Run();
        }
    }
}
