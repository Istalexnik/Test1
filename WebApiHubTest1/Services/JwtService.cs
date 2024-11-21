using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace WebApiHubTest1.Services;

public class JwtService
{
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly string _audience;

    public JwtService(IConfiguration configuration)
    {
        var jwtSettings = configuration.GetSection("JwtSettings");

        _secretKey = jwtSettings["SecretKey"]
            ?? throw new InvalidOperationException("JWT SecretKey is missing in configuration.");
        _issuer = jwtSettings["Issuer"]
            ?? throw new InvalidOperationException("JWT Issuer is missing in configuration.");
        _audience = jwtSettings["Audience"]
            ?? throw new InvalidOperationException("JWT Audience is missing in configuration.");
    }

    public SymmetricSecurityKey GetSymmetricSecurityKey()
    {
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
    }

    public TokenValidationParameters GetTokenValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            IssuerSigningKey = GetSymmetricSecurityKey()
        };
    }

    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256);
    }

    public string GetIssuer() => _issuer;
    public string GetAudience() => _audience;
}
