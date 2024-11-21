using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApiHubTest1.Services;

public class JwtService
{
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly double _expiryMinutes;

    public JwtService(IConfiguration configuration)
    {
        var jwtSettings = configuration.GetSection("JwtSettings");

        _secretKey = jwtSettings["SecretKey"]
            ?? throw new InvalidOperationException("JWT SecretKey is missing in configuration.");
        _issuer = jwtSettings["Issuer"]
            ?? throw new InvalidOperationException("JWT Issuer is missing in configuration.");
        _audience = jwtSettings["Audience"]
            ?? throw new InvalidOperationException("JWT Audience is missing in configuration.");
        _expiryMinutes = double.TryParse(jwtSettings["ExpiryMinutes"], out var expiry) ? expiry : 60;
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey))
        };
    }


    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256);
    }

    public string GetIssuer() => _issuer;
    public string GetAudience() => _audience;

    public string GenerateToken(string username)
    {
        var signingCredentials = GetSigningCredentials();

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username)
            // Add additional claims if necessary
        };

        var tokenOptions = new JwtSecurityToken(
            issuer: GetIssuer(),
            audience: GetAudience(),
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_expiryMinutes),
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
    }
}
