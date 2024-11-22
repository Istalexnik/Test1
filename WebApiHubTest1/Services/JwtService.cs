using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApiHubTest1.Models;

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

    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256);
    }

    public string GenerateToken(string email)
    {
        var signingCredentials = GetSigningCredentials();

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, email)
            // Add additional claims if necessary
        };

        var tokenOptions = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(_expiryMinutes),
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
    }

    public RefreshToken GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);

        return new RefreshToken
        {
            Token = Convert.ToBase64String(randomNumber),
            ExpiresAt = DateTime.Now.AddDays(7), // Set refresh token expiration
            CreatedAt = DateTime.Now
        };
    }
}
