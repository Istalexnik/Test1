using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using WebApiHubTest1.Models;

namespace WebApiHubTest1.Services;

public class UserService
{
    private readonly string _connectionString;

    public UserService(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<bool> IsUserExistsAsync(string username)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT COUNT(*) FROM Users WHERE Username = @Username", connection);
        command.Parameters.AddWithValue("@Username", username);

        int count = (int)await command.ExecuteScalarAsync();
        return count > 0;
    }

    public async Task RegisterUserAsync(RegisterRequest request)
    {
        string passwordHash = HashPassword(request.Password);

        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("INSERT INTO Users (Username, PasswordHash) VALUES (@Username, @PasswordHash)", connection);
        command.Parameters.AddWithValue("@Username", request.Username);
        command.Parameters.AddWithValue("@PasswordHash", passwordHash);

        await command.ExecuteNonQueryAsync();
    }

    public async Task<bool> ValidateUserAsync(LoginRequest request)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT PasswordHash FROM Users WHERE Username = @Username", connection);
        command.Parameters.AddWithValue("@Username", request.Username);

        var result = await command.ExecuteScalarAsync();
        if (result == null)
            return false;

        string storedHash = result.ToString();
        return VerifyPassword(request.Password, storedHash);
    }

    private string HashPassword(string password)
    {
        byte[] salt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        byte[] hash = pbkdf2.GetBytes(32);

        byte[] hashBytes = new byte[48];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 32);

        return Convert.ToBase64String(hashBytes);
    }

    private bool VerifyPassword(string password, string storedHash)
    {
        byte[] hashBytes = Convert.FromBase64String(storedHash);

        byte[] salt = new byte[16];
        Array.Copy(hashBytes, 0, salt, 0, 16);

        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        byte[] hash = pbkdf2.GetBytes(32);

        for (int i = 0; i < 32; i++)
            if (hashBytes[i + 16] != hash[i])
                return false;

        return true;
    }
}
