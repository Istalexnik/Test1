using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using WebApiHubTest1.Models;

namespace WebApiHubTest1.Services;

public class UserService
{
    private readonly string _connectionString;
    private readonly ILogger<UserService> _logger;
    private readonly Encryption _encryption;

    public UserService(string connectionString, ILogger<UserService> logger, Encryption encryption)
    {
        _connectionString = connectionString;
        _logger = logger;
        _encryption = encryption;
    }

        public async Task<bool> IsUserExistsAsync(string email, SqlConnection connection, SqlTransaction transaction)
        {

        var command = new SqlCommand("SELECT COUNT(*) FROM Users WHERE Email = @Email", connection, transaction);
            command.Parameters.AddWithValue("@Email", email);

        int count = Convert.ToInt32(await command.ExecuteScalarAsync());

        return count > 0;
        }


    // Overloaded method that doesn't require connection and transaction
    public async Task<bool> IsUserExistsAsync(string email)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT COUNT(*) FROM Users WHERE Email = @Email", connection);
        command.Parameters.AddWithValue("@Email", email);

        int count = Convert.ToInt32(await command.ExecuteScalarAsync());

        return count > 0;
    }

    public async Task RegisterUserAsync(RegisterRequest request)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        using var transaction = connection.BeginTransaction();

        try
        {
            // Check if user exists within the transaction
            if (await IsUserExistsAsync(request.Email, connection, transaction))
            {
                throw new Exception("User already exists.");
            }

            string encryptedPassword = _encryption.Encrypt(request.Password);

            var command = new SqlCommand(
                "INSERT INTO Users (Email, PasswordHash) VALUES (@Email, @PasswordHash)",
                connection,
                transaction
            );
            command.Parameters.AddWithValue("@Email", request.Email);
            command.Parameters.AddWithValue("@PasswordHash", encryptedPassword);

            await command.ExecuteNonQueryAsync();

            // Commit the transaction
            await transaction.CommitAsync();
        }
        catch
        {
            // Rollback the transaction
            await transaction.RollbackAsync();
            throw; // Re-throw the exception to be handled by the calling code
        }
    }


    public async Task<bool> ValidateUserAsync(LoginRequest request)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT PasswordHash FROM Users WHERE Email = @Email", connection);
        command.Parameters.AddWithValue("@Email", request.Email);

        var result = await command.ExecuteScalarAsync();

        if (result == null || result == DBNull.Value)
            return false;

        string storedEncryptedPassword = (string)result;
        string decryptedPassword = _encryption.Decrypt(storedEncryptedPassword);

        return decryptedPassword == request.Password;
    }


    // Method to save a refresh token
    public async Task SaveRefreshTokenAsync(int userId, RefreshToken refreshToken)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            "INSERT INTO RefreshTokens (UserId, Token, ExpiresAt, CreatedAt) VALUES (@UserId, @Token, @ExpiresAt, @CreatedAt)",
            connection
        );

        command.Parameters.AddWithValue("@UserId", userId);
        command.Parameters.AddWithValue("@Token", refreshToken.Token);
        command.Parameters.AddWithValue("@ExpiresAt", refreshToken.ExpiresAt);
        command.Parameters.AddWithValue("@CreatedAt", refreshToken.CreatedAt);

        await command.ExecuteNonQueryAsync();
    }


    // Method to get a refresh token
    public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            "SELECT * FROM RefreshTokens WHERE Token = @Token",
            connection
        );

        command.Parameters.AddWithValue("@Token", token);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new RefreshToken
            {
                Id = reader.GetInt32(reader.GetOrdinal("Id")),
                UserId = reader.GetInt32(reader.GetOrdinal("UserId")),
                Token = reader.GetString(reader.GetOrdinal("Token")),
                ExpiresAt = reader.GetDateTime(reader.GetOrdinal("ExpiresAt")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("CreatedAt")),
                RevokedAt = reader.IsDBNull(reader.GetOrdinal("RevokedAt")) ? null : reader.GetDateTime(reader.GetOrdinal("RevokedAt")),
                ReplacedByToken = reader.IsDBNull(reader.GetOrdinal("ReplacedByToken")) ? null : reader.GetString(reader.GetOrdinal("ReplacedByToken"))
            };
        }

        return null;
    }


    // Method to revoke a refresh token
    public async Task RevokeRefreshTokenAsync(string token, string? replacedByToken = null)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            "UPDATE RefreshTokens SET RevokedAt = @RevokedAt, ReplacedByToken = @ReplacedByToken WHERE Token = @Token",
            connection
        );

        command.Parameters.AddWithValue("@Token", token);
        command.Parameters.AddWithValue("@RevokedAt", DateTime.Now);
        command.Parameters.AddWithValue("@ReplacedByToken", replacedByToken ?? (object)DBNull.Value);

        await command.ExecuteNonQueryAsync();
    }



    public async Task<int> GetUserIdAsync(string email)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT Id FROM Users WHERE Email = @Email", connection);
        command.Parameters.AddWithValue("@Email", email);

        var result = await command.ExecuteScalarAsync();

        if (result != null && result != DBNull.Value)
        {
            return Convert.ToInt32(result);
        }

        throw new Exception("User not found.");
    }


    public async Task<string> GetEmailByIdAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT Email FROM Users WHERE Id = @UserId", connection);
        command.Parameters.AddWithValue("@UserId", userId);

        var result = await command.ExecuteScalarAsync();

        if (result != null && result != DBNull.Value)
        {
            return result.ToString()!;
        }

        throw new Exception("User not found.");
    }


    public async Task RevokeAllRefreshTokensAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            "UPDATE RefreshTokens SET RevokedAt = @RevokedAt WHERE UserId = @UserId AND RevokedAt IS NULL",
            connection
        );

        command.Parameters.AddWithValue("@UserId", userId);
        command.Parameters.AddWithValue("@RevokedAt", DateTime.Now);

        await command.ExecuteNonQueryAsync();
    }



    public async Task SetEmailConfirmationCodeAsync(string email, string code, DateTime expiresAt)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"UPDATE Users 
          SET EmailConfirmationCode = @Code, EmailConfirmationCodeExpiresAt = @ExpiresAt 
          WHERE Email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);
        command.Parameters.AddWithValue("@Code", code);
        command.Parameters.AddWithValue("@ExpiresAt", expiresAt);

        await command.ExecuteNonQueryAsync();
    }


    public async Task<bool> ConfirmEmailAsync(string email, string code)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"SELECT EmailConfirmationCode, EmailConfirmationCodeExpiresAt 
          FROM Users 
          WHERE Email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            var storedCode = reader["EmailConfirmationCode"] as string;
            var expiresAt = reader["EmailConfirmationCodeExpiresAt"] as DateTime?;

            if (storedCode == code && expiresAt >= DateTime.UtcNow)
            {
                reader.Close();

                var updateCommand = new SqlCommand(
                    @"UPDATE Users 
                  SET IsEmailConfirmed = 1, EmailConfirmationCode = NULL, EmailConfirmationCodeExpiresAt = NULL 
                  WHERE Email = @Email",
                    connection
                );
                updateCommand.Parameters.AddWithValue("@Email", email);

                await updateCommand.ExecuteNonQueryAsync();

                return true;
            }
        }

        return false;
    }


    public async Task<bool> IsEmailConfirmedAsync(string email)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"SELECT IsEmailConfirmed 
          FROM Users 
          WHERE Email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);

        var result = await command.ExecuteScalarAsync();

        return result != null && result != DBNull.Value && Convert.ToBoolean(result);
    }




}
