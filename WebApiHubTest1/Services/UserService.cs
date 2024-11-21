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

        public async Task<bool> IsUserExistsAsync(string username, SqlConnection connection, SqlTransaction transaction)
        {

        var command = new SqlCommand("SELECT COUNT(*) FROM Users WHERE Username = @Username", connection, transaction);
            command.Parameters.AddWithValue("@Username", username);

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
            if (await IsUserExistsAsync(request.Username, connection, transaction))
            {
                throw new Exception("User already exists.");
            }

            string encryptedPassword = _encryption.Encrypt(request.Password);

            var command = new SqlCommand(
                "INSERT INTO Users (Username, PasswordHash) VALUES (@Username, @PasswordHash)",
                connection,
                transaction
            );
            command.Parameters.AddWithValue("@Username", request.Username);
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

        var command = new SqlCommand("SELECT PasswordHash FROM Users WHERE Username = @Username", connection);
        command.Parameters.AddWithValue("@Username", request.Username);

        var result = await command.ExecuteScalarAsync();

        if (result == null || result == DBNull.Value)
            return false;

        string storedEncryptedPassword = (string)result;
        string decryptedPassword = _encryption.Decrypt(storedEncryptedPassword);

        return decryptedPassword == request.Password;
    }

}
