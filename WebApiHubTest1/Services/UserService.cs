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

        var command = new SqlCommand("SELECT COUNT(*) FROM tbl_users WHERE col_email = @Email", connection, transaction);
            command.Parameters.AddWithValue("@Email", email);

        int count = Convert.ToInt32(await command.ExecuteScalarAsync());

        return count > 0;
        }


    // Overloaded method that doesn't require connection and transaction
    public async Task<bool> IsUserExistsAsync(string email)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand("SELECT COUNT(*) FROM tbl_users WHERE col_email = @Email", connection);
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
                "INSERT INTO tbl_users (col_email, col_password_hash) VALUES (@Email, @PasswordHash)",
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

        var command = new SqlCommand("SELECT col_password_hash FROM tbl_users WHERE col_email = @Email", connection);
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
            "INSERT INTO tbl_refresh_tokens (col_user_id, col_token, col_expires_at, col_created_at) VALUES (@UserId, @Token, @ExpiresAt, @CreatedAt)",
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
            "SELECT * FROM tbl_refresh_tokens WHERE col_token = @Token",
            connection
        );

        command.Parameters.AddWithValue("@Token", token);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new RefreshToken
            {
                Id = reader.GetInt32(reader.GetOrdinal("col_id")),
                UserId = reader.GetInt32(reader.GetOrdinal("col_user_id")),
                Token = reader.GetString(reader.GetOrdinal("col_token")),
                ExpiresAt = reader.GetDateTime(reader.GetOrdinal("col_expires_at")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("col_created_at")),
                RevokedAt = reader.IsDBNull(reader.GetOrdinal("col_revoked_at")) ? null : reader.GetDateTime(reader.GetOrdinal("col_revoked_at")),
                ReplacedByToken = reader.IsDBNull(reader.GetOrdinal("col_replaced_by_token")) ? null : reader.GetString(reader.GetOrdinal("col_replaced_by_token"))
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
            "UPDATE tbl_refresh_tokens SET col_revoked_at = @RevokedAt, col_replaced_by_token = @ReplacedByToken WHERE col_token = @Token",
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

        var command = new SqlCommand("SELECT col_id FROM tbl_users WHERE col_email = @Email", connection);
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

        var command = new SqlCommand("SELECT col_email FROM tbl_users WHERE col_id = @UserId", connection);
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
            "UPDATE tbl_refresh_tokens SET col_revoked_at = @RevokedAt WHERE col_user_id = @UserId AND col_revoked_at IS NULL",
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
            @"UPDATE tbl_users 
          SET col_email_confirmation_code = @Code, col_email_confirmation_code_expires_at = @ExpiresAt 
          WHERE col_email = @Email",
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
            @"SELECT col_email_confirmation_code, col_email_confirmation_code_expires_at 
          FROM tbl_users 
          WHERE col_email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            var storedCode = reader["col_email_confirmation_code"] as string;
            var expiresAt = reader["col_email_confirmation_code_expires_at"] as DateTime?;

            if (storedCode == code && expiresAt >= DateTime.UtcNow)
            {
                reader.Close();

                var updateCommand = new SqlCommand(
                    @"UPDATE tbl_users 
                  SET col_is_email_confirmed = 1, col_email_confirmation_code = NULL, col_email_confirmation_code_expires_at = NULL 
                  WHERE col_email = @Email",
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
            @"SELECT col_is_email_confirmed 
          FROM tbl_users 
          WHERE col_email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);

        var result = await command.ExecuteScalarAsync();

        return result != null && result != DBNull.Value && Convert.ToBoolean(result);
    }



    public async Task SetPasswordResetCodeAsync(string email, string code, DateTime expiresAt)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"UPDATE tbl_users 
          SET col_password_reset_code = @Code, col_password_reset_code_expires_at = @ExpiresAt 
          WHERE col_email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);
        command.Parameters.AddWithValue("@Code", code);
        command.Parameters.AddWithValue("@ExpiresAt", expiresAt);

        await command.ExecuteNonQueryAsync();
    }


    public async Task<bool> ResetPasswordAsync(string email, string code, string newPassword)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"SELECT col_password_reset_code, col_password_reset_code_expires_at 
          FROM tbl_users 
          WHERE col_email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            var storedCode = reader["col_password_reset_code"] as string;
            var expiresAt = reader["col_password_reset_code_expires_at"] as DateTime?;

            if (storedCode == code && expiresAt >= DateTime.UtcNow)
            {
                reader.Close();

                // Encrypt the new password
                string encryptedPassword = _encryption.Encrypt(newPassword);

                var updateCommand = new SqlCommand(
                    @"UPDATE tbl_users 
                  SET col_password_hash = @PasswordHash, 
                      col_password_reset_code = NULL, 
                      col_password_reset_code_expires_at = NULL 
                  WHERE col_email = @Email",
                    connection
                );
                updateCommand.Parameters.AddWithValue("@Email", email);
                updateCommand.Parameters.AddWithValue("@PasswordHash", encryptedPassword);

                await updateCommand.ExecuteNonQueryAsync();

                return true;
            }
        }

        return false;
    }



    public async Task SetEmailChangeCodeAsync(string currentEmail, string newEmail, string code, DateTime expiresAt)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"UPDATE tbl_users 
          SET col_new_email = @NewEmail, 
              col_email_change_code = @Code, 
              col_email_change_code_expires_at = @ExpiresAt 
          WHERE col_email = @CurrentEmail",
            connection
        );

        command.Parameters.AddWithValue("@CurrentEmail", currentEmail);
        command.Parameters.AddWithValue("@NewEmail", newEmail);
        command.Parameters.AddWithValue("@Code", code);
        command.Parameters.AddWithValue("@ExpiresAt", expiresAt);

        await command.ExecuteNonQueryAsync();
    }



    public async Task<bool> ConfirmEmailChangeAsync(string currentEmail, string code)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"SELECT col_new_email, col_email_change_code, col_email_change_code_expires_at 
          FROM tbl_users 
          WHERE col_email = @CurrentEmail",
            connection
        );

        command.Parameters.AddWithValue("@CurrentEmail", currentEmail);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            var newEmail = reader["col_new_email"] as string;
            var storedCode = reader["col_email_change_code"] as string;
            var expiresAt = reader["col_email_change_code_expires_at"] as DateTime?;

            if (storedCode == code && expiresAt >= DateTime.UtcNow && !string.IsNullOrEmpty(newEmail))
            {
                reader.Close();

                // Check if new email is already in use
                if (await IsUserExistsAsync(newEmail))
                {
                    return false; // New email is already taken
                }

                var updateCommand = new SqlCommand(
                    @"UPDATE tbl_users 
                  SET col_email = @NewEmail, 
                      col_new_email = NULL, 
                      col_email_change_code = NULL, 
                      col_Email_change_code_expires_at = NULL 
                  WHERE col_email = @CurrentEmail",
                    connection
                );
                updateCommand.Parameters.AddWithValue("@CurrentEmail", currentEmail);
                updateCommand.Parameters.AddWithValue("@NewEmail", newEmail);

                await updateCommand.ExecuteNonQueryAsync();

                return true;
            }
        }

        return false;
    }




}
