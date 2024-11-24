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

    // Services/UserService.cs
    public async Task RegisterUserAsync(RegisterRequest request)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        using var transaction = connection.BeginTransaction();

        try
        {
            // Retrieve the user details
            var existingUser = await GetUserByEmailAsync(request.Email, connection, transaction);

            if (existingUser != null)
            {
                if (!existingUser.IsEmailConfirmed)
                {
                    // Delete the existing unconfirmed user
                    var deleteCommand = new SqlCommand(
                        "DELETE FROM tbl_users WHERE col_email = @Email",
                        connection,
                        transaction
                    );
                    deleteCommand.Parameters.AddWithValue("@Email", request.Email);

                    await deleteCommand.ExecuteNonQueryAsync();
                    _logger.LogInformation($"Deleted unconfirmed user with email: {request.Email}");
                }
                else
                {
                    throw new Exception("User already exists.");
                }
            }

            // Proceed with registration
            string encryptedPassword = _encryption.Encrypt(request.Password);

            var insertCommand = new SqlCommand(
                "INSERT INTO tbl_users (col_email, col_password_hash, col_is_email_confirmed) VALUES (@Email, @PasswordHash, 0)",
                connection,
                transaction
            );
            insertCommand.Parameters.AddWithValue("@Email", request.Email);
            insertCommand.Parameters.AddWithValue("@PasswordHash", encryptedPassword);

            await insertCommand.ExecuteNonQueryAsync();

            _logger.LogInformation($"Registered new user with email: {request.Email}");

            // Commit the transaction
            await transaction.CommitAsync();
        }
        catch
        {
            // Rollback the transaction in case of error
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


    // Services/UserService.cs
    public async Task<bool> ConfirmEmailAsync(string email, string code)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"SELECT col_email_confirmation_code, col_email_confirmation_code_expires_at, col_failed_attempts, col_code_request_blocked_until 
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
            var failedAttempts = reader["col_failed_attempts"] != DBNull.Value ? Convert.ToInt32(reader["col_failed_attempts"]) : 0;
            var blockedUntil = reader["col_code_request_blocked_until"] != DBNull.Value ? (DateTime?)reader["col_code_request_blocked_until"] : null;

            // Check if the email is currently blocked
            if (blockedUntil.HasValue && blockedUntil > DateTime.Now)
            {
                throw new Exception($"Code request is blocked until {blockedUntil.Value.ToString("g")}. Please try again later.");
            }

            if (storedCode == code && expiresAt >= DateTime.Now)
            {
                reader.Close();

                var updateCommand = new SqlCommand(
                    @"UPDATE tbl_users 
                  SET col_is_email_confirmed = 1, col_email_confirmation_code = NULL, col_email_confirmation_code_expires_at = NULL, col_failed_attempts = 0, col_code_request_blocked_until = NULL 
                  WHERE col_email = @Email",
                    connection
                );
                updateCommand.Parameters.AddWithValue("@Email", email);

                await updateCommand.ExecuteNonQueryAsync();

                _logger.LogInformation($"Email confirmed for: {email}");

                return true;
            }
            else
            {
                // Increment failed attempts
                failedAttempts++;
                reader.Close();

                var updateCommand = new SqlCommand(
                    @"UPDATE tbl_users 
                  SET col_failed_attempts = @FailedAttempts, 
                      col_code_request_blocked_until = CASE 
                          WHEN @FailedAttempts >= 3 THEN @BlockedUntil 
                          ELSE col_code_request_blocked_until 
                      END 
                  WHERE col_email = @Email",
                    connection
                );

                updateCommand.Parameters.AddWithValue("@Email", email);
                updateCommand.Parameters.AddWithValue("@FailedAttempts", failedAttempts);
                updateCommand.Parameters.AddWithValue("@BlockedUntil", DateTime.Now.AddHours(24));

                await updateCommand.ExecuteNonQueryAsync();
                return false;
            }
        }

        _logger.LogWarning($"Email confirmation failed for: {email} with code: {code}");

        return false;
    }


    public async Task<bool> IsBlockedAsync(string email)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var command = new SqlCommand(
            @"SELECT col_failed_attempts, col_code_request_blocked_until 
      FROM tbl_users 
      WHERE col_email = @Email",
            connection
        );

        command.Parameters.AddWithValue("@Email", email);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            var failedAttempts = reader["col_failed_attempts"] != DBNull.Value ? Convert.ToInt32(reader["col_failed_attempts"]) : 0;
            var blockedUntil = reader["col_code_request_blocked_until"] != DBNull.Value ? (DateTime?)reader["col_code_request_blocked_until"] : null;

            // Reset FailedAttempts if the block period has expired
            if (blockedUntil.HasValue && blockedUntil <= DateTime.Now)
            {
                reader.Close();

                var resetCommand = new SqlCommand(
                    @"UPDATE tbl_users 
                  SET col_failed_attempts = 0, 
                      col_code_request_blocked_until = NULL 
                  WHERE col_email = @Email",
                    connection
                );

                resetCommand.Parameters.AddWithValue("@Email", email);
                await resetCommand.ExecuteNonQueryAsync();

                return false; // Not blocked anymore
            }

            // If still within block period, return true (blocked)
            if (blockedUntil.HasValue && blockedUntil > DateTime.Now)
            {
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

            if (storedCode == code && expiresAt >= DateTime.Now)
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

            if (storedCode == code && expiresAt >= DateTime.Now && !string.IsNullOrEmpty(newEmail))
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


    // Services/UserService.cs
    public async Task<User?> GetUserByEmailAsync(string email, SqlConnection connection, SqlTransaction transaction)
    {
        var command = new SqlCommand(
            "SELECT col_id, col_email, col_is_email_confirmed FROM tbl_users WHERE col_email = @Email",
            connection,
            transaction
        );
        command.Parameters.AddWithValue("@Email", email);

        using var reader = await command.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return new User
            {
                Id = reader.GetInt32(reader.GetOrdinal("col_id")),
                Email = reader.GetString(reader.GetOrdinal("col_email")),
                IsEmailConfirmed = reader.GetBoolean(reader.GetOrdinal("col_is_email_confirmed"))
                // Initialize other fields as necessary
            };
        }

        return null;
    }


}
