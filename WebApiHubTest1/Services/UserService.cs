using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WebApiHubTest1.Data;
using WebApiHubTest1.Models;

namespace WebApiHubTest1.Services
{
    public class UserService
    {
        private readonly DBTools _dbTools;
        private readonly ILogger<UserService> _logger;
        private readonly Encryption _encryption;

        public UserService(DBTools dbTools, ILogger<UserService> logger, Encryption encryption)
        {
            _dbTools = dbTools;
            _logger = logger;
            _encryption = encryption;
        }

        public async Task<bool> IsUserExistsAsync(string email)
        {
            string query = "SELECT COUNT(*) FROM tbl_users WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email)
            };

            var result = await _dbTools.RunTextScalarAsync(query, parameters);
            int count = Convert.ToInt32(result);

            return count > 0;
        }

        public async Task RegisterUserAsync(RegisterRequest request)
        {
            try
            {
                if (await IsUserExistsAsync(request.Email))
                {
                    throw new Exception("User already exists.");
                }

                string encryptedPassword = _encryption.Encrypt(request.Password);

                string query = "INSERT INTO tbl_users (col_email, col_password_hash, col_is_email_confirmed) VALUES (@Email, @PasswordHash, 0)";
                var parameters = new List<SqlParameter>
                {
                    new SqlParameter("@Email", request.Email),
                    new SqlParameter("@PasswordHash", encryptedPassword)
                };

                await _dbTools.RunTextNonQueryAsync(query, parameters);

                _logger.LogInformation($"Registered new user with email: {request.Email}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error occurred while registering user with email: {request.Email}");
                throw;
            }
        }

        public async Task<bool> ValidateUserAsync(LoginRequest request)
        {
            string query = "SELECT col_password_hash FROM tbl_users WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", request.Email)
            };

            var result = await _dbTools.RunTextScalarAsync(query, parameters);

            if (result == null || result == DBNull.Value)
                return false;

            string storedEncryptedPassword = (string)result;
            string decryptedPassword = _encryption.Decrypt(storedEncryptedPassword);

            return decryptedPassword == request.Password;
        }

        public async Task<int> GetUserIdAsync(string email)
        {
            string query = "SELECT col_id FROM tbl_users WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email)
            };

            var result = await _dbTools.RunTextScalarAsync(query, parameters);

            if (result != null && result != DBNull.Value)
            {
                return Convert.ToInt32(result);
            }

            throw new Exception("User not found.");
        }

        public async Task<string> GetEmailByIdAsync(int userId)
        {
            string query = "SELECT col_email FROM tbl_users WHERE col_id = @UserId";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@UserId", userId)
            };

            var result = await _dbTools.RunTextScalarAsync(query, parameters);

            if (result != null && result != DBNull.Value)
            {
                return result.ToString()!;
            }

            throw new Exception("User not found.");
        }

        public async Task SaveRefreshTokenAsync(int userId, RefreshToken refreshToken)
        {
            string query = @"INSERT INTO tbl_refresh_tokens 
                             (col_user_id, col_token, col_expires_at, col_created_at) 
                             VALUES (@UserId, @Token, @ExpiresAt, @CreatedAt)";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@UserId", userId),
                new SqlParameter("@Token", refreshToken.Token),
                new SqlParameter("@ExpiresAt", refreshToken.ExpiresAt),
                new SqlParameter("@CreatedAt", refreshToken.CreatedAt)
            };

            await _dbTools.RunTextNonQueryAsync(query, parameters);
        }

        public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
        {
            string query = "SELECT * FROM tbl_refresh_tokens WHERE col_token = @Token";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Token", token)
            };

            using var reader = await _dbTools.RunTextReaderAsync(query, parameters);

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

        public async Task RevokeRefreshTokenAsync(string token, string? replacedByToken = null)
        {
            string query = @"UPDATE tbl_refresh_tokens 
                             SET col_revoked_at = @RevokedAt, col_replaced_by_token = @ReplacedByToken 
                             WHERE col_token = @Token";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Token", token),
                new SqlParameter("@RevokedAt", DateTime.Now),
                new SqlParameter("@ReplacedByToken", (object?)replacedByToken ?? DBNull.Value)
            };

            await _dbTools.RunTextNonQueryAsync(query, parameters);
        }

        public async Task RevokeAllRefreshTokensAsync(int userId)
        {
            string query = @"UPDATE tbl_refresh_tokens 
                             SET col_revoked_at = @RevokedAt 
                             WHERE col_user_id = @UserId AND col_revoked_at IS NULL";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@UserId", userId),
                new SqlParameter("@RevokedAt", DateTime.Now)
            };

            await _dbTools.RunTextNonQueryAsync(query, parameters);
        }

        public async Task SetEmailConfirmationCodeAsync(string email, string code, DateTime expiresAt)
        {
            string query = @"UPDATE tbl_users 
                             SET col_email_confirmation_code = @Code, 
                                 col_email_confirmation_code_expires_at = @ExpiresAt 
                             WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email),
                new SqlParameter("@Code", code),
                new SqlParameter("@ExpiresAt", expiresAt)
            };

            await _dbTools.RunTextNonQueryAsync(query, parameters);
        }

        public async Task<bool> ConfirmEmailAsync(string email, string code)
        {
            string query = @"SELECT col_email_confirmation_code, 
                                    col_email_confirmation_code_expires_at, 
                                    col_failed_attempts, 
                                    col_code_request_blocked_until 
                             FROM tbl_users 
                             WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email)
            };

            using var reader = await _dbTools.RunTextReaderAsync(query, parameters);

            if (await reader.ReadAsync())
            {
                var storedCode = reader["col_email_confirmation_code"] as string;
                var expiresAt = reader["col_email_confirmation_code_expires_at"] as DateTime?;
                var failedAttempts = reader["col_failed_attempts"] != DBNull.Value ? Convert.ToInt32(reader["col_failed_attempts"]) : 0;
                var blockedUntil = reader["col_code_request_blocked_until"] != DBNull.Value ? (DateTime?)reader["col_code_request_blocked_until"] : null;

                if (blockedUntil.HasValue && blockedUntil > DateTime.Now)
                {
                    throw new Exception($"Code request is blocked until {blockedUntil.Value:g}. Please try again later.");
                }

                if (storedCode == code && expiresAt >= DateTime.Now)
                {
                    reader.Close();

                    string updateQuery = @"UPDATE tbl_users 
                                           SET col_is_email_confirmed = 1, 
                                               col_email_confirmation_code = NULL, 
                                               col_email_confirmation_code_expires_at = NULL, 
                                               col_failed_attempts = 0, 
                                               col_code_request_blocked_until = NULL 
                                           WHERE col_email = @Email";
                    var updateParameters = new List<SqlParameter>
                    {
                        new SqlParameter("@Email", email)
                    };

                    await _dbTools.RunTextNonQueryAsync(updateQuery, updateParameters);

                    _logger.LogInformation($"Email confirmed for: {email}");

                    return true;
                }
                else
                {
                    // Increment failed attempts
                    failedAttempts++;
                    reader.Close();

                    string updateQuery = @"UPDATE tbl_users 
                                           SET col_failed_attempts = @FailedAttempts, 
                                               col_code_request_blocked_until = CASE 
                                                   WHEN @FailedAttempts >= 3 THEN @BlockedUntil 
                                                   ELSE col_code_request_blocked_until 
                                               END 
                                           WHERE col_email = @Email";
                    var updateParameters = new List<SqlParameter>
                    {
                        new SqlParameter("@Email", email),
                        new SqlParameter("@FailedAttempts", failedAttempts),
                        new SqlParameter("@BlockedUntil", DateTime.Now.AddHours(24))
                    };

                    await _dbTools.RunTextNonQueryAsync(updateQuery, updateParameters);
                    return false;
                }
            }

            _logger.LogWarning($"Email confirmation failed for: {email} with code: {code}");
            return false;
        }

        public async Task<bool> IsBlockedAsync(string email)
        {
            string query = @"SELECT col_failed_attempts, col_code_request_blocked_until 
                             FROM tbl_users 
                             WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email)
            };

            using var reader = await _dbTools.RunTextReaderAsync(query, parameters);

            if (await reader.ReadAsync())
            {
                var failedAttempts = reader["col_failed_attempts"] != DBNull.Value ? Convert.ToInt32(reader["col_failed_attempts"]) : 0;
                var blockedUntil = reader["col_code_request_blocked_until"] != DBNull.Value ? (DateTime?)reader["col_code_request_blocked_until"] : null;

                if (blockedUntil.HasValue && blockedUntil <= DateTime.Now)
                {
                    reader.Close();

                    string resetQuery = @"UPDATE tbl_users 
                                          SET col_failed_attempts = 0, 
                                              col_code_request_blocked_until = NULL 
                                          WHERE col_email = @Email";
                    var resetParameters = new List<SqlParameter>
                    {
                        new SqlParameter("@Email", email)
                    };

                    await _dbTools.RunTextNonQueryAsync(resetQuery, resetParameters);

                    return false;
                }

                if (blockedUntil.HasValue && blockedUntil > DateTime.Now)
                {
                    return true;
                }
            }

            return false;
        }

        public async Task<bool> IsEmailConfirmedAsync(string email)
        {
            string query = @"SELECT col_is_email_confirmed 
                             FROM tbl_users 
                             WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email)
            };

            var result = await _dbTools.RunTextScalarAsync(query, parameters);

            return result != null && result != DBNull.Value && Convert.ToBoolean(result);
        }

        public async Task SetPasswordResetCodeAsync(string email, string code, DateTime expiresAt)
        {
            string query = @"UPDATE tbl_users 
                             SET col_password_reset_code = @Code, 
                                 col_password_reset_code_expires_at = @ExpiresAt 
                             WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email),
                new SqlParameter("@Code", code),
                new SqlParameter("@ExpiresAt", expiresAt)
            };

            await _dbTools.RunTextNonQueryAsync(query, parameters);
        }

        public async Task<bool> ResetPasswordAsync(string email, string code, string newPassword)
        {
            string query = @"SELECT col_password_reset_code, col_password_reset_code_expires_at 
                             FROM tbl_users 
                             WHERE col_email = @Email";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@Email", email)
            };

            using var reader = await _dbTools.RunTextReaderAsync(query, parameters);

            if (await reader.ReadAsync())
            {
                var storedCode = reader["col_password_reset_code"] as string;
                var expiresAt = reader["col_password_reset_code_expires_at"] as DateTime?;

                if (storedCode == code && expiresAt >= DateTime.Now)
                {
                    reader.Close();

                    string encryptedPassword = _encryption.Encrypt(newPassword);

                    string updateQuery = @"UPDATE tbl_users 
                                           SET col_password_hash = @PasswordHash, 
                                               col_password_reset_code = NULL, 
                                               col_password_reset_code_expires_at = NULL 
                                           WHERE col_email = @Email";
                    var updateParameters = new List<SqlParameter>
                    {
                        new SqlParameter("@Email", email),
                        new SqlParameter("@PasswordHash", encryptedPassword)
                    };

                    await _dbTools.RunTextNonQueryAsync(updateQuery, updateParameters);

                    return true;
                }
            }

            return false;
        }

        public async Task SetEmailChangeCodeAsync(string currentEmail, string newEmail, string code, DateTime expiresAt)
        {
            string query = @"UPDATE tbl_users 
                             SET col_new_email = @NewEmail, 
                                 col_email_change_code = @Code, 
                                 col_email_change_code_expires_at = @ExpiresAt 
                             WHERE col_email = @CurrentEmail";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@CurrentEmail", currentEmail),
                new SqlParameter("@NewEmail", newEmail),
                new SqlParameter("@Code", code),
                new SqlParameter("@ExpiresAt", expiresAt)
            };

            await _dbTools.RunTextNonQueryAsync(query, parameters);
        }

        public async Task<bool> ConfirmEmailChangeAsync(string currentEmail, string code)
        {
            string query = @"SELECT col_new_email, col_email_change_code, col_email_change_code_expires_at 
                             FROM tbl_users 
                             WHERE col_email = @CurrentEmail";
            var parameters = new List<SqlParameter>
            {
                new SqlParameter("@CurrentEmail", currentEmail)
            };

            using var reader = await _dbTools.RunTextReaderAsync(query, parameters);

            if (await reader.ReadAsync())
            {
                var newEmail = reader["col_new_email"] as string;
                var storedCode = reader["col_email_change_code"] as string;
                var expiresAt = reader["col_email_change_code_expires_at"] as DateTime?;

                if (storedCode == code && expiresAt >= DateTime.Now && !string.IsNullOrEmpty(newEmail))
                {
                    reader.Close();

                    if (await IsUserExistsAsync(newEmail))
                    {
                        return false; // New email is already taken
                    }

                    string updateQuery = @"UPDATE tbl_users 
                                           SET col_email = @NewEmail, 
                                               col_new_email = NULL, 
                                               col_email_change_code = NULL, 
                                               col_email_change_code_expires_at = NULL 
                                           WHERE col_email = @CurrentEmail";
                    var updateParameters = new List<SqlParameter>
                    {
                        new SqlParameter("@CurrentEmail", currentEmail),
                        new SqlParameter("@NewEmail", newEmail)
                    };

                    await _dbTools.RunTextNonQueryAsync(updateQuery, updateParameters);

                    return true;
                }
            }

            return false;
        }
    }
}
