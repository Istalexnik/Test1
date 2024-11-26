using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace WebApiHubTest1.Data
{
    public class DBTools
    {
        private readonly string _connectionString;

        public DBTools(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("WebApiHubTest1Connection")
                ?? throw new InvalidOperationException("Connection string 'WebApiHubTest1Connection' not found.");
        }

        // Asynchronous method for executing text queries that do not return results
        public async Task<int> RunTextNonQueryAsync(string text, List<SqlParameter>? parameters = null)
        {
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(text, connection);
            command.CommandType = System.Data.CommandType.Text;

            if (parameters != null)
                command.Parameters.AddRange(parameters.ToArray());

            await connection.OpenAsync();
            return await command.ExecuteNonQueryAsync();
        }

        // Asynchronous method for executing stored procedures that do not return results
        public async Task<int> RunProcNonQueryAsync(string procName, List<SqlParameter>? parameters = null)
        {
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(procName, connection);
            command.CommandType = System.Data.CommandType.StoredProcedure;

            if (parameters != null)
                command.Parameters.AddRange(parameters.ToArray());

            await connection.OpenAsync();
            return await command.ExecuteNonQueryAsync();
        }

        // Asynchronous method for executing text queries that return a scalar value
        public async Task<object?> RunTextScalarAsync(string text, List<SqlParameter>? parameters = null)
        {
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(text, connection);
            command.CommandType = System.Data.CommandType.Text;

            if (parameters != null)
                command.Parameters.AddRange(parameters.ToArray());

            await connection.OpenAsync();
            return await command.ExecuteScalarAsync();
        }

        // Asynchronous method for executing stored procedures that return a scalar value
        public async Task<object?> RunProcScalarAsync(string procName, List<SqlParameter>? parameters = null)
        {
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(procName, connection);
            command.CommandType = System.Data.CommandType.StoredProcedure;

            if (parameters != null)
                command.Parameters.AddRange(parameters.ToArray());

            await connection.OpenAsync();
            return await command.ExecuteScalarAsync();
        }

        // Asynchronous method for executing text queries that return a data reader
        public async Task<SqlDataReader> RunTextReaderAsync(string text, List<SqlParameter>? parameters = null)
        {
            var connection = new SqlConnection(_connectionString);
            var command = new SqlCommand(text, connection);
            command.CommandType = System.Data.CommandType.Text;

            if (parameters != null)
                command.Parameters.AddRange(parameters.ToArray());

            await connection.OpenAsync();
            var reader = await command.ExecuteReaderAsync(System.Data.CommandBehavior.CloseConnection);
            return reader;
        }

        // Asynchronous method for executing stored procedures that return a data reader
        public async Task<SqlDataReader> RunProcReaderAsync(string procName, List<SqlParameter>? parameters = null)
        {
            var connection = new SqlConnection(_connectionString);
            var command = new SqlCommand(procName, connection);
            command.CommandType = System.Data.CommandType.StoredProcedure;

            if (parameters != null)
                command.Parameters.AddRange(parameters.ToArray());

            await connection.OpenAsync();
            var reader = await command.ExecuteReaderAsync(System.Data.CommandBehavior.CloseConnection);
            return reader;
        }
    }
}
