using Microsoft.Data.SqlClient;

namespace WebApiHubTest1.Data
{
    public class DBTools
    {
        private readonly string _connectionString;

        public DBTools(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
        }
        public int RunTextNonQuery(string text, List<SqlParameter>? lParam = null)
        {
            using (SqlConnection con = new SqlConnection(_connectionString))
            {
                using (SqlCommand cmd = new SqlCommand(text, con))
                {
                    cmd.CommandType = System.Data.CommandType.Text;
                    if (lParam != null)
                    {
                        cmd.Parameters.AddRange(lParam.ToArray());
                    }
                    con.Open();
                    return cmd.ExecuteNonQuery();
                }
            }
        }


        public int RunProcNonQuery(string proc, List<SqlParameter>? lParam = null)
        {
            using (SqlConnection con = new SqlConnection(_connectionString))
            {
                using (SqlCommand cmd = new SqlCommand(proc, con))
                {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    if (lParam != null)
                    {
                        cmd.Parameters.AddRange(lParam.ToArray());
                    }
                    con.Open();
                    return cmd.ExecuteNonQuery();
                }
            }
        }


        public object RunProcScalar(string proc, List<SqlParameter>? lParam = null)
        {
            using (SqlConnection con = new SqlConnection(_connectionString))
            {
                using (SqlCommand cmd = new SqlCommand(proc, con))
                {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    if (lParam != null)
                    {
                        cmd.Parameters.AddRange(lParam.ToArray());
                    }
                    con.Open();
                    return cmd.ExecuteScalar();
                }
            }
        }


        public SqlDataReader RunProcReader(string proc, List<SqlParameter>? lParam = null)
        {
            SqlConnection con = new SqlConnection(_connectionString);
            using (SqlCommand cmd = new SqlCommand(proc, con))
            {
                cmd.CommandType = System.Data.CommandType.StoredProcedure;
                if (lParam != null)
                {
                    cmd.Parameters.AddRange(lParam.ToArray());
                }
                con.Open();
                return cmd.ExecuteReader(System.Data.CommandBehavior.CloseConnection);
            }
        }


    }
}