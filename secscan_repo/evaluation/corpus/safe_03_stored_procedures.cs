// safe_03_stored_procedures.cs
// GROUND TRUTH: 0 VULNERABLE methods, 4 SAFE methods
// Patterns: stored procedure calls via CommandType.StoredProcedure
// Domain: Finance / accounting
// Expected tool output: 0 findings — tests whether stored proc style is correctly ignored

using System;
using System.Data;
using System.Data.SqlClient;

namespace Finance.Data
{
    public class AccountingRepository
    {
        private readonly string _conn;
        public AccountingRepository(string conn) { _conn = conn; }

        // SAFE: stored procedure with AddWithValue params
        public DataTable GetInvoicesByClient(int clientId, string status, DateTime fromDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand("usp_GetInvoicesByClient", conn);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@ClientId", clientId);
                cmd.Parameters.AddWithValue("@Status",   status);
                cmd.Parameters.AddWithValue("@FromDate", fromDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: stored procedure with SqlParameter objects
        public DataTable GetGeneralLedger(int accountId, int fiscalYear, int period)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand("usp_GetGeneralLedger", conn);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.Add(new SqlParameter("@AccountId",  SqlDbType.Int) { Value = accountId });
                cmd.Parameters.Add(new SqlParameter("@FiscalYear", SqlDbType.Int) { Value = fiscalYear });
                cmd.Parameters.Add(new SqlParameter("@Period",     SqlDbType.Int) { Value = period });
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: stored procedure with output parameter
        public decimal GetAccountBalance(int accountId, DateTime asOfDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand("usp_GetAccountBalance", conn);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@AccountId", accountId);
                cmd.Parameters.AddWithValue("@AsOfDate",  asOfDate);
                var balParam = new SqlParameter("@Balance", SqlDbType.Decimal)
                {
                    Direction = ParameterDirection.Output,
                    Precision = 18,
                    Scale     = 2
                };
                cmd.Parameters.Add(balParam);
                cmd.ExecuteNonQuery();
                return (decimal)balParam.Value;
            }
        }

        // SAFE: stored procedure inside transaction
        public void PostJournalEntry(int accountDebit, int accountCredit, decimal amount, string description)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand("usp_PostJournalEntry", conn, tx);
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@AccountDebit",  accountDebit);
                    cmd.Parameters.AddWithValue("@AccountCredit", accountCredit);
                    cmd.Parameters.AddWithValue("@Amount",        amount);
                    cmd.Parameters.AddWithValue("@Description",   description);
                    cmd.Parameters.AddWithValue("@PostedDate",    DateTime.UtcNow);
                    cmd.ExecuteNonQuery();
                    tx.Commit();
                }
            }
        }
    }
}
