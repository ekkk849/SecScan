// vuln_02_interpolation_banking.cs
// GROUND TRUTH: 3 VULNERABLE methods, 0 SAFE methods
// Patterns: interpolated_sql only
// Domain: Bank account management

using System;
using System.Data;
using System.Data.SqlClient;

namespace Banking.Data
{
    public class AccountRepository
    {
        private readonly string _conn;
        public AccountRepository(string conn) { _conn = conn; }

        // VULNERABLE: accountNumber, transactionType, fromDate, toDate via interpolation
        public DataTable GetTransactionHistory(string accountNumber, string transactionType, string fromDate, string toDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = $"SELECT tx.TransactionId, tx.Amount, tx.TransactionDate, " +
                                  $"tx.TransactionType, tx.Description, ac.AccountNumber " +
                                  $"FROM Transactions tx " +
                                  $"INNER JOIN Accounts ac ON tx.AccountId = ac.AccountId " +
                                  $"WHERE ac.AccountNumber = '{accountNumber}' " +
                                  $"AND tx.TransactionType = '{transactionType}' " +
                                  $"AND tx.TransactionDate BETWEEN '{fromDate}' AND '{toDate}'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: customerId and branchCode via interpolation
        public DataTable GetCustomerAccounts(string customerId, string branchCode)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = $"SELECT ac.AccountId, ac.AccountNumber, ac.AccountType, " +
                                  $"ac.Balance, ac.OpenDate, br.BranchName, cu.FullName " +
                                  $"FROM Accounts ac " +
                                  $"INNER JOIN Customers cu ON ac.CustomerId = cu.CustomerId " +
                                  $"INNER JOIN Branches br ON ac.BranchId = br.BranchId " +
                                  $"WHERE cu.CustomerId = '{customerId}' " +
                                  $"AND br.BranchCode = '{branchCode}'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: status, accountType, branchCode via interpolation
        public DataTable SearchAccountsByStatus(string status, string accountType, string branchCode)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = $"SELECT ac.AccountId, ac.AccountNumber, cu.FullName, " +
                                  $"cu.Email, ac.Balance, ac.Status " +
                                  $"FROM Accounts ac " +
                                  $"INNER JOIN Customers cu ON ac.CustomerId = cu.CustomerId " +
                                  $"WHERE ac.Status = '{status}' " +
                                  $"AND ac.AccountType = '{accountType}' " +
                                  $"AND ac.BranchCode = '{branchCode}'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
