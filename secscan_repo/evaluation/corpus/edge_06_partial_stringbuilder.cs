// edge_06_partial_stringbuilder.cs
// GROUND TRUTH: 3 VULNERABLE methods, 2 SAFE methods
// KEY EDGE: same file has BOTH standard concat AND StringBuilder in different methods
//           One method mixes safe @param AND StringBuilder in the same method body
//           Tests partial detection: tool should catch the concat methods but miss StringBuilder ones
// Domain: Telecom / subscription management

using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace Telecom.Data
{
    public class SubscriptionRepository
    {
        private readonly string _conn;
        public SubscriptionRepository(string conn) { _conn = conn; }

        // VULNERABLE via standard concat — TOOL WILL FIND THIS
        public DataTable SearchSubscriptions(string customerName, string planType, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT s.SubscriptionId, s.PhoneNumber, s.Status, " +
                                  "s.StartDate, s.EndDate, s.MonthlyFee, " +
                                  "c.FirstName, c.LastName, c.Email, " +
                                  "p.PlanName, p.DataAllowance " +
                                  "FROM Subscriptions s " +
                                  "INNER JOIN Customers c ON s.CustomerId = c.CustomerId " +
                                  "INNER JOIN Plans p ON s.PlanId = p.PlanId " +
                                  "WHERE c.LastName LIKE '%" + customerName + "%' " +
                                  "AND p.PlanType = '" + planType + "' " +
                                  "AND s.Status = '" + status + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE via StringBuilder — TOOL WILL MISS THIS
        public DataTable GetUsageReport_Builder(string customerId, string fromDate, string toDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                var sql = new StringBuilder();
                sql.Append("SELECT u.UsageId, u.UsageDate, u.DataUsedMB, u.CallMinutes, ");
                sql.Append("u.SMSCount, u.ChargeAmount, s.PhoneNumber, p.PlanName ");
                sql.Append("FROM UsageRecords u ");
                sql.Append("INNER JOIN Subscriptions s ON u.SubscriptionId = s.SubscriptionId ");
                sql.Append("INNER JOIN Plans p ON s.PlanId = p.PlanId ");
                sql.Append("INNER JOIN Customers c ON s.CustomerId = c.CustomerId ");
                sql.Append("WHERE c.CustomerId = '").Append(customerId).Append("' ");
                sql.Append("AND u.UsageDate BETWEEN '").Append(fromDate).Append("' ");
                sql.Append("AND '").Append(toDate).Append("'");
                cmd.CommandText = sql.ToString();
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized plan lookup
        public DataTable GetAvailablePlans(string planType, decimal maxPrice)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT p.PlanId, p.PlanName, p.PlanType,
                                           p.MonthlyFee, p.DataAllowance, p.CallMinutes,
                                           p.SMSCount, p.ContractLength
                                    FROM Plans p
                                    WHERE p.PlanType = @PlanType
                                    AND p.MonthlyFee <= @MaxPrice
                                    AND p.Status = @Status
                                    ORDER BY p.MonthlyFee ASC";
                cmd.Parameters.AddWithValue("@PlanType", planType);
                cmd.Parameters.AddWithValue("@MaxPrice", maxPrice);
                cmd.Parameters.AddWithValue("@Status",   "active");
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE via interpolation — TOOL WILL FIND THIS
        public DataTable GetInvoicesByStatus(string customerId, string invoiceStatus, string month)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = $"SELECT i.InvoiceId, i.InvoiceDate, i.DueDate, " +
                                  $"i.TotalAmount, i.Status, i.PaidDate, " +
                                  $"c.FirstName, c.LastName, c.Email " +
                                  $"FROM Invoices i " +
                                  $"INNER JOIN Customers c ON i.CustomerId = c.CustomerId " +
                                  $"WHERE i.CustomerId = '{customerId}' " +
                                  $"AND i.Status = '{invoiceStatus}' " +
                                  $"AND MONTH(i.InvoiceDate) = {month}";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized support ticket lookup
        public DataTable GetSupportTickets(int customerId, string priority, DateTime fromDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT t.TicketId, t.Subject, t.Priority,
                                           t.Status, t.CreatedDate, t.ResolvedDate,
                                           t.Description, ag.AgentName, ag.Department
                                    FROM SupportTickets t
                                    INNER JOIN Customers c ON t.CustomerId = c.CustomerId
                                    INNER JOIN Agents ag ON t.AssignedAgentId = ag.AgentId
                                    WHERE t.CustomerId = @CustomerId
                                    AND t.Priority = @Priority
                                    AND t.CreatedDate >= @FromDate
                                    ORDER BY t.CreatedDate DESC";
                cmd.Parameters.AddWithValue("@CustomerId", customerId);
                cmd.Parameters.AddWithValue("@Priority",   priority);
                cmd.Parameters.AddWithValue("@FromDate",   fromDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
