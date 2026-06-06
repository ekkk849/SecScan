// edge_01_multiline_literal_fp.cs
// GROUND TRUTH: 2 VULNERABLE methods, 3 SAFE methods
// Edge cases tested:
//   (A) Multi-line literal concatenation in safe method — SHOULD trigger FP (known tool bug)
//   (B) Column that appears in both safe and vulnerable context on same table
//   (C) Large schema: 10 tables
// Domain: Insurance claims management

using System;
using System.Data;
using System.Data.SqlClient;

namespace Insurance.Data
{
    public class ClaimsRepository
    {
        private readonly string _conn;
        public ClaimsRepository(string conn) { _conn = conn; }

        // SAFE — but WILL trigger FP: multi-line literal-only string concat
        // cmd.CommandText is assigned using + to join string literals across lines
        // No user variable is concatenated. WHERE uses @PolicyNumber param.
        // Tool bug: _CONCAT_PATTERN[0] fires on line with "SELECT...\" +"
        public DataTable GetPolicyDetails(int policyId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT p.PolicyId, p.PolicyNumber, p.PolicyType, " +
                                  "p.StartDate, p.EndDate, p.PremiumAmount, " +
                                  "c.FirstName, c.LastName, c.Email, " +
                                  "pt.PolicyTypeName, pt.CoverageLimit " +
                                  "FROM Policies p " +
                                  "INNER JOIN Customers c ON p.CustomerId = c.CustomerId " +
                                  "INNER JOIN PolicyTypes pt ON p.PolicyTypeId = pt.PolicyTypeId " +
                                  "WHERE p.PolicyId = @PolicyId";
                cmd.Parameters.AddWithValue("@PolicyId", policyId);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: claimStatus and assessorId (string) via concat
        // Column ClaimStatus also appears in the safe GetClaimById below —
        // this creates the safe+vulnerable column conflict the tool must handle
        public DataTable SearchClaims(string claimStatus, string assessorId, string claimType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT cl.ClaimId, cl.ClaimNumber, cl.ClaimType, " +
                                  "cl.ClaimDate, cl.ClaimAmount, cl.ClaimStatus, " +
                                  "c.FirstName, c.LastName, a.AssessorName " +
                                  "FROM Claims cl " +
                                  "INNER JOIN Policies p ON cl.PolicyId = p.PolicyId " +
                                  "INNER JOIN Customers c ON p.CustomerId = c.CustomerId " +
                                  "INNER JOIN Assessors a ON cl.AssessorId = a.AssessorId " +
                                  "WHERE cl.ClaimStatus = '" + claimStatus + "' " +
                                  "AND cl.AssessorId = '" + assessorId + "' " +
                                  "AND cl.ClaimType = '" + claimType + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: GetClaimById uses @ClaimStatus — same column as vulnerable method above
        // Creates a conflict where ClaimStatus is in both safe_columns and vulnerable_columns
        public DataTable GetClaimById(int claimId, string claimStatus)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT cl.ClaimId, cl.ClaimNumber, cl.ClaimAmount,
                                           cl.ClaimStatus, cl.ClaimDate, cl.SettlementDate,
                                           p.PolicyNumber, c.FirstName, c.LastName
                                    FROM Claims cl
                                    INNER JOIN Policies p ON cl.PolicyId = p.PolicyId
                                    INNER JOIN Customers c ON p.CustomerId = c.CustomerId
                                    WHERE cl.ClaimId = @ClaimId
                                    AND cl.ClaimStatus = @ClaimStatus";
                cmd.Parameters.AddWithValue("@ClaimId",     claimId);
                cmd.Parameters.AddWithValue("@ClaimStatus", claimStatus);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: String.Format on large multi-table report
        public DataTable GetClaimsReport(string startDate, string endDate, string region, string claimType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Format(
                    "SELECT r.RegionName, cl.ClaimType, " +
                    "COUNT(cl.ClaimId) AS TotalClaims, " +
                    "SUM(cl.ClaimAmount) AS TotalValue, " +
                    "AVG(cl.ClaimAmount) AS AvgValue " +
                    "FROM Claims cl " +
                    "INNER JOIN Policies p ON cl.PolicyId = p.PolicyId " +
                    "INNER JOIN Customers c ON p.CustomerId = c.CustomerId " +
                    "INNER JOIN Regions r ON c.RegionId = r.RegionId " +
                    "INNER JOIN Assessors a ON cl.AssessorId = a.AssessorId " +
                    "INNER JOIN PolicyTypes pt ON p.PolicyTypeId = pt.PolicyTypeId " +
                    "WHERE cl.ClaimDate BETWEEN '{0}' AND '{1}' " +
                    "AND r.RegionName = '{2}' " +
                    "AND cl.ClaimType = '{3}' " +
                    "GROUP BY r.RegionName, cl.ClaimType",
                    startDate, endDate, region, claimType
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized assessor performance report
        public DataTable GetAssessorPerformance(int assessorId, DateTime fromDate, DateTime toDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT a.AssessorId, a.AssessorName, a.Region,
                                           COUNT(cl.ClaimId) AS ClaimsHandled,
                                           AVG(DATEDIFF(day, cl.ClaimDate, cl.SettlementDate)) AS AvgDaysToSettle,
                                           SUM(cl.ClaimAmount) AS TotalValue
                                    FROM Assessors a
                                    INNER JOIN Claims cl ON a.AssessorId = cl.AssessorId
                                    WHERE a.AssessorId = @AssessorId
                                    AND cl.ClaimDate BETWEEN @FromDate AND @ToDate
                                    GROUP BY a.AssessorId, a.AssessorName, a.Region";
                cmd.Parameters.AddWithValue("@AssessorId", assessorId);
                cmd.Parameters.AddWithValue("@FromDate",   fromDate);
                cmd.Parameters.AddWithValue("@ToDate",     toDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
