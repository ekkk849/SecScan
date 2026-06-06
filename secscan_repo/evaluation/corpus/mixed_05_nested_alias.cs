// mixed_05_nested_alias.cs
// GROUND TRUTH: 3 VULNERABLE methods, 3 SAFE methods
// KEY EDGE: complex alias patterns — same letter alias used for different tables across methods
//           e.g. 'u' = Users in one method, 'u' = Units in another
//           Tests v2 parser's per-method alias scoping fix directly
// Domain: Property management / tenancy

using System;
using System.Data;
using System.Data.SqlClient;

namespace PropertyMgmt.Data
{
    public class TenancyRepository
    {
        private readonly string _conn;
        public TenancyRepository(string conn) { _conn = conn; }

        // VULNERABLE: tenantName and propertyRef via concat
        // Alias 'p' = Properties here, 'u' = Units
        public DataTable SearchTenants(string tenantName, string propertyRef, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT t.TenantId, t.FirstName, t.LastName, t.Email, " +
                                  "u.UnitNumber, p.PropertyRef, p.Address, ta.StartDate " +
                                  "FROM Tenants t " +
                                  "INNER JOIN TenancyAgreements ta ON t.TenantId = ta.TenantId " +
                                  "INNER JOIN Units u ON ta.UnitId = u.UnitId " +
                                  "INNER JOIN Properties p ON u.PropertyId = p.PropertyId " +
                                  "WHERE t.LastName LIKE '%" + tenantName + "%' " +
                                  "AND p.PropertyRef = '" + propertyRef + "' " +
                                  "AND ta.Status = '" + status + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized maintenance lookup
        // Alias 'p' = Properties here too — v2 scoping must keep this separate from above
        public DataTable GetMaintenanceRequests(int propertyId, string priority, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT m.RequestId, m.Description, m.Priority,
                                           m.RequestDate, m.Status, m.ResolvedDate,
                                           p.Address, u.UnitNumber, t.FirstName, t.LastName
                                    FROM MaintenanceRequests m
                                    INNER JOIN Units u ON m.UnitId = u.UnitId
                                    INNER JOIN Properties p ON u.PropertyId = p.PropertyId
                                    INNER JOIN Tenants t ON m.TenantId = t.TenantId
                                    WHERE p.PropertyId = @PropertyId
                                    AND m.Priority = @Priority
                                    AND m.Status = @Status";
                cmd.Parameters.AddWithValue("@PropertyId", propertyId);
                cmd.Parameters.AddWithValue("@Priority",   priority);
                cmd.Parameters.AddWithValue("@Status",     status);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: rentFromDate and rentToDate (strings) via interpolation
        // Alias 'u' = Units here (different from first method where 'u' = Units too, but 't' differs)
        public DataTable GetRentArrearsReport(string tenantId, string rentFromDate, string rentToDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = $"SELECT t.FirstName, t.LastName, t.Email, " +
                                  $"u.UnitNumber, rp.DueDate, rp.Amount, rp.PaidDate, rp.Status " +
                                  $"FROM RentPayments rp " +
                                  $"INNER JOIN TenancyAgreements ta ON rp.TenancyId = ta.TenancyId " +
                                  $"INNER JOIN Tenants t ON ta.TenantId = t.TenantId " +
                                  $"INNER JOIN Units u ON ta.UnitId = u.UnitId " +
                                  $"WHERE t.TenantId = '{tenantId}' " +
                                  $"AND rp.DueDate BETWEEN '{rentFromDate}' AND '{rentToDate}' " +
                                  $"AND rp.Status = 'overdue'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized lease agreement lookup
        public DataTable GetLeaseAgreement(int tenancyId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT ta.TenancyId, ta.StartDate, ta.EndDate,
                                           ta.MonthlyRent, ta.DepositAmount, ta.Status,
                                           t.FirstName, t.LastName, t.Email,
                                           u.UnitNumber, p.Address
                                    FROM TenancyAgreements ta
                                    INNER JOIN Tenants t ON ta.TenantId = t.TenantId
                                    INNER JOIN Units u ON ta.UnitId = u.UnitId
                                    INNER JOIN Properties p ON u.PropertyId = p.PropertyId
                                    WHERE ta.TenancyId = @TenancyId";
                cmd.Parameters.AddWithValue("@TenancyId", tenancyId);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: String.Format on occupancy report with many aliases
        public DataTable GetOccupancyReport(string regionCode, string startDate, string endDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Format(
                    "SELECT r.RegionName, p.PropertyRef, " +
                    "COUNT(u.UnitId) AS TotalUnits, " +
                    "COUNT(ta.TenancyId) AS OccupiedUnits, " +
                    "CAST(COUNT(ta.TenancyId) AS FLOAT) / COUNT(u.UnitId) * 100 AS OccupancyRate " +
                    "FROM Regions r " +
                    "INNER JOIN Properties p ON r.RegionId = p.RegionId " +
                    "INNER JOIN Units u ON p.PropertyId = u.PropertyId " +
                    "LEFT JOIN TenancyAgreements ta ON u.UnitId = ta.UnitId " +
                    "AND ta.Status = 'active' " +
                    "WHERE r.RegionCode = '{0}' " +
                    "AND p.CreatedDate BETWEEN '{1}' AND '{2}' " +
                    "GROUP BY r.RegionName, p.PropertyRef",
                    regionCode, startDate, endDate
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized inspection record
        public DataTable GetPropertyInspections(int propertyId, DateTime fromDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT i.InspectionId, i.InspectionDate, i.InspectorName,
                                           i.OverallCondition, i.Notes, i.NextInspectionDate,
                                           p.Address, p.PropertyRef
                                    FROM Inspections i
                                    INNER JOIN Properties p ON i.PropertyId = p.PropertyId
                                    WHERE i.PropertyId = @PropertyId
                                    AND i.InspectionDate >= @FromDate
                                    ORDER BY i.InspectionDate DESC";
                cmd.Parameters.AddWithValue("@PropertyId", propertyId);
                cmd.Parameters.AddWithValue("@FromDate",   fromDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
