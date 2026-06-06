// mixed_04_column_level.cs
// GROUND TRUTH: 3 VULNERABLE methods, 2 SAFE methods
// KEY EDGE: One method has BOTH a safe param AND a concat on DIFFERENT columns of the same table
//           This tests whether the tool works at column level not just method level
// Domain: Pharmaceutical supply chain

using System;
using System.Data;
using System.Data.SqlClient;

namespace Pharma.Data
{
    public class SupplyChainRepository
    {
        private readonly string _conn;
        public SupplyChainRepository(string conn) { _conn = conn; }

        // VULNERABLE: productName via concat, but productId is parameterized
        // Same method — safe column (ProductId) AND vulnerable column (ProductName, Manufacturer)
        // Tests column-level classification: tool must flag ProductName/Manufacturer but not ProductId
        public DataTable SearchDrugs(int categoryId, string productName, string manufacturer)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT d.DrugId, d.ProductName, d.ActiveIngredient, " +
                                  "d.Strength, d.Manufacturer, d.BatchNumber, c.CategoryName " +
                                  "FROM Drugs d " +
                                  "INNER JOIN DrugCategories c ON d.CategoryId = c.CategoryId " +
                                  "WHERE d.CategoryId = @CategoryId " +
                                  "AND d.ProductName LIKE '%" + productName + "%' " +
                                  "AND d.Manufacturer = '" + manufacturer + "'";
                cmd.Parameters.AddWithValue("@CategoryId", categoryId);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: both supplierId and drugId fully parameterized
        public DataTable GetSupplierStock(int supplierId, int drugId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT s.SupplierName, s.ContactEmail,
                                           st.QuantityAvailable, st.UnitPrice,
                                           st.LeadTimeDays, d.ProductName
                                    FROM SupplierStock st
                                    INNER JOIN Suppliers s ON st.SupplierId = s.SupplierId
                                    INNER JOIN Drugs d ON st.DrugId = d.DrugId
                                    WHERE st.SupplierId = @SupplierId
                                    AND st.DrugId = @DrugId";
                cmd.Parameters.AddWithValue("@SupplierId", supplierId);
                cmd.Parameters.AddWithValue("@DrugId",     drugId);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: batchNumber and expiryBefore via concat
        public DataTable GetExpiringBatches(string batchNumber, string expiryBefore, string warehouseId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT b.BatchId, b.BatchNumber, b.ExpiryDate, " +
                                  "b.QuantityRemaining, d.ProductName, w.WarehouseName " +
                                  "FROM Batches b " +
                                  "INNER JOIN Drugs d ON b.DrugId = d.DrugId " +
                                  "INNER JOIN Warehouses w ON b.WarehouseId = w.WarehouseId " +
                                  "WHERE b.BatchNumber LIKE '%" + batchNumber + "%' " +
                                  "AND b.ExpiryDate <= '" + expiryBefore + "' " +
                                  "AND b.WarehouseId = '" + warehouseId + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: String.Format on shipment report
        public DataTable GetShipmentReport(string startDate, string endDate, string supplierId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Format(
                    "SELECT sh.ShipmentId, s.SupplierName, sh.ShipmentDate, " +
                    "sh.TotalValue, sh.Status, COUNT(si.ItemId) AS ItemCount " +
                    "FROM Shipments sh " +
                    "INNER JOIN Suppliers s ON sh.SupplierId = s.SupplierId " +
                    "INNER JOIN ShipmentItems si ON sh.ShipmentId = si.ShipmentId " +
                    "WHERE sh.ShipmentDate BETWEEN '{0}' AND '{1}' " +
                    "AND sh.SupplierId = '{2}' " +
                    "GROUP BY sh.ShipmentId, s.SupplierName, sh.ShipmentDate, sh.TotalValue, sh.Status",
                    startDate, endDate, supplierId
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized compliance audit
        public DataTable GetComplianceAudit(int drugId, DateTime fromDate, DateTime toDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT ca.AuditId, ca.AuditDate, ca.AuditType,
                                           ca.Result, ca.Notes, d.ProductName,
                                           au.AuditorName
                                    FROM ComplianceAudits ca
                                    INNER JOIN Drugs d ON ca.DrugId = d.DrugId
                                    INNER JOIN Auditors au ON ca.AuditorId = au.AuditorId
                                    WHERE ca.DrugId = @DrugId
                                    AND ca.AuditDate BETWEEN @FromDate AND @ToDate";
                cmd.Parameters.AddWithValue("@DrugId",   drugId);
                cmd.Parameters.AddWithValue("@FromDate", fromDate);
                cmd.Parameters.AddWithValue("@ToDate",   toDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
