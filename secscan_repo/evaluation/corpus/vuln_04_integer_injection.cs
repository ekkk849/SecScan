// vuln_04_integer_injection.cs
// GROUND TRUTH: 4 VULNERABLE methods, 0 SAFE methods
// Patterns: integer parameter concatenation — no string quotes in payload
// Domain: Inventory / warehouse management

using System;
using System.Data;
using System.Data.SqlClient;

namespace Inventory.Data
{
    public class InventoryRepository
    {
        private readonly string _conn;
        public InventoryRepository(string conn) { _conn = conn; }

        // VULNERABLE: warehouseId and categoryId as strings, no quotes
        public DataTable GetStockByWarehouse(string warehouseId, string categoryId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT iv.ItemId, iv.ItemName, iv.SKU, iv.QuantityOnHand, " +
                                  "iv.ReorderLevel, wh.WarehouseName, ct.CategoryName " +
                                  "FROM InventoryItems iv " +
                                  "INNER JOIN Warehouses wh ON iv.WarehouseId = wh.WarehouseId " +
                                  "INNER JOIN Categories ct ON iv.CategoryId = ct.CategoryId " +
                                  "WHERE iv.WarehouseId = " + warehouseId +
                                  " AND iv.CategoryId = " + categoryId;
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: supplierId and minQuantity as strings, no quotes
        public DataTable GetLowStockItems(string supplierId, string minQuantity)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT iv.ItemId, iv.ItemName, iv.QuantityOnHand, " +
                                  "iv.ReorderLevel, sp.SupplierName, sp.ContactEmail " +
                                  "FROM InventoryItems iv " +
                                  "INNER JOIN Suppliers sp ON iv.SupplierId = sp.SupplierId " +
                                  "WHERE iv.SupplierId = " + supplierId +
                                  " AND iv.QuantityOnHand < " + minQuantity;
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: itemId, warehouseId, movementType via concat
        public DataTable GetStockMovements(string itemId, string warehouseId, string movementType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT sm.MovementId, sm.MovementType, sm.Quantity, " +
                                  "sm.MovementDate, iv.ItemName, wh.WarehouseName " +
                                  "FROM StockMovements sm " +
                                  "INNER JOIN InventoryItems iv ON sm.ItemId = iv.ItemId " +
                                  "INNER JOIN Warehouses wh ON sm.WarehouseId = wh.WarehouseId " +
                                  "WHERE sm.ItemId = " + itemId +
                                  " AND sm.WarehouseId = " + warehouseId +
                                  " AND sm.MovementType = '" + movementType + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: warehouseId + ORDER BY sortColumn sortDir
        public DataTable GetInventoryReport(string warehouseId, string sortColumn, string sortDir)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT iv.ItemId, iv.ItemName, iv.SKU, " +
                                  "iv.QuantityOnHand, iv.UnitCost, iv.TotalValue " +
                                  "FROM InventoryItems iv " +
                                  "WHERE iv.WarehouseId = " + warehouseId +
                                  " ORDER BY " + sortColumn + " " + sortDir;
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
