// ECommerceRepository.cs
// Test file 1: E-commerce order management system
// Contains: string concatenation vulnerabilities, parameterized queries, complex joins

using System;
using System.Data;
using System.Data.SqlClient;

namespace ECommerce.Data
{
    public class OrderRepository
    {
        private readonly string _connectionString;

        public OrderRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        // -------------------------------------------------------
        // VULNERABLE: search built with raw string concatenation
        // -------------------------------------------------------
        public DataTable SearchProductsByName(string searchTerm, string category)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                // BUG: direct user input concatenated into SQL
                cmd.CommandText = "SELECT p.ProductId, p.Name, p.Price, p.Stock, c.CategoryName " +
                                  "FROM Products p " +
                                  "INNER JOIN Categories c ON p.CategoryId = c.CategoryId " +
                                  "WHERE p.Name LIKE '%" + searchTerm + "%' " +
                                  "AND c.CategoryName = '" + category + "'";

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }

        // -------------------------------------------------------
        // VULNERABLE: order status filter via interpolation
        // -------------------------------------------------------
        public DataTable GetOrdersByStatus(string status, string customerId)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                // BUG: C# string interpolation — injects directly
                cmd.CommandText = $"SELECT o.OrderId, o.OrderDate, o.TotalAmount, o.Status, " +
                                  $"c.FirstName, c.LastName, c.Email " +
                                  $"FROM Orders o " +
                                  $"INNER JOIN Customers c ON o.CustomerId = c.CustomerId " +
                                  $"WHERE o.Status = '{status}' " +
                                  $"AND o.CustomerId = {customerId}";

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }

        // -------------------------------------------------------
        // VULNERABLE: reporting query via string.Format
        // -------------------------------------------------------
        public DataTable GetSalesReport(string startDate, string endDate, string region)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                // BUG: string.Format with user input
                cmd.CommandText = string.Format(
                    "SELECT r.RegionName, SUM(oi.Quantity * oi.UnitPrice) AS Revenue, " +
                    "COUNT(DISTINCT o.OrderId) AS OrderCount, " +
                    "AVG(o.TotalAmount) AS AvgOrderValue " +
                    "FROM Orders o " +
                    "INNER JOIN OrderItems oi ON o.OrderId = oi.OrderId " +
                    "INNER JOIN Customers c ON o.CustomerId = c.CustomerId " +
                    "INNER JOIN Regions r ON c.RegionId = r.RegionId " +
                    "WHERE o.OrderDate BETWEEN '{0}' AND '{1}' " +
                    "AND r.RegionName = '{2}' " +
                    "GROUP BY r.RegionName",
                    startDate, endDate, region
                );

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }

        // -------------------------------------------------------
        // SAFE: parameterized product lookup by ID
        // -------------------------------------------------------
        public DataTable GetProductById(int productId)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT p.ProductId, p.Name, p.Description, p.Price, p.Stock, " +
                                  "p.SKU, c.CategoryName, s.SupplierName " +
                                  "FROM Products p " +
                                  "INNER JOIN Categories c ON p.CategoryId = c.CategoryId " +
                                  "INNER JOIN Suppliers s ON p.SupplierId = s.SupplierId " +
                                  "WHERE p.ProductId = @ProductId";
                cmd.Parameters.AddWithValue("@ProductId", productId);

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }

        // -------------------------------------------------------
        // SAFE: parameterized order creation
        // -------------------------------------------------------
        public int CreateOrder(int customerId, decimal totalAmount, string status)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = @"INSERT INTO Orders (CustomerId, OrderDate, TotalAmount, Status)
                                    VALUES (@CustomerId, @OrderDate, @TotalAmount, @Status);
                                    SELECT SCOPE_IDENTITY();";
                cmd.Parameters.AddWithValue("@CustomerId", customerId);
                cmd.Parameters.AddWithValue("@OrderDate", DateTime.UtcNow);
                cmd.Parameters.AddWithValue("@TotalAmount", totalAmount);
                cmd.Parameters.AddWithValue("@Status", status);

                return Convert.ToInt32(cmd.ExecuteScalar());
            }
        }

        // -------------------------------------------------------
        // SAFE: inventory management with params
        // -------------------------------------------------------
        public DataTable GetLowStockProducts(int threshold, int categoryId)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = @"SELECT p.ProductId, p.Name, p.SKU, p.Stock,
                                           s.SupplierName, s.Email AS SupplierEmail
                                    FROM Products p
                                    INNER JOIN Suppliers s ON p.SupplierId = s.SupplierId
                                    WHERE p.Stock < @Threshold
                                    AND p.CategoryId = @CategoryId
                                    ORDER BY p.Stock ASC";
                cmd.Parameters.AddWithValue("@Threshold", threshold);
                cmd.Parameters.AddWithValue("@CategoryId", categoryId);

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }

        // -------------------------------------------------------
        // VULNERABLE: customer search via concat
        // -------------------------------------------------------
        public DataTable SearchCustomers(string lastName, string city)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                // BUG: last name and city injected directly
                cmd.CommandText = "SELECT c.CustomerId, c.FirstName, c.LastName, c.Email, " +
                                  "c.Phone, a.City, a.Country, c.Status " +
                                  "FROM Customers c " +
                                  "LEFT JOIN Addresses a ON c.CustomerId = a.CustomerId " +
                                  "WHERE c.LastName LIKE '%" + lastName + "%' " +
                                  "AND a.City = '" + city + "'";

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }

        // -------------------------------------------------------
        // SAFE: update stock with transaction
        // -------------------------------------------------------
        public void UpdateStock(int productId, int quantity)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"UPDATE Products
                                        SET Stock = Stock - @Quantity,
                                            ModifiedDate = @ModifiedDate
                                        WHERE ProductId = @ProductId
                                        AND Stock >= @Quantity";
                    cmd.Parameters.AddWithValue("@ProductId", productId);
                    cmd.Parameters.AddWithValue("@Quantity", quantity);
                    cmd.Parameters.AddWithValue("@ModifiedDate", DateTime.UtcNow);
                    cmd.ExecuteNonQuery();
                    tx.Commit();
                }
            }
        }

        // -------------------------------------------------------
        // VULNERABLE: dynamic sort order injection
        // -------------------------------------------------------
        public DataTable GetOrderItemsWithSort(int orderId, string sortColumn, string sortDir)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                // BUG: sort column and direction are injected — classic second-order issue
                cmd.CommandText = "SELECT oi.OrderItemId, oi.OrderId, oi.Quantity, oi.UnitPrice, " +
                                  "p.Name AS ProductName, p.SKU, " +
                                  "(oi.Quantity * oi.UnitPrice) AS LineTotal " +
                                  "FROM OrderItems oi " +
                                  "INNER JOIN Products p ON oi.ProductId = p.ProductId " +
                                  "WHERE oi.OrderId = " + orderId +
                                  " ORDER BY " + sortColumn + " " + sortDir;

                var adapter = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                adapter.Fill(dt);
                return dt;
            }
        }
    }
}
