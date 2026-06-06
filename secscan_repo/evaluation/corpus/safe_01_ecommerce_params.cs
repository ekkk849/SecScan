// safe_01_ecommerce_params.cs
// GROUND TRUTH: 0 VULNERABLE methods, 5 SAFE methods
// Patterns: AddWithValue parameterized queries throughout
// Domain: E-commerce product catalogue and orders
// Expected tool output: 0 findings, all columns in safe_columns

using System;
using System.Data;
using System.Data.SqlClient;

namespace ECommerce.Data
{
    public class CatalogueRepository
    {
        private readonly string _conn;
        public CatalogueRepository(string conn) { _conn = conn; }

        // SAFE: product search fully parameterized
        public DataTable SearchProducts(string searchTerm, string category, decimal maxPrice)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT p.ProductId, p.Name, p.Description, p.Price, " +
                                  "p.Stock, c.CategoryName " +
                                  "FROM Products p " +
                                  "INNER JOIN Categories c ON p.CategoryId = c.CategoryId " +
                                  "WHERE p.Name LIKE @SearchTerm " +
                                  "AND c.CategoryName = @Category " +
                                  "AND p.Price <= @MaxPrice";
                cmd.Parameters.AddWithValue("@SearchTerm", "%" + searchTerm + "%");
                cmd.Parameters.AddWithValue("@Category", category);
                cmd.Parameters.AddWithValue("@MaxPrice", maxPrice);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: order lookup with named parameters
        public DataTable GetOrdersByCustomer(int customerId, string status, DateTime fromDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = @"SELECT o.OrderId, o.OrderDate, o.TotalAmount, o.Status,
                                           c.FirstName, c.LastName, c.Email
                                    FROM Orders o
                                    INNER JOIN Customers c ON o.CustomerId = c.CustomerId
                                    WHERE o.CustomerId = @CustomerId
                                    AND o.Status = @Status
                                    AND o.OrderDate >= @FromDate";
                cmd.Parameters.AddWithValue("@CustomerId", customerId);
                cmd.Parameters.AddWithValue("@Status", status);
                cmd.Parameters.AddWithValue("@FromDate", fromDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized INSERT with SCOPE_IDENTITY
        public int CreateOrder(int customerId, decimal totalAmount, string status)
        {
            using (var conn = new SqlConnection(_conn))
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

        // SAFE: parameterized UPDATE
        public void UpdateProductStock(int productId, int quantity)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = @"UPDATE Products
                                    SET Stock = Stock - @Quantity,
                                        LastModified = @LastModified
                                    WHERE ProductId = @ProductId
                                    AND Stock >= @Quantity";
                cmd.Parameters.AddWithValue("@ProductId", productId);
                cmd.Parameters.AddWithValue("@Quantity", quantity);
                cmd.Parameters.AddWithValue("@LastModified", DateTime.UtcNow);
                cmd.ExecuteNonQuery();
            }
        }

        // SAFE: parameterized review search
        public DataTable GetProductReviews(int productId, int minRating)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = @"SELECT r.ReviewId, r.Rating, r.Comment, r.ReviewDate,
                                           c.FirstName, c.LastName
                                    FROM Reviews r
                                    INNER JOIN Customers c ON r.CustomerId = c.CustomerId
                                    WHERE r.ProductId = @ProductId
                                    AND r.Rating >= @MinRating
                                    ORDER BY r.ReviewDate DESC";
                cmd.Parameters.AddWithValue("@ProductId", productId);
                cmd.Parameters.AddWithValue("@MinRating", minRating);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
