// edge_05_alias_confusion.cs
// GROUND TRUTH: 2 VULNERABLE methods, 3 SAFE methods
// KEY EDGE: variable names in C# code that look like SQL table aliases
//           e.g. var c = customerInput; cmd.CommandText = "...WHERE c.Name = '" + c + "'"
//           Parser's _NOISE_ALIASES filters cmd, conn etc. but not arbitrary variable names
//           Also: method parameter named exactly like a table (e.g. string Orders)
// Domain: Logistics / courier

using System;
using System.Data;
using System.Data.SqlClient;

namespace Logistics.Data
{
    public class CourierRepository
    {
        private readonly string _conn;
        public CourierRepository(string conn) { _conn = conn; }

        // VULNERABLE: variable 'q' used in C# AND as SQL alias — may confuse parser
        // q = user query string; SQL also uses q as alias for nothing (no alias in SQL here)
        public DataTable TrackShipment(string q, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT s.ShipmentId, s.TrackingNumber, s.Status, " +
                                  "s.EstimatedDelivery, s.ActualDelivery, " +
                                  "o.RecipientName, o.DeliveryAddress, " +
                                  "c.CourierName, v.VehicleReg " +
                                  "FROM Shipments s " +
                                  "INNER JOIN Orders o ON s.OrderId = o.OrderId " +
                                  "INNER JOIN Couriers c ON s.CourierId = c.CourierId " +
                                  "INNER JOIN Vehicles v ON s.VehicleId = v.VehicleId " +
                                  "WHERE s.TrackingNumber LIKE '%" + q + "%' " +
                                  "AND s.Status = '" + status + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: uses variable named 'sc' — looks like alias but is safe
        public DataTable GetCourierSchedule(int courierId, DateTime scheduleDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var sc  = scheduleDate.Date;
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT c.CourierId, c.CourierName, c.Phone,
                                           r.RouteName, r.StartLocation, r.EndLocation,
                                           v.VehicleReg, v.VehicleType,
                                           cs.ShiftStart, cs.ShiftEnd
                                    FROM Couriers c
                                    INNER JOIN CourierSchedules cs ON c.CourierId = cs.CourierId
                                    INNER JOIN Routes r ON cs.RouteId = r.RouteId
                                    INNER JOIN Vehicles v ON cs.VehicleId = v.VehicleId
                                    WHERE c.CourierId = @CourierId
                                    AND CAST(cs.ShiftStart AS DATE) = @ScheduleDate";
                cmd.Parameters.AddWithValue("@CourierId",     courierId);
                cmd.Parameters.AddWithValue("@ScheduleDate",  sc);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: method param literally named 'Orders' — same as table name
        // Tests whether parser confuses the C# parameter with the SQL table
        public DataTable GetOrderStatus(string Orders, string depot, string dateFrom)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT o.OrderId, o.OrderRef, o.Status, " +
                                  "o.RecipientName, o.DeliveryAddress, o.CreatedDate, " +
                                  "d.DepotName, d.City " +
                                  "FROM Orders o " +
                                  "INNER JOIN Depots d ON o.DepotId = d.DepotId " +
                                  "WHERE o.OrderRef LIKE '%" + Orders + "%' " +
                                  "AND d.DepotName = '" + depot + "' " +
                                  "AND o.CreatedDate >= '" + dateFrom + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized depot report
        public DataTable GetDepotPerformance(int depotId, DateTime fromDate, DateTime toDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT d.DepotId, d.DepotName, d.City,
                                           COUNT(s.ShipmentId) AS TotalShipments,
                                           COUNT(CASE WHEN s.Status = 'delivered' THEN 1 END) AS Delivered,
                                           AVG(DATEDIFF(hour, s.CreatedDate, s.ActualDelivery)) AS AvgHoursToDelivery
                                    FROM Depots d
                                    INNER JOIN Shipments s ON d.DepotId = s.DepotId
                                    WHERE d.DepotId = @DepotId
                                    AND s.CreatedDate BETWEEN @FromDate AND @ToDate
                                    GROUP BY d.DepotId, d.DepotName, d.City";
                cmd.Parameters.AddWithValue("@DepotId",  depotId);
                cmd.Parameters.AddWithValue("@FromDate", fromDate);
                cmd.Parameters.AddWithValue("@ToDate",   toDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized vehicle assignment
        public void AssignVehicle(int courierId, int vehicleId, DateTime assignDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection  = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"UPDATE Vehicles SET Status = @Busy WHERE VehicleId = @VehicleId;
                                        INSERT INTO VehicleAssignments (CourierId, VehicleId, AssignDate, Status)
                                        VALUES (@CourierId, @VehicleId, @AssignDate, @Status);";
                    cmd.Parameters.AddWithValue("@CourierId",  courierId);
                    cmd.Parameters.AddWithValue("@VehicleId",  vehicleId);
                    cmd.Parameters.AddWithValue("@AssignDate", assignDate);
                    cmd.Parameters.AddWithValue("@Status",     "active");
                    cmd.Parameters.AddWithValue("@Busy",       "in-use");
                    cmd.ExecuteNonQuery();
                    tx.Commit();
                }
            }
        }
    }
}
