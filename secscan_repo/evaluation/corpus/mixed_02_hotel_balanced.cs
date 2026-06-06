// mixed_02_hotel_balanced.cs
// GROUND TRUTH: 3 VULNERABLE methods, 3 SAFE methods
// Ratio: 50/50 balanced — core mixed test
// Domain: Hotel booking and room management
// Vuln params: guestName, roomType, checkIn, checkOut (string), nationality

using System;
using System.Data;
using System.Data.SqlClient;

namespace Hotel.Data
{
    public class BookingRepository
    {
        private readonly string _conn;
        public BookingRepository(string conn) { _conn = conn; }

        // VULNERABLE: guestName and nationality via concat
        public DataTable SearchGuests(string guestName, string nationality, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT g.GuestId, g.FirstName, g.LastName, g.Email, " +
                                  "g.Phone, g.Nationality, g.LoyaltyPoints " +
                                  "FROM Guests g " +
                                  "WHERE g.LastName LIKE '%" + guestName + "%' " +
                                  "AND g.Nationality = '" + nationality + "' " +
                                  "AND g.Status = '" + status + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized room availability check
        public DataTable CheckRoomAvailability(string roomType, DateTime checkIn, DateTime checkOut)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT r.RoomId, r.RoomNumber, r.RoomType,
                                           r.PricePerNight, r.Floor, r.Capacity
                                    FROM Rooms r
                                    WHERE r.RoomType = @RoomType
                                    AND r.RoomId NOT IN (
                                        SELECT b.RoomId FROM Bookings b
                                        WHERE b.CheckInDate < @CheckOut
                                        AND b.CheckOutDate > @CheckIn
                                        AND b.Status != @CancelledStatus
                                    )";
                cmd.Parameters.AddWithValue("@RoomType",        roomType);
                cmd.Parameters.AddWithValue("@CheckIn",         checkIn);
                cmd.Parameters.AddWithValue("@CheckOut",        checkOut);
                cmd.Parameters.AddWithValue("@CancelledStatus", "cancelled");
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: checkIn and checkOut passed as strings via interpolation
        public DataTable GetBookingsByDateRange(string checkIn, string checkOut, string roomType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = $"SELECT b.BookingId, g.FirstName, g.LastName, " +
                                  $"r.RoomNumber, r.RoomType, b.CheckInDate, b.CheckOutDate, " +
                                  $"b.TotalAmount, b.Status " +
                                  $"FROM Bookings b " +
                                  $"INNER JOIN Guests g ON b.GuestId = g.GuestId " +
                                  $"INNER JOIN Rooms r ON b.RoomId = r.RoomId " +
                                  $"WHERE b.CheckInDate >= '{checkIn}' " +
                                  $"AND b.CheckOutDate <= '{checkOut}' " +
                                  $"AND r.RoomType = '{roomType}'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized booking creation with transaction
        public int CreateBooking(int guestId, int roomId, DateTime checkIn, DateTime checkOut, decimal amount)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection  = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"INSERT INTO Bookings
                                        (GuestId, RoomId, CheckInDate, CheckOutDate, TotalAmount, Status)
                                        VALUES (@GuestId, @RoomId, @CheckIn, @CheckOut, @Amount, @Status);
                                        SELECT SCOPE_IDENTITY();";
                    cmd.Parameters.AddWithValue("@GuestId",  guestId);
                    cmd.Parameters.AddWithValue("@RoomId",   roomId);
                    cmd.Parameters.AddWithValue("@CheckIn",  checkIn);
                    cmd.Parameters.AddWithValue("@CheckOut", checkOut);
                    cmd.Parameters.AddWithValue("@Amount",   amount);
                    cmd.Parameters.AddWithValue("@Status",   "confirmed");
                    var id = Convert.ToInt32(cmd.ExecuteScalar());
                    tx.Commit();
                    return id;
                }
            }
        }

        // VULNERABLE: String.Format on revenue report
        public DataTable GetRevenueReport(string startDate, string endDate, string roomType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Format(
                    "SELECT r.RoomType, COUNT(b.BookingId) AS TotalBookings, " +
                    "SUM(b.TotalAmount) AS Revenue, AVG(b.TotalAmount) AS AvgRate " +
                    "FROM Bookings b " +
                    "INNER JOIN Rooms r ON b.RoomId = r.RoomId " +
                    "WHERE b.CheckInDate BETWEEN '{0}' AND '{1}' " +
                    "AND r.RoomType = '{2}' " +
                    "GROUP BY r.RoomType",
                    startDate, endDate, roomType
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized guest profile update
        public void UpdateGuestProfile(int guestId, string email, string phone)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"UPDATE Guests
                                    SET Email = @Email,
                                        Phone = @Phone,
                                        LastModified = @LastModified
                                    WHERE GuestId = @GuestId";
                cmd.Parameters.AddWithValue("@GuestId",      guestId);
                cmd.Parameters.AddWithValue("@Email",        email);
                cmd.Parameters.AddWithValue("@Phone",        phone);
                cmd.Parameters.AddWithValue("@LastModified", DateTime.UtcNow);
                cmd.ExecuteNonQuery();
            }
        }
    }
}
