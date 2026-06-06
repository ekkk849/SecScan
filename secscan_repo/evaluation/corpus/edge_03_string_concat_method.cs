// edge_03_string_concat_method.cs
// GROUND TRUTH: 3 VULNERABLE methods, 2 SAFE methods
// KEY EDGE: uses string.Concat() static method instead of + operator
//           _CONCAT_PATTERNS only match + operator — string.Concat() is a blind spot variant
// Domain: Event management / ticketing

using System;
using System.Data;
using System.Data.SqlClient;

namespace Events.Data
{
    public class EventRepository
    {
        private readonly string _conn;
        public EventRepository(string conn) { _conn = conn; }

        // VULNERABLE via string.Concat() — TOOL MAY MISS THIS
        // string.Concat() does not use + operator so regex won't fire
        public DataTable SearchEvents(string eventName, string venue, string category)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Concat(
                    "SELECT e.EventId, e.EventName, e.EventDate, e.TicketPrice, ",
                    "e.AvailableTickets, v.VenueName, v.City, ec.CategoryName ",
                    "FROM Events e ",
                    "INNER JOIN Venues v ON e.VenueId = v.VenueId ",
                    "INNER JOIN EventCategories ec ON e.CategoryId = ec.CategoryId ",
                    "WHERE e.EventName LIKE '%", eventName, "%' ",
                    "AND v.VenueName LIKE '%", venue, "%' ",
                    "AND ec.CategoryName = '", category, "'"
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE via string.Concat() — TOOL MAY MISS THIS
        public DataTable GetBookingsByOrganiser(string organiserId, string eventStatus)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Concat(
                    "SELECT b.BookingId, a.FirstName, a.LastName, ",
                    "e.EventName, b.TicketCount, b.TotalPrice, b.BookingDate ",
                    "FROM Bookings b ",
                    "INNER JOIN Attendees a ON b.AttendeeId = a.AttendeeId ",
                    "INNER JOIN Events e ON b.EventId = e.EventId ",
                    "WHERE e.OrganiserId = '", organiserId, "' ",
                    "AND e.Status = '", eventStatus, "'"
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE via standard + concat — TOOL WILL FIND THIS
        // Control: ensures the tool still finds standard patterns in the same file
        public DataTable SearchAttendees(string lastName, string email, string eventId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT a.AttendeeId, a.FirstName, a.LastName, a.Email, " +
                                  "b.TicketCount, e.EventName, b.BookingDate " +
                                  "FROM Attendees a " +
                                  "INNER JOIN Bookings b ON a.AttendeeId = b.AttendeeId " +
                                  "INNER JOIN Events e ON b.EventId = e.EventId " +
                                  "WHERE a.LastName LIKE '%" + lastName + "%' " +
                                  "AND a.Email LIKE '%" + email + "%' " +
                                  "AND e.EventId = '" + eventId + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized event detail
        public DataTable GetEventById(int eventId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT e.EventId, e.EventName, e.Description,
                                           e.EventDate, e.TicketPrice, e.AvailableTickets,
                                           v.VenueName, v.City, v.Capacity,
                                           ec.CategoryName, o.OrgName
                                    FROM Events e
                                    INNER JOIN Venues v ON e.VenueId = v.VenueId
                                    INNER JOIN EventCategories ec ON e.CategoryId = ec.CategoryId
                                    INNER JOIN Organisers o ON e.OrganiserId = o.OrganiserId
                                    WHERE e.EventId = @EventId";
                cmd.Parameters.AddWithValue("@EventId", eventId);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized booking creation
        public int CreateBooking(int attendeeId, int eventId, int ticketCount, decimal totalPrice)
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
                                        (AttendeeId, EventId, TicketCount, TotalPrice, BookingDate, Status)
                                        VALUES (@AttendeeId, @EventId, @TicketCount, @TotalPrice, @BookingDate, @Status);
                                        UPDATE Events SET AvailableTickets = AvailableTickets - @TicketCount
                                        WHERE EventId = @EventId;
                                        SELECT SCOPE_IDENTITY();";
                    cmd.Parameters.AddWithValue("@AttendeeId",  attendeeId);
                    cmd.Parameters.AddWithValue("@EventId",     eventId);
                    cmd.Parameters.AddWithValue("@TicketCount", ticketCount);
                    cmd.Parameters.AddWithValue("@TotalPrice",  totalPrice);
                    cmd.Parameters.AddWithValue("@BookingDate", DateTime.UtcNow);
                    cmd.Parameters.AddWithValue("@Status",      "confirmed");
                    var id = Convert.ToInt32(cmd.ExecuteScalar());
                    tx.Commit();
                    return id;
                }
            }
        }
    }
}
