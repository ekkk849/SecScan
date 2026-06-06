// mixed_03_library_lowvuln.cs
// GROUND TRUTH: 1 VULNERABLE method, 4 SAFE methods
// Ratio: 20% vulnerable — tests precision, tool must find the needle in mostly-safe code
// Domain: Library management
// Vuln method: SearchBooks (title, author via concat)
// Safe methods: GetMemberLoans, ReserveBook, ReturnBook, GetOverdueLoans

using System;
using System.Data;
using System.Data.SqlClient;

namespace Library.Data
{
    public class LibraryRepository
    {
        private readonly string _conn;
        public LibraryRepository(string conn) { _conn = conn; }

        // VULNERABLE: title and author via string concat — the one needle
        public DataTable SearchBooks(string title, string author, string genre)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT b.BookId, b.Title, b.Author, b.ISBN, " +
                                  "b.Genre, b.PublishYear, b.AvailableCopies " +
                                  "FROM Books b " +
                                  "WHERE b.Title LIKE '%" + title + "%' " +
                                  "AND b.Author LIKE '%" + author + "%' " +
                                  "AND b.Genre = '" + genre + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized member loan history
        public DataTable GetMemberLoans(int memberId, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT l.LoanId, b.Title, b.Author, b.ISBN,
                                           l.LoanDate, l.DueDate, l.ReturnDate, l.Status
                                    FROM Loans l
                                    INNER JOIN Books b ON l.BookId = b.BookId
                                    INNER JOIN Members m ON l.MemberId = m.MemberId
                                    WHERE l.MemberId = @MemberId
                                    AND l.Status = @Status
                                    ORDER BY l.LoanDate DESC";
                cmd.Parameters.AddWithValue("@MemberId", memberId);
                cmd.Parameters.AddWithValue("@Status",   status);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized reservation with transaction
        public int ReserveBook(int memberId, int bookId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection  = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"INSERT INTO Reservations (MemberId, BookId, ReservedDate, Status)
                                        VALUES (@MemberId, @BookId, @ReservedDate, @Status);
                                        UPDATE Books SET ReservedCopies = ReservedCopies + 1
                                        WHERE BookId = @BookId;
                                        SELECT SCOPE_IDENTITY();";
                    cmd.Parameters.AddWithValue("@MemberId",     memberId);
                    cmd.Parameters.AddWithValue("@BookId",       bookId);
                    cmd.Parameters.AddWithValue("@ReservedDate", DateTime.UtcNow);
                    cmd.Parameters.AddWithValue("@Status",       "active");
                    var id = Convert.ToInt32(cmd.ExecuteScalar());
                    tx.Commit();
                    return id;
                }
            }
        }

        // SAFE: parameterized return
        public void ReturnBook(int loanId, DateTime returnDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection  = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"UPDATE Loans
                                        SET ReturnDate = @ReturnDate, Status = @Status
                                        WHERE LoanId = @LoanId;
                                        UPDATE Books SET AvailableCopies = AvailableCopies + 1
                                        WHERE BookId = (SELECT BookId FROM Loans WHERE LoanId = @LoanId);";
                    cmd.Parameters.AddWithValue("@LoanId",     loanId);
                    cmd.Parameters.AddWithValue("@ReturnDate", returnDate);
                    cmd.Parameters.AddWithValue("@Status",     "returned");
                    cmd.ExecuteNonQuery();
                    tx.Commit();
                }
            }
        }

        // SAFE: overdue report, parameterized
        public DataTable GetOverdueLoans(int daysOverdue)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT l.LoanId, m.FirstName, m.LastName, m.Email,
                                           b.Title, b.ISBN, l.DueDate,
                                           DATEDIFF(day, l.DueDate, GETDATE()) AS DaysOverdue
                                    FROM Loans l
                                    INNER JOIN Members m ON l.MemberId = m.MemberId
                                    INNER JOIN Books b ON l.BookId = b.BookId
                                    WHERE l.Status = @Status
                                    AND DATEDIFF(day, l.DueDate, GETDATE()) >= @DaysOverdue
                                    ORDER BY DaysOverdue DESC";
                cmd.Parameters.AddWithValue("@Status",      "active");
                cmd.Parameters.AddWithValue("@DaysOverdue", daysOverdue);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
