// mixed_01_school_highvuln.cs
// GROUND TRUTH: 4 VULNERABLE methods, 1 SAFE method
// Ratio: 80% vulnerable — tests whether tool stays precise under high vuln density
// Domain: School management system
// Vuln params: studentName, grade, subject, teacherId(string), term, year(string)

using System;
using System.Data;
using System.Data.SqlClient;

namespace School.Data
{
    public class SchoolRepository
    {
        private readonly string _conn;
        public SchoolRepository(string conn) { _conn = conn; }

        // VULNERABLE: studentName and grade via concat
        public DataTable SearchStudents(string studentName, string grade, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT s.StudentId, s.FirstName, s.LastName, " +
                                  "s.Grade, s.Email, c.ClassName " +
                                  "FROM Students s " +
                                  "INNER JOIN Classes c ON s.ClassId = c.ClassId " +
                                  "WHERE s.LastName LIKE '%" + studentName + "%' " +
                                  "AND s.Grade = '" + grade + "' " +
                                  "AND s.Status = '" + status + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: teacherId (string) and subject via concat
        public DataTable GetClassesByTeacher(string teacherId, string subject)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT c.ClassId, c.ClassName, c.Subject, " +
                                  "t.FirstName, t.LastName, c.Schedule " +
                                  "FROM Classes c " +
                                  "INNER JOIN Teachers t ON c.TeacherId = t.TeacherId " +
                                  "WHERE t.TeacherId = '" + teacherId + "' " +
                                  "AND c.Subject = '" + subject + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: term and year (string) via String.Format
        public DataTable GetExamResults(string term, string year, string subject)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Format(
                    "SELECT s.FirstName, s.LastName, e.Subject, " +
                    "e.Score, e.Grade, e.ExamDate " +
                    "FROM ExamResults e " +
                    "INNER JOIN Students s ON e.StudentId = s.StudentId " +
                    "WHERE e.Term = '{0}' AND e.Year = '{1}' AND e.Subject = '{2}'",
                    term, year, subject
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: interpolated attendance lookup
        public DataTable GetAttendanceReport(string classId, string month, string year)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = $"SELECT s.FirstName, s.LastName, " +
                                  $"a.AttendanceDate, a.Status, c.ClassName " +
                                  $"FROM Attendance a " +
                                  $"INNER JOIN Students s ON a.StudentId = s.StudentId " +
                                  $"INNER JOIN Classes c ON a.ClassId = c.ClassId " +
                                  $"WHERE a.ClassId = '{classId}' " +
                                  $"AND MONTH(a.AttendanceDate) = {month} " +
                                  $"AND YEAR(a.AttendanceDate) = {year}";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized fee lookup
        public DataTable GetStudentFees(int studentId, string feeType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT f.FeeId, f.FeeType, f.Amount,
                                           f.DueDate, f.PaidDate, f.Status,
                                           s.FirstName, s.LastName
                                    FROM Fees f
                                    INNER JOIN Students s ON f.StudentId = s.StudentId
                                    WHERE f.StudentId = @StudentId
                                    AND f.FeeType = @FeeType";
                cmd.Parameters.AddWithValue("@StudentId", studentId);
                cmd.Parameters.AddWithValue("@FeeType",   feeType);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
