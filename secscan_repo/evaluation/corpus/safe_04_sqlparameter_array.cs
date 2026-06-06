// safe_04_sqlparameter_array.cs
// GROUND TRUTH: 0 VULNERABLE methods, 4 SAFE methods
// Patterns: SqlParameter array construction, new SqlParameter() style — not AddWithValue
// Domain: University student records
// Tests whether the tool recognises SqlParameter objects (not just AddWithValue)

using System;
using System.Data;
using System.Data.SqlClient;

namespace University.Data
{
    public class StudentRecordsRepository
    {
        private readonly string _conn;
        public StudentRecordsRepository(string conn) { _conn = conn; }

        // SAFE: SqlParameter array passed to command
        public DataTable GetStudentTranscript(int studentId, int academicYear)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT m.ModuleCode, m.ModuleName, m.Credits,
                                           g.Grade, g.Mark, g.ExamDate, g.Status
                                    FROM Grades g
                                    INNER JOIN Modules m ON g.ModuleId = m.ModuleId
                                    INNER JOIN Students s ON g.StudentId = s.StudentId
                                    WHERE g.StudentId = @StudentId
                                    AND g.AcademicYear = @AcademicYear
                                    ORDER BY m.ModuleCode";
                cmd.Parameters.AddRange(new SqlParameter[]
                {
                    new SqlParameter("@StudentId",    SqlDbType.Int) { Value = studentId },
                    new SqlParameter("@AcademicYear", SqlDbType.Int) { Value = academicYear }
                });
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: new SqlParameter() with explicit type and size
        public DataTable GetCourseEnrollments(string courseCode, string semester, int year)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT s.StudentId, s.FirstName, s.LastName,
                                           s.Email, e.EnrollDate, e.Status,
                                           c.CourseName, c.CourseCode
                                    FROM Enrollments e
                                    INNER JOIN Students s ON e.StudentId = s.StudentId
                                    INNER JOIN Courses c ON e.CourseId = c.CourseId
                                    WHERE c.CourseCode = @CourseCode
                                    AND e.Semester = @Semester
                                    AND e.AcademicYear = @Year";
                cmd.Parameters.Add(new SqlParameter("@CourseCode", SqlDbType.VarChar, 10)  { Value = courseCode });
                cmd.Parameters.Add(new SqlParameter("@Semester",   SqlDbType.VarChar, 20)  { Value = semester });
                cmd.Parameters.Add(new SqlParameter("@Year",       SqlDbType.Int)           { Value = year });
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized INSERT with SqlParameter array
        public int EnrollStudent(int studentId, int courseId, string semester, int year)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"INSERT INTO Enrollments
                                    (StudentId, CourseId, Semester, AcademicYear, EnrollDate, Status)
                                    VALUES (@StudentId, @CourseId, @Semester, @Year, @EnrollDate, @Status);
                                    SELECT SCOPE_IDENTITY();";
                cmd.Parameters.AddRange(new SqlParameter[]
                {
                    new SqlParameter("@StudentId",  SqlDbType.Int)          { Value = studentId },
                    new SqlParameter("@CourseId",   SqlDbType.Int)          { Value = courseId },
                    new SqlParameter("@Semester",   SqlDbType.VarChar, 20)  { Value = semester },
                    new SqlParameter("@Year",       SqlDbType.Int)          { Value = year },
                    new SqlParameter("@EnrollDate", SqlDbType.DateTime)     { Value = DateTime.UtcNow },
                    new SqlParameter("@Status",     SqlDbType.VarChar, 20)  { Value = "active" }
                });
                return Convert.ToInt32(cmd.ExecuteScalar());
            }
        }

        // SAFE: parameterized grade update
        public void UpdateGrade(int gradeId, decimal mark, string grade, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"UPDATE Grades
                                    SET Mark = @Mark, Grade = @Grade,
                                        Status = @Status, LastModified = @LastModified
                                    WHERE GradeId = @GradeId";
                cmd.Parameters.AddRange(new SqlParameter[]
                {
                    new SqlParameter("@GradeId",      SqlDbType.Int)          { Value = gradeId },
                    new SqlParameter("@Mark",         SqlDbType.Decimal)      { Value = mark, Precision = 5, Scale = 2 },
                    new SqlParameter("@Grade",        SqlDbType.VarChar, 5)   { Value = grade },
                    new SqlParameter("@Status",       SqlDbType.VarChar, 20)  { Value = status },
                    new SqlParameter("@LastModified", SqlDbType.DateTime)     { Value = DateTime.UtcNow }
                });
                cmd.ExecuteNonQuery();
            }
        }
    }
}
