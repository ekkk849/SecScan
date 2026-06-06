// vuln_03_format_orderby_hr.cs
// GROUND TRUTH: 4 VULNERABLE methods, 0 SAFE methods
// Patterns: String.Format (2 methods) + ORDER BY injection (2 methods)
// Domain: HR / Payroll system

using System;
using System.Data;
using System.Data.SqlClient;

namespace HR.Data
{
    public class EmployeeRepository
    {
        private readonly string _conn;
        public EmployeeRepository(string conn) { _conn = conn; }

        // VULNERABLE: String.Format with department, jobTitle, status
        public DataTable SearchEmployees(string department, string jobTitle, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = string.Format(
                    "SELECT em.EmployeeId, em.FirstName, em.LastName, em.Email, " +
                    "em.JobTitle, dp.DepartmentName, em.Salary " +
                    "FROM Employees em " +
                    "INNER JOIN Departments dp ON em.DepartmentId = dp.DepartmentId " +
                    "WHERE dp.DepartmentName = '{0}' " +
                    "AND em.JobTitle LIKE '%{1}%' " +
                    "AND em.Status = '{2}'",
                    department, jobTitle, status
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: String.Format on payroll date range
        public DataTable GetPayrollReport(string startDate, string endDate, string department)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = string.Format(
                    "SELECT em.EmployeeId, em.FirstName, em.LastName, " +
                    "py.PayDate, py.GrossPay, py.NetPay, py.Deductions, dp.DepartmentName " +
                    "FROM Payroll py " +
                    "INNER JOIN Employees em ON py.EmployeeId = em.EmployeeId " +
                    "INNER JOIN Departments dp ON em.DepartmentId = dp.DepartmentId " +
                    "WHERE py.PayDate BETWEEN '{0}' AND '{1}' " +
                    "AND dp.DepartmentName = '{2}'",
                    startDate, endDate, department
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: ORDER BY sortColumn + sortDir
        public DataTable GetEmployeesSorted(int departmentId, string sortColumn, string sortDir)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT em.EmployeeId, em.FirstName, em.LastName, " +
                                  "em.Salary, em.HireDate, em.JobTitle " +
                                  "FROM Employees em " +
                                  "WHERE em.DepartmentId = " + departmentId +
                                  " ORDER BY " + sortColumn + " " + sortDir;
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: employeeId, leaveType, sortField via concat + ORDER BY
        public DataTable GetLeaveRequests(string employeeId, string leaveType, string sortField)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT lr.LeaveId, em.FirstName, em.LastName, " +
                                  "lr.LeaveType, lr.StartDate, lr.EndDate, lr.Status " +
                                  "FROM LeaveRequests lr " +
                                  "INNER JOIN Employees em ON lr.EmployeeId = em.EmployeeId " +
                                  "WHERE lr.EmployeeId = '" + employeeId + "' " +
                                  "AND lr.LeaveType = '" + leaveType + "' " +
                                  "ORDER BY " + sortField;
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
