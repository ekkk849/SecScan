// vuln_05_like_injection.cs
// GROUND TRUTH: 3 VULNERABLE methods, 0 SAFE methods
// Patterns: LIKE % injection
// Domain: Recruitment / job portal

using System;
using System.Data;
using System.Data.SqlClient;

namespace Recruitment.Data
{
    public class JobRepository
    {
        private readonly string _conn;
        public JobRepository(string conn) { _conn = conn; }

        // VULNERABLE: jobTitle, skills, location via LIKE concat
        public DataTable SearchJobs(string jobTitle, string skills, string location)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT jb.JobId, jb.JobTitle, jb.Description, " +
                                  "jb.Salary, jb.PostedDate, co.CompanyName, lc.CityName " +
                                  "FROM Jobs jb " +
                                  "INNER JOIN Companies co ON jb.CompanyId = co.CompanyId " +
                                  "INNER JOIN Locations lc ON jb.LocationId = lc.LocationId " +
                                  "WHERE jb.JobTitle LIKE '%" + jobTitle + "%' " +
                                  "AND jb.RequiredSkills LIKE '%" + skills + "%' " +
                                  "AND lc.CityName LIKE '%" + location + "%'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: candidateName, skills, education via LIKE concat
        public DataTable SearchCandidates(string candidateName, string skills, string education)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT ca.CandidateId, ca.FirstName, ca.LastName, " +
                                  "ca.Email, ca.Phone, ca.CurrentTitle, ca.YearsExperience " +
                                  "FROM Candidates ca " +
                                  "WHERE ca.LastName LIKE '%" + candidateName + "%' " +
                                  "AND ca.Skills LIKE '%" + skills + "%' " +
                                  "AND ca.Education LIKE '%" + education + "%'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: companyName, industry, location via LIKE concat
        public DataTable SearchCompanies(string companyName, string industry, string location)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT co.CompanyId, co.CompanyName, co.Industry, " +
                                  "co.Size, co.Website, lc.CityName, co.Description " +
                                  "FROM Companies co " +
                                  "INNER JOIN Locations lc ON co.LocationId = lc.LocationId " +
                                  "WHERE co.CompanyName LIKE '%" + companyName + "%' " +
                                  "AND co.Industry LIKE '%" + industry + "%' " +
                                  "AND lc.CityName LIKE '%" + location + "%'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
