// edge_02_stringbuilder_blindspot.cs
// GROUND TRUTH: 3 VULNERABLE methods, 2 SAFE methods
// Edge cases tested:
//   (A) StringBuilder.Append() injection — tool CANNOT detect this (known FN blind spot)
//   (B) Standard concat injection — tool CAN detect
//   (C) Mix of both — tool partially detects
// Domain: Real estate property listings
//
// EXPECTED TOOL BEHAVIOUR:
//   SearchPropertiesByBuilder  -> FN (StringBuilder, tool misses it completely)
//   GetAgentListings_Builder   -> FN (StringBuilder, tool misses it completely)
//   FilterProperties_Concat    -> TP (standard concat, tool finds it)
//   GetPropertyById            -> TN (safe, tool skips it)
//   GetAgentStats              -> TN (safe, tool skips it)

using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace RealEstate.Data
{
    public class PropertyRepository
    {
        private readonly string _conn;
        public PropertyRepository(string conn) { _conn = conn; }

        // VULNERABLE via StringBuilder — tool WILL MISS THIS (blind spot)
        // Injection params: propertyType, city, agentName
        public DataTable SearchPropertiesByBuilder(string propertyType, string city, string agentName)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd  = new SqlCommand();
                cmd.Connection = conn;
                var sql  = new StringBuilder();
                sql.Append("SELECT pr.PropertyId, pr.Title, pr.PropertyType, ");
                sql.Append("pr.Price, pr.Bedrooms, pr.Bathrooms, pr.SquareFootage, ");
                sql.Append("a.FirstName, a.LastName, ci.CityName ");
                sql.Append("FROM Properties pr ");
                sql.Append("INNER JOIN Agents a ON pr.AgentId = a.AgentId ");
                sql.Append("INNER JOIN Cities ci ON pr.CityId = ci.CityId ");
                sql.Append("WHERE pr.PropertyType = '" + propertyType + "' ");
                sql.Append("AND ci.CityName = '" + city + "' ");
                sql.Append("AND a.LastName LIKE '%" + agentName + "%'");
                cmd.CommandText = sql.ToString();
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE via StringBuilder — tool WILL MISS THIS
        // Injection params: agentId (string), status
        public DataTable GetAgentListings_Builder(string agentId, string status, string sortColumn)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                var sql = new StringBuilder();
                sql.Append("SELECT pr.PropertyId, pr.Title, pr.Price, pr.Status, ");
                sql.Append("pr.ListedDate, pr.Bedrooms, pr.Bathrooms ");
                sql.Append("FROM Properties pr ");
                sql.Append("INNER JOIN Agents a ON pr.AgentId = a.AgentId ");
                sql.Append("WHERE a.AgentId = '");
                sql.Append(agentId);
                sql.Append("' AND pr.Status = '");
                sql.Append(status);
                sql.Append("' ORDER BY ");
                sql.Append(sortColumn);
                cmd.CommandText = sql.ToString();
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE via standard concat — tool WILL FIND THIS
        // Injection params: minPrice, maxPrice (strings), propertyType
        public DataTable FilterProperties_Concat(string minPrice, string maxPrice, string propertyType, string city)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT pr.PropertyId, pr.Title, pr.Price, " +
                                  "pr.PropertyType, ci.CityName, pr.Bedrooms " +
                                  "FROM Properties pr " +
                                  "INNER JOIN Cities ci ON pr.CityId = ci.CityId " +
                                  "WHERE pr.Price >= " + minPrice +
                                  " AND pr.Price <= " + maxPrice +
                                  " AND pr.PropertyType = '" + propertyType + "'" +
                                  " AND ci.CityName = '" + city + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized property detail lookup
        public DataTable GetPropertyById(int propertyId)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT pr.PropertyId, pr.Title, pr.Description,
                                           pr.Price, pr.Bedrooms, pr.Bathrooms,
                                           pr.SquareFootage, pr.ListedDate,
                                           a.FirstName, a.LastName, a.Email,
                                           ci.CityName, pr.PostCode
                                    FROM Properties pr
                                    INNER JOIN Agents a ON pr.AgentId = a.AgentId
                                    INNER JOIN Cities ci ON pr.CityId = ci.CityId
                                    WHERE pr.PropertyId = @PropertyId";
                cmd.Parameters.AddWithValue("@PropertyId", propertyId);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized agent stats
        public DataTable GetAgentStats(int agentId, DateTime fromDate, DateTime toDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT a.AgentId, a.FirstName, a.LastName,
                                           COUNT(pr.PropertyId) AS TotalListings,
                                           COUNT(CASE WHEN pr.Status = 'sold' THEN 1 END) AS SoldCount,
                                           SUM(CASE WHEN pr.Status = 'sold' THEN pr.Price ELSE 0 END) AS TotalSalesValue
                                    FROM Agents a
                                    INNER JOIN Properties pr ON a.AgentId = pr.AgentId
                                    WHERE a.AgentId = @AgentId
                                    AND pr.ListedDate BETWEEN @FromDate AND @ToDate
                                    GROUP BY a.AgentId, a.FirstName, a.LastName";
                cmd.Parameters.AddWithValue("@AgentId",  agentId);
                cmd.Parameters.AddWithValue("@FromDate", fromDate);
                cmd.Parameters.AddWithValue("@ToDate",   toDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
