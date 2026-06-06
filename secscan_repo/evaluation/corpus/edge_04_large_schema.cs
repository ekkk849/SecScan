// edge_04_large_schema.cs
// GROUND TRUTH: 3 VULNERABLE methods, 2 SAFE methods
// KEY EDGE: very large schema — 12 tables, deeply nested JOINs
//           Tests schema reconstruction accuracy and UNION NULL padding correctness
// Domain: Hospital clinical management (expanded from safe_02)

using System;
using System.Data;
using System.Data.SqlClient;

namespace Hospital.Clinical
{
    public class ClinicalRepository
    {
        private readonly string _conn;
        public ClinicalRepository(string conn) { _conn = conn; }

        // VULNERABLE: patientName and diagnosisCode via concat — 6-table JOIN
        public DataTable SearchClinicalRecords(string patientName, string diagnosisCode, string wardName)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = "SELECT p.PatientId, p.FirstName, p.LastName, p.NHSNumber, " +
                                  "cr.RecordDate, cr.DiagnosisCode, cr.DiagnosisDescription, " +
                                  "d.FirstName AS DoctorFirstName, d.LastName AS DoctorLastName, " +
                                  "w.WardName, dep.DepartmentName, h.HospitalName " +
                                  "FROM ClinicalRecords cr " +
                                  "INNER JOIN Patients p ON cr.PatientId = p.PatientId " +
                                  "INNER JOIN Doctors d ON cr.DoctorId = d.DoctorId " +
                                  "INNER JOIN Wards w ON cr.WardId = w.WardId " +
                                  "INNER JOIN Departments dep ON w.DepartmentId = dep.DepartmentId " +
                                  "INNER JOIN Hospitals h ON dep.HospitalId = h.HospitalId " +
                                  "WHERE p.LastName LIKE '%" + patientName + "%' " +
                                  "AND cr.DiagnosisCode LIKE '%" + diagnosisCode + "%' " +
                                  "AND w.WardName = '" + wardName + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: prescriptionStatus and drugClass via interpolation — 5-table JOIN
        public DataTable GetActivePrescriptions(string patientId, string prescriptionStatus, string drugClass)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = $"SELECT pr.PrescriptionId, pr.PrescribedDate, pr.Dosage, " +
                                  $"pr.Frequency, pr.Duration, pr.Status, " +
                                  $"d.GenericName, d.BrandName, d.DrugClass, " +
                                  $"doc.FirstName AS DocFirst, doc.LastName AS DocLast, " +
                                  $"p.FirstName, p.LastName " +
                                  $"FROM Prescriptions pr " +
                                  $"INNER JOIN Drugs d ON pr.DrugId = d.DrugId " +
                                  $"INNER JOIN Doctors doc ON pr.DoctorId = doc.DoctorId " +
                                  $"INNER JOIN Patients p ON pr.PatientId = p.PatientId " +
                                  $"INNER JOIN DrugCategories dc ON d.CategoryId = dc.CategoryId " +
                                  $"WHERE pr.PatientId = '{patientId}' " +
                                  $"AND pr.Status = '{prescriptionStatus}' " +
                                  $"AND d.DrugClass = '{drugClass}'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized surgical record — 5-table JOIN
        public DataTable GetSurgicalHistory(int patientId, DateTime fromDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT sr.SurgeryId, sr.SurgeryDate, sr.SurgeryType,
                                           sr.Outcome, sr.Duration, sr.Notes,
                                           s.FirstName AS SurgeonFirst, s.LastName AS SurgeonLast,
                                           s.Specialisation,
                                           ot.TheatreName, ot.Floor,
                                           p.FirstName, p.LastName, p.NHSNumber
                                    FROM SurgicalRecords sr
                                    INNER JOIN Surgeons s ON sr.SurgeonId = s.SurgeonId
                                    INNER JOIN OperatingTheatres ot ON sr.TheatreId = ot.TheatreId
                                    INNER JOIN Patients p ON sr.PatientId = p.PatientId
                                    INNER JOIN Hospitals h ON ot.HospitalId = h.HospitalId
                                    WHERE sr.PatientId = @PatientId
                                    AND sr.SurgeryDate >= @FromDate
                                    ORDER BY sr.SurgeryDate DESC";
                cmd.Parameters.AddWithValue("@PatientId", patientId);
                cmd.Parameters.AddWithValue("@FromDate",  fromDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: String.Format on cross-hospital audit — 7-table JOIN
        public DataTable GetHospitalAuditReport(string hospitalCode, string startDate, string endDate, string departmentName)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = string.Format(
                    "SELECT h.HospitalName, dep.DepartmentName, w.WardName, " +
                    "COUNT(DISTINCT cr.PatientId) AS UniquePatients, " +
                    "COUNT(cr.RecordId) AS TotalRecords, " +
                    "COUNT(DISTINCT pr.PrescriptionId) AS Prescriptions, " +
                    "AVG(DATEDIFF(day, adm.AdmissionDate, adm.DischargeDate)) AS AvgStay " +
                    "FROM Hospitals h " +
                    "INNER JOIN Departments dep ON h.HospitalId = dep.HospitalId " +
                    "INNER JOIN Wards w ON dep.DepartmentId = w.DepartmentId " +
                    "INNER JOIN ClinicalRecords cr ON w.WardId = cr.WardId " +
                    "INNER JOIN Admissions adm ON cr.PatientId = adm.PatientId " +
                    "LEFT JOIN Prescriptions pr ON cr.PatientId = pr.PatientId " +
                    "AND pr.PrescribedDate BETWEEN '{1}' AND '{2}' " +
                    "WHERE h.HospitalCode = '{0}' " +
                    "AND dep.DepartmentName = '{3}' " +
                    "AND cr.RecordDate BETWEEN '{1}' AND '{2}' " +
                    "GROUP BY h.HospitalName, dep.DepartmentName, w.WardName",
                    hospitalCode, startDate, endDate, departmentName
                );
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized lab results — 4-table JOIN
        public DataTable GetLabResults(int patientId, string testType, DateTime fromDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT lr.ResultId, lr.TestDate, lr.TestType,
                                           lr.ResultValue, lr.Units, lr.ReferenceRange, lr.Flag,
                                           lt.LabName, lt.Location,
                                           p.FirstName, p.LastName
                                    FROM LabResults lr
                                    INNER JOIN Labs lt ON lr.LabId = lt.LabId
                                    INNER JOIN Patients p ON lr.PatientId = p.PatientId
                                    INNER JOIN Doctors d ON lr.RequestedBy = d.DoctorId
                                    WHERE lr.PatientId = @PatientId
                                    AND lr.TestType = @TestType
                                    AND lr.TestDate >= @FromDate
                                    ORDER BY lr.TestDate DESC";
                cmd.Parameters.AddWithValue("@PatientId", patientId);
                cmd.Parameters.AddWithValue("@TestType",  testType);
                cmd.Parameters.AddWithValue("@FromDate",  fromDate);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
