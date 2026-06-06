// vuln_01_concat_healthcare.cs
// GROUND TRUTH: 4 VULNERABLE methods, 0 SAFE methods
// Patterns: string_concat only
// Domain: Hospital patient management

using System;
using System.Data;
using System.Data.SqlClient;

namespace Hospital.Data
{
    public class PatientRepository
    {
        private readonly string _conn;
        public PatientRepository(string conn) { _conn = conn; }

        // VULNERABLE: searchTerm and ward via concat
        public DataTable SearchPatients(string searchTerm, string ward)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT pt.PatientId, pt.FirstName, pt.LastName, pt.NHSNumber, " +
                                  "pt.DateOfBirth, wd.WardName " +
                                  "FROM Patients pt " +
                                  "INNER JOIN Wards wd ON pt.WardId = wd.WardId " +
                                  "WHERE pt.LastName LIKE '%" + searchTerm + "%' " +
                                  "AND wd.WardName = '" + ward + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: doctorId and status via concat
        public DataTable GetPatientsByDoctor(string doctorId, string status)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT pt.PatientId, pt.FirstName, pt.LastName, pt.BloodType, " +
                                  "pt.Allergies, ap.AppointmentDate, ap.Diagnosis " +
                                  "FROM Patients pt " +
                                  "INNER JOIN Appointments ap ON pt.PatientId = ap.PatientId " +
                                  "INNER JOIN Doctors dr ON ap.DoctorId = dr.DoctorId " +
                                  "WHERE dr.DoctorId = '" + doctorId + "' " +
                                  "AND pt.Status = '" + status + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: startDate, endDate, wardName via concat
        public DataTable GetAdmissionReport(string startDate, string endDate, string wardName)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT pt.PatientId, pt.FirstName, pt.LastName, " +
                                  "ad.AdmissionDate, ad.DischargeDate, wd.WardName " +
                                  "FROM Patients pt " +
                                  "INNER JOIN Admissions ad ON pt.PatientId = ad.PatientId " +
                                  "INNER JOIN Wards wd ON ad.WardId = wd.WardId " +
                                  "WHERE ad.AdmissionDate >= '" + startDate + "' " +
                                  "AND ad.AdmissionDate <= '" + endDate + "' " +
                                  "AND wd.WardName = '" + wardName + "'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // VULNERABLE: medicationName and patientLastName via concat
        public DataTable SearchPrescriptions(string medicationName, string patientLastName)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = "SELECT pr.PrescriptionId, pt.FirstName, pt.LastName, " +
                                  "pr.MedicationName, pr.Dosage, pr.Frequency, pr.PrescribedDate " +
                                  "FROM Prescriptions pr " +
                                  "INNER JOIN Patients pt ON pr.PatientId = pt.PatientId " +
                                  "WHERE pr.MedicationName LIKE '%" + medicationName + "%' " +
                                  "AND pt.LastName LIKE '%" + patientLastName + "%'";
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
