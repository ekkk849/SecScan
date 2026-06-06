// safe_02_hospital_transactions.cs
// GROUND TRUTH: 0 VULNERABLE methods, 4 SAFE methods
// Patterns: transactions, SqlParameter objects, named params
// Domain: Hospital staff and ward management
// Expected tool output: 0 findings

using System;
using System.Data;
using System.Data.SqlClient;

namespace Hospital.Admin
{
    public class StaffRepository
    {
        private readonly string _conn;
        public StaffRepository(string conn) { _conn = conn; }

        // SAFE: transaction with multiple parameterized statements
        public void AdmitPatient(int patientId, int wardId, int doctorId, DateTime admissionDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection  = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"INSERT INTO Admissions (PatientId, WardId, DoctorId, AdmissionDate, Status)
                                        VALUES (@PatientId, @WardId, @DoctorId, @AdmissionDate, @Status);
                                        UPDATE Patients SET Status = @NewStatus WHERE PatientId = @PatientId;";
                    cmd.Parameters.AddWithValue("@PatientId",     patientId);
                    cmd.Parameters.AddWithValue("@WardId",        wardId);
                    cmd.Parameters.AddWithValue("@DoctorId",      doctorId);
                    cmd.Parameters.AddWithValue("@AdmissionDate", admissionDate);
                    cmd.Parameters.AddWithValue("@Status",        "admitted");
                    cmd.Parameters.AddWithValue("@NewStatus",     "inpatient");
                    cmd.ExecuteNonQuery();
                    tx.Commit();
                }
            }
        }

        // SAFE: SqlParameter objects (not AddWithValue) — different safe style
        public DataTable GetWardCapacity(int wardId, string shiftType)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT w.WardName, w.Capacity, w.CurrentOccupancy,
                                           s.StaffId, s.FirstName, s.LastName, s.ShiftType
                                    FROM Wards w
                                    INNER JOIN Staff s ON s.WardId = w.WardId
                                    WHERE w.WardId = @WardId
                                    AND s.ShiftType = @ShiftType";
                cmd.Parameters.Add(new SqlParameter("@WardId",    SqlDbType.Int)     { Value = wardId });
                cmd.Parameters.Add(new SqlParameter("@ShiftType", SqlDbType.VarChar) { Value = shiftType });
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }

        // SAFE: parameterized DELETE inside transaction
        public void DischargePatient(int admissionId, DateTime dischargeDate, string notes)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                using (var tx = conn.BeginTransaction())
                {
                    var cmd = new SqlCommand();
                    cmd.Connection  = conn;
                    cmd.Transaction = tx;
                    cmd.CommandText = @"UPDATE Admissions
                                        SET DischargeDate = @DischargeDate,
                                            DischargeNotes = @Notes,
                                            Status = @Status
                                        WHERE AdmissionId = @AdmissionId";
                    cmd.Parameters.AddWithValue("@AdmissionId",   admissionId);
                    cmd.Parameters.AddWithValue("@DischargeDate", dischargeDate);
                    cmd.Parameters.AddWithValue("@Notes",         notes);
                    cmd.Parameters.AddWithValue("@Status",        "discharged");
                    cmd.ExecuteNonQuery();
                    tx.Commit();
                }
            }
        }

        // SAFE: parameterized staff lookup
        public DataTable GetDoctorSchedule(int doctorId, DateTime scheduleDate)
        {
            using (var conn = new SqlConnection(_conn))
            {
                conn.Open();
                var cmd = new SqlCommand();
                cmd.Connection  = conn;
                cmd.CommandText = @"SELECT d.DoctorId, d.FirstName, d.LastName,
                                           d.Specialisation, sch.StartTime, sch.EndTime,
                                           w.WardName
                                    FROM Doctors d
                                    INNER JOIN Schedules sch ON d.DoctorId = sch.DoctorId
                                    INNER JOIN Wards w ON sch.WardId = w.WardId
                                    WHERE d.DoctorId = @DoctorId
                                    AND CAST(sch.StartTime AS DATE) = @ScheduleDate";
                cmd.Parameters.AddWithValue("@DoctorId",     doctorId);
                cmd.Parameters.AddWithValue("@ScheduleDate", scheduleDate.Date);
                var da = new SqlDataAdapter(cmd);
                var dt = new DataTable();
                da.Fill(dt);
                return dt;
            }
        }
    }
}
