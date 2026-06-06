# app.py — SecScan v2.0

import os
import sqlite3
import json
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, Response)
from parser import SQLParser
from db_builder import DBBuilder
from injector import SmartInjector
from report import ReportGenerator

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secscan-dev-key-change-in-prod")

DB_FILE = "simulation.db"
MAX_FILE_SIZE = 512 * 1024  # 512 KB


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _rebuild_db(parsed_data: dict) -> tuple[bool, str]:
    """Drop and recreate simulation DB. Returns (success, error_msg)."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    builder = DBBuilder(parsed_data)
    try:
        builder.execute_and_populate()
        return True, ""
    except Exception as e:
        return False, str(e)


def _get_builder(parsed_data: dict) -> DBBuilder:
    return DBBuilder(parsed_data)


# ──────────────────────────────────────────────
# 1. Upload
# ──────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="No file uploaded.")

        if not file.filename.endswith((".cs", ".txt", ".sql")):
            return render_template("upload.html", error="Please upload a .cs, .sql, or .txt file.")

        code = file.read(MAX_FILE_SIZE).decode("utf-8", errors="ignore")
        if not code.strip():
            return render_template("upload.html", error="File is empty.")

        parser = SQLParser(code, file_name=file.filename)
        parsed_data = parser.parse()

        if not parsed_data["columns"]:
            return render_template("upload.html",
                error="No SQL table references detected. Make sure the file contains SQL queries.")

        session.clear()
        session["parsed_data"] = parsed_data
        session["sql_blocks"]  = parser.extract_sql_blocks()
        session["file_name"]   = file.filename

        return redirect(url_for("overview"))

    return render_template("upload.html")


# ──────────────────────────────────────────────
# 2. Overview / findings dashboard
# ──────────────────────────────────────────────

@app.route("/overview")
def overview():
    parsed_data = session.get("parsed_data")
    if not parsed_data:
        return redirect(url_for("upload"))

    findings = parsed_data.get("findings", [])
    tables   = list(parsed_data["columns"].keys())
    file_name = session.get("file_name", "unknown.cs")

    high   = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    return render_template("overview.html",
        findings=findings,
        high=high,
        medium=medium,
        tables=tables,
        file_name=file_name,
        parsed_data=parsed_data,
        db_type=parsed_data.get("db_type", "sqlite"),
    )


# ──────────────────────────────────────────────
# 3. Table selection
# ──────────────────────────────────────────────

@app.route("/tables", methods=["GET", "POST"])
def tables():
    parsed_data = session.get("parsed_data")
    if not parsed_data:
        return redirect(url_for("upload"))

    tables = list(parsed_data["columns"].keys())

    if request.method == "POST":
        selected = request.form.get("table")
        if not selected or selected not in tables:
            return render_template("tables.html", tables=tables, error="Please select a valid table.")
        session["selected_table"] = selected
        return redirect(url_for("inject"))

    return render_template("tables.html", tables=tables,
                           parsed_data=parsed_data)


# ──────────────────────────────────────────────
# 4. Injection testing
# ──────────────────────────────────────────────

@app.route("/inject", methods=["GET", "POST"])
def inject():
    parsed_data    = session.get("parsed_data")
    selected_table = session.get("selected_table")
    sql_blocks     = session.get("sql_blocks", [])

    if not parsed_data or not selected_table:
        return redirect(url_for("upload"))

    builder  = _get_builder(parsed_data)
    injector = SmartInjector(parsed_data, column_counts=builder.column_counts)

    # Find the SQL block for this table
    chosen_sql = next(
        (s for s in sql_blocks if selected_table.lower() in s.lower()),
        None
    )
    if not chosen_sql and sql_blocks:
        chosen_sql = sql_blocks[0]

    # Column metadata for the UI
    col_types     = parsed_data["column_types"].get(selected_table, {})
    safe_cols     = set(parsed_data.get("safe_columns", {}).get(selected_table, []))
    vuln_cols     = set(parsed_data.get("vulnerable_columns", {}).get(selected_table, []))
    available_atk = injector.available_attacks()

    # Filter: exclude PK columns from the dropdown
    pk_col = f"{selected_table.lower()}id"
    injectable_cols = {
        col: ctype for col, ctype in col_types.items()
        if col.lower() != pk_col
    }

    result  = None
    payload = None
    error   = None
    query_executed = None
    column_status = None  # "safe" | "vulnerable" | "unknown"

    if request.method == "POST":
        column = request.form.get("column")
        attack = request.form.get("attack")

        if not column or not attack:
            error = "Select a column and attack type."
        elif column not in injectable_cols:
            error = f"Column '{column}' is not injectable."
        else:
            column_status = (
                "safe"       if column in safe_cols  else
                "vulnerable" if column in vuln_cols  else
                "unknown"
            )

            payload = injector.inject(selected_table, column, attack)

            if payload is None:
                error = f"Column '{column}' is either a join key or uses parameterized queries — skipping."
            else:
                # Rebuild DB fresh
                ok, err = _rebuild_db(parsed_data)
                if not ok:
                    error = f"Schema build error: {err}"
                else:
                    conn   = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()

                    col_type = injectable_cols.get(column, "TEXT")
                    if col_type == "INTEGER":
                        query_executed = f'SELECT * FROM "{selected_table}" WHERE "{column}" = {payload};'
                    else:
                        query_executed = f'SELECT * FROM "{selected_table}" WHERE "{column}" = \'{payload}\';'

                    try:
                        cursor.execute(query_executed)
                        rows = cursor.fetchall()
                        col_names = [d[0] for d in cursor.description] if cursor.description else []
                        result = {"columns": col_names, "rows": rows, "count": len(rows)}
                    except Exception as e:
                        result = {"error": str(e), "columns": [], "rows": [], "count": 0}

                    conn.close()

                    # Store this test in session results
                    tests = session.get("injection_tests", [])
                    tests.append({
                        "table":         selected_table,
                        "column":        column,
                        "attack":        attack,
                        "payload":       payload,
                        "rows_returned": result.get("count", 0) if isinstance(result, dict) else 0,
                        "error":         result.get("error") if isinstance(result, dict) else None,
                    })
                    session["injection_tests"] = tests

    return render_template("inject.html",
        original_sql   = chosen_sql,
        table          = selected_table,
        columns        = injectable_cols,
        safe_cols      = safe_cols,
        vuln_cols      = vuln_cols,
        payload        = payload,
        result         = result,
        error          = error,
        query_executed = query_executed,
        column_status  = column_status,
        available_attacks = available_atk,
        db_type        = parsed_data.get("db_type", "sqlite"),
    )


# ──────────────────────────────────────────────
# 5. Report download
# ──────────────────────────────────────────────

@app.route("/report/<fmt>")
def download_report(fmt: str):
    parsed_data = session.get("parsed_data")
    if not parsed_data:
        return redirect(url_for("upload"))

    file_name = session.get("file_name", "scan.cs")
    inj_tests = session.get("injection_tests", [])

    gen = ReportGenerator(parsed_data, file_name=file_name, injection_results=inj_tests)

    if fmt == "json":
        return Response(
            gen.to_json(),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=secscan_report.json"}
        )
    elif fmt == "html":
        return Response(
            gen.to_html(),
            mimetype="text/html",
            headers={"Content-Disposition": "attachment; filename=secscan_report.html"}
        )
    else:
        return "Unknown format", 400


# ──────────────────────────────────────────────
# 6. API endpoint — run all attacks on all tables
# ──────────────────────────────────────────────

@app.route("/api/scan-all", methods=["POST"])
def scan_all():
    """Run all attack types on all non-safe columns. Returns JSON."""
    parsed_data = session.get("parsed_data")
    if not parsed_data:
        return jsonify({"error": "No scan data in session"}), 400

    builder  = _get_builder(parsed_data)
    injector = SmartInjector(parsed_data, column_counts=builder.column_counts)

    ok, err = _rebuild_db(parsed_data)
    if not ok:
        return jsonify({"error": err}), 500

    results = []
    attacks = [a["value"] for a in injector.available_attacks()]
    conn = sqlite3.connect(DB_FILE)

    for table, col_types in parsed_data["column_types"].items():
        pk_col = f"{table.lower()}id"
        for column, col_type in col_types.items():
            if column.lower() == pk_col:
                continue
            for attack in attacks:
                payload = injector.inject(table, column, attack)
                if payload is None:
                    continue

                if col_type == "INTEGER":
                    query = f'SELECT * FROM "{table}" WHERE "{column}" = {payload};'
                else:
                    query = f'SELECT * FROM "{table}" WHERE "{column}" = \'{payload}\';'

                try:
                    cursor = conn.cursor()
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    results.append({
                        "table": table, "column": column, "attack": attack,
                        "payload": payload, "rows_returned": len(rows), "error": None
                    })
                except Exception as e:
                    results.append({
                        "table": table, "column": column, "attack": attack,
                        "payload": payload, "rows_returned": 0, "error": str(e)
                    })

    conn.close()
    session["injection_tests"] = results
    return jsonify({"results": results, "total": len(results)})


# ──────────────────────────────────────────────
# 7. Reset
# ──────────────────────────────────────────────

@app.route("/reset")
def reset():
    session.clear()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    return redirect(url_for("upload"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
