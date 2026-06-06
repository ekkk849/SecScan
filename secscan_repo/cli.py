#!/usr/bin/env python3
# cli.py — SecScan CLI
# Usage: python cli.py <file.cs> [options]
#
# Place this file in the same folder as parser.py, db_builder.py, injector.py, report.py
# i.e. inside the Editted/ directory alongside the rest of the project.

import argparse
import json
import os
import sqlite3
import sys

from parser import SQLParser
from db_builder import DBBuilder
from injector import SmartInjector
from report import ReportGenerator

DB_FILE = "simulation.db"

# ── Colours (stripped automatically if stdout is not a terminal) ──────────────
def _supports_colour():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

class C:
    if _supports_colour():
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        GREEN  = "\033[92m"
        CYAN   = "\033[96m"
        BOLD   = "\033[1m"
        DIM    = "\033[2m"
        RESET  = "\033[0m"
    else:
        RED = YELLOW = GREEN = CYAN = BOLD = DIM = RESET = ""

def header(text):
    width = 60
    print(f"\n{C.BOLD}{C.CYAN}{'─' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {text}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'─' * width}{C.RESET}")

def ok(msg):    print(f"  {C.GREEN}✔{C.RESET}  {msg}")
def warn(msg):  print(f"  {C.YELLOW}⚠{C.RESET}  {msg}")
def err(msg):   print(f"  {C.RED}✘{C.RESET}  {msg}")
def info(msg):  print(f"  {C.DIM}{msg}{C.RESET}")
def sep():      print(f"  {'·' * 56}")


# ── Step 1: Parse ─────────────────────────────────────────────────────────────
def run_parse(filepath: str) -> tuple[dict, list[str]]:
    if not os.path.isfile(filepath):
        err(f"File not found: {filepath}")
        sys.exit(1)

    if not filepath.endswith((".cs", ".sql", ".txt")):
        warn("Expected a .cs, .sql, or .txt file — continuing anyway.")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read(512 * 1024)   # 512 KB cap — same as web app

    if not code.strip():
        err("File is empty.")
        sys.exit(1)

    file_name = os.path.basename(filepath)
    parser = SQLParser(code, file_name=file_name)
    parsed_data = parser.parse()
    sql_blocks  = parser.extract_sql_blocks()

    if not parsed_data["columns"]:
        err("No SQL table references detected.")
        sys.exit(1)

    return parsed_data, sql_blocks


# ── Step 2: Print overview ────────────────────────────────────────────────────
def print_overview(parsed_data: dict, file_name: str):
    header(f"Scan results — {file_name}")

    tables   = list(parsed_data["columns"].keys())
    findings = parsed_data["findings"]
    high     = [f for f in findings if f["severity"] == "HIGH"]
    medium   = [f for f in findings if f["severity"] == "MEDIUM"]

    print(f"\n  DB type   : {C.BOLD}{parsed_data['db_type'].upper()}{C.RESET}")
    print(f"  Tables    : {C.BOLD}{len(tables)}{C.RESET}  ({', '.join(tables)})")
    print(f"  Findings  : {C.RED}{len(high)} HIGH{C.RESET}  |  {C.YELLOW}{len(medium)} MEDIUM{C.RESET}")

    if findings:
        header("Vulnerability findings")
        for f in findings:
            colour = C.RED if f["severity"] == "HIGH" else C.YELLOW
            sev    = f["severity"]
            print(f"\n  {colour}[{sev}]{C.RESET}  Line {f['line_number']} — {f['vuln_type']}")
            print(f"        Table  : {f['table']}  |  Column: {f['column'] or '—'}")
            print(f"        Snippet: {C.DIM}{f['code_snippet'][:80]}…{C.RESET}")
            print(f"        Fix    : {f['recommendation']}")

    header("Columns per table")
    for table, cols in sorted(parsed_data["columns"].items()):
        vuln = set(parsed_data.get("vulnerable_columns", {}).get(table, []))
        safe = set(parsed_data.get("safe_columns",       {}).get(table, []))
        col_display = []
        for c in cols:
            if c in vuln:
                col_display.append(f"{C.RED}{c}✘{C.RESET}")
            elif c in safe:
                col_display.append(f"{C.GREEN}{c}✔{C.RESET}")
            else:
                col_display.append(c)
        print(f"\n  {C.BOLD}{table}{C.RESET}")
        print(f"    {' | '.join(col_display)}")
    print(f"\n  {C.RED}✘ vulnerable{C.RESET}   {C.GREEN}✔ parameterized/safe{C.RESET}   unmarked = unclassified")


# ── Step 3: Build DB ──────────────────────────────────────────────────────────
def rebuild_db(parsed_data: dict) -> bool:
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    builder = DBBuilder(parsed_data)
    try:
        builder.execute_and_populate()
        return True
    except Exception as e:
        err(f"Schema build error: {e}")
        return False


# ── Step 4: Run injections ────────────────────────────────────────────────────
def run_injections(
    parsed_data: dict,
    tables_filter: list[str] | None,
    attacks_filter: list[str] | None,
    verbose: bool,
) -> list[dict]:
    builder  = DBBuilder(parsed_data)
    injector = SmartInjector(parsed_data, column_counts=builder.column_counts)

    header("Building simulation DB")
    if not rebuild_db(parsed_data):
        sys.exit(1)
    ok("Database created and populated.")

    available_attacks = [a["value"] for a in injector.available_attacks()]
    attacks = attacks_filter if attacks_filter else available_attacks

    # Validate requested attacks
    for a in attacks:
        if a not in available_attacks:
            warn(f"Unknown attack type '{a}' — skipping. Valid: {available_attacks}")
    attacks = [a for a in attacks if a in available_attacks]

    tables = tables_filter if tables_filter else list(parsed_data["column_types"].keys())
    # Validate requested tables
    valid_tables = set(parsed_data["column_types"].keys())
    for t in tables:
        if t not in valid_tables:
            warn(f"Table '{t}' not found — skipping.")
    tables = [t for t in tables if t in valid_tables]

    header("Running injection tests")
    results = []
    conn = sqlite3.connect(DB_FILE)

    for table in tables:
        col_types = parsed_data["column_types"].get(table, {})
        pk_col    = f"{table.lower().rstrip('s')}id"
        print(f"\n  {C.BOLD}{table}{C.RESET}")

        for column, col_type in col_types.items():
            if column.lower() in (pk_col, f"{table.lower()}id"):
                info(f"  {column:<20} — skipped (primary key)")
                continue

            for attack in attacks:
                payload = injector.inject(table, column, attack)
                if payload is None:
                    if verbose:
                        info(f"  {column:<20} [{attack:<8}] — skipped (safe/join column)")
                    continue

                if col_type == "INTEGER":
                    query = f'SELECT * FROM "{table}" WHERE "{column}" = {payload};'
                else:
                    query = f'SELECT * FROM "{table}" WHERE "{column}" = \'{payload}\';'

                try:
                    cursor = conn.cursor()
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    count = len(rows)
                    results.append({
                        "table": table, "column": column, "attack": attack,
                        "payload": payload, "rows_returned": count, "error": None,
                        "query": query,
                    })
                    if count > 0:
                        print(f"  {C.RED}  ✘ INJECTED{C.RESET}  {column:<20} [{attack:<8}]  → {count} rows  |  {C.DIM}{payload}{C.RESET}")
                    else:
                        if verbose:
                            ok(f"  {column:<20} [{attack:<8}]  → 0 rows (blocked or no match)")

                except Exception as e:
                    results.append({
                        "table": table, "column": column, "attack": attack,
                        "payload": payload, "rows_returned": 0, "error": str(e),
                        "query": query,
                    })
                    if verbose:
                        warn(f"  {column:<20} [{attack:<8}]  → ERROR: {e}")

    conn.close()
    return results


# ── Step 5: Summary ───────────────────────────────────────────────────────────
def print_summary(results: list[dict]):
    header("Injection test summary")
    successful = [r for r in results if r["rows_returned"] > 0]
    errored    = [r for r in results if r["error"]]
    clean      = [r for r in results if r["rows_returned"] == 0 and not r["error"]]

    print(f"\n  Total tests   : {len(results)}")
    print(f"  {C.RED}Successful injections : {len(successful)}{C.RESET}")
    print(f"  {C.YELLOW}Errors                : {len(errored)}{C.RESET}")
    print(f"  {C.GREEN}Clean (0 rows)        : {len(clean)}{C.RESET}")

    if successful:
        print(f"\n  {C.BOLD}Successful injections:{C.RESET}")
        for r in successful:
            print(f"    {C.RED}✘{C.RESET}  {r['table']}.{r['column']}  [{r['attack']}]  → {r['rows_returned']} rows")
            print(f"       Payload : {C.DIM}{r['payload']}{C.RESET}")


# ── Step 6: Save report ───────────────────────────────────────────────────────
def save_report(parsed_data: dict, file_name: str, results: list[dict], fmt: str, out_path: str):
    gen = ReportGenerator(parsed_data, file_name=file_name, injection_results=results)
    if fmt == "json":
        content = gen.to_json()
        mode = "w"
    elif fmt == "html":
        content = gen.to_html()
        mode = "w"
    else:
        err(f"Unknown report format '{fmt}'. Use json or html.")
        return

    with open(out_path, mode, encoding="utf-8") as f:
        f.write(content)
    ok(f"Report saved → {out_path}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="SecScan — SQL injection vulnerability scanner (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Scan and show findings only (no injection)
  python cli.py target.cs

  # Run all injection attacks
  python cli.py target.cs --inject

  # Only test specific tables
  python cli.py target.cs --inject --tables Products Orders

  # Only run boolean and union attacks
  python cli.py target.cs --inject --attacks boolean union

  # Save a JSON report
  python cli.py target.cs --inject --report json --output report.json

  # Save an HTML report
  python cli.py target.cs --inject --report html --output report.html

  # Verbose output (show skipped columns too)
  python cli.py target.cs --inject --verbose
        """,
    )

    parser.add_argument("file",
        help="Path to the .cs / .sql / .txt file to scan")
    parser.add_argument("--inject", action="store_true",
        help="Run SQL injection simulations against the built DB")
    parser.add_argument("--tables", nargs="+", metavar="TABLE",
        help="Only test these tables (default: all)")
    parser.add_argument("--attacks", nargs="+",
        choices=["boolean", "union", "error", "time"],
        metavar="ATTACK",
        help="Attack types to run: boolean union error time (default: all)")
    parser.add_argument("--report", choices=["json", "html"],
        metavar="FORMAT",
        help="Save a report in this format")
    parser.add_argument("--output", metavar="FILE",
        help="Output path for the report (default: secscan_report.<fmt>)")
    parser.add_argument("--verbose", "-v", action="store_true",
        help="Show skipped/clean columns in injection output")
    parser.add_argument("--json-dump", action="store_true",
        help="Dump raw parsed data as JSON to stdout and exit")

    args = parser.parse_args()

    file_name   = os.path.basename(args.file)
    parsed_data, sql_blocks = run_parse(args.file)

    if args.json_dump:
        print(json.dumps(parsed_data, indent=2))
        sys.exit(0)

    print_overview(parsed_data, file_name)

    results = []
    if args.inject:
        results = run_injections(
            parsed_data,
            tables_filter  = args.tables,
            attacks_filter = args.attacks,
            verbose        = args.verbose,
        )
        print_summary(results)

    if args.report:
        out = args.output or f"secscan_report.{args.report}"
        save_report(parsed_data, file_name, results, args.report, out)

    header("Done")


if __name__ == "__main__":
    main()
