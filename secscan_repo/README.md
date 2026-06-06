# SecScan — SQL Injection Detection Tool

A lightweight, locally-run security analysis tool that detects SQL injection vulnerabilities in C# source files using a hybrid static analysis + sandboxed dynamic simulation approach.

## How it works

1. **Parse** — `parser.py` scans the C# file for SQL queries built via string concatenation, interpolation, or `String.Format()`. It extracts the table/column schema using per-method alias resolution.
2. **Build** — `db_builder.py` reconstructs the database schema from the parsed SQL and populates a local SQLite database with 25 rows of synthetic data. No real data is ever used.
3. **Inject** — `injector.py` runs boolean, UNION, error-based, and time-based payloads against the synthetic database to confirm exploitability.
4. **Report** — `report.py` produces a JSON or HTML report with findings, severity levels, and remediation guidance.

## Interfaces

### Web app (Flask)
```bash
pip install flask
python app.py
# Open http://localhost:5000
```

### CLI
```bash
# Scan and show findings only
python cli.py target.cs

# Run injection simulation too
python cli.py target.cs --inject

# Save a JSON report
python cli.py target.cs --inject --report json --output report.json

# Save an HTML report
python cli.py target.cs --inject --report html --output report.html

# Filter to specific tables or attack types
python cli.py target.cs --inject --tables Products Orders --attacks boolean union

# Verbose (show skipped columns too)
python cli.py target.cs --inject --verbose
```

## Requirements

- Python 3.10+
- Flask (web interface only): `pip install flask`
- No other dependencies — uses Python standard library only

## File structure

```
secscan/
├── parser.py          # SQLParser — static analysis engine
├── db_builder.py      # DBBuilder — schema reconstruction + synthetic data
├── injector.py        # SmartInjector — payload execution
├── report.py          # ReportGenerator — JSON/HTML output
├── cli.py             # Command-line interface
├── app.py             # Flask web interface
├── templates/         # Flask HTML templates
├── examples/
│   └── test_ecommerce.cs   # Sample C# file with mixed safe and vulnerable methods
└── evaluation/
    ├── corpus/        # 20 synthetic C# test files (4 categories)
    ├── figures/       # Evaluation result charts
    ├── ground_truth.json   # Method-level ground truth labels
    └── run_evaluation.sh   # Script to run all 20 files and collect results
```

## Evaluation corpus

The `evaluation/corpus/` folder contains 20 synthetic C# files used to evaluate the tool, organised into four categories:

| Category | Files | Purpose |
|---|---|---|
| Clearly vulnerable | `vuln_01` – `vuln_05` | Baseline recall — all methods injectable |
| Clearly safe | `safe_01` – `safe_04` | FP rate — all methods parameterised |
| Mixed | `mixed_01` – `mixed_05` | Realistic files with both safe and vulnerable methods |
| Edge cases | `edge_01` – `edge_06` | Known limitations: StringBuilder, string.Concat(), multiline literals, large schemas |

### Running the evaluation

```bash
cd evaluation
chmod +x run_evaluation.sh
./run_evaluation.sh
# Results saved to evaluation/results/ as JSON files
```

## Known limitations

- **C# only** — currently supports `.cs` files. Java, Python, PHP are not yet handled.
- **StringBuilder blind spot** — SQL built with `StringBuilder.Append()` is not detected.
- **`string.Concat()` blind spot** — the static method form is not detected (only the `+` operator is matched).
- **Simulation SQLite/SQL Server mismatch** — when the source file targets SQL Server, UNION/error/time payloads use SQL Server syntax which SQLite cannot execute. Boolean injection still works correctly.
- **Anchor method requirement** — the parser requires at least one parameterised method in the file to correctly attribute table/column names to findings.

## Vulnerability types detected

| Type | Example pattern | Severity |
|---|---|---|
| String concatenation | `"WHERE id = '" + userInput + "'"` | HIGH |
| String interpolation | `$"WHERE id = '{userInput}'"` | HIGH |
| String.Format | `String.Format("WHERE id = '{0}'", userInput)` | HIGH |
| Integer injection | `"WHERE id = " + userId` | HIGH |
| LIKE injection | `"WHERE name LIKE '%" + search + "%'"` | HIGH |
| ORDER BY injection | `"ORDER BY " + sortColumn` | HIGH |
| No parameterisation | SQL method with no `@param` usage | MEDIUM |
