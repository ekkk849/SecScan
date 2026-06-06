# Evaluation Corpus

This folder contains the 20 synthetic C# source files and supporting materials used to evaluate SecScan's SQL injection detection module.

## Running the evaluation

Copy all `.cs` files and `run_evaluation.sh` into the SecScan root directory (alongside `cli.py`), then:

```bash
chmod +x run_evaluation.sh
./run_evaluation.sh
```

Results will be saved to `./results/` as one JSON file per test file.

## Corpus categories

### Clearly vulnerable (5 files)
All methods in these files contain a SQL injection vulnerability. Each file tests a distinct injection pattern.

| File | Pattern tested |
|---|---|
| `vuln_01_concat_healthcare.cs` | String concatenation (`+` operator) |
| `vuln_02_interpolation_banking.cs` | C# string interpolation (`$"..."`) |
| `vuln_03_format_orderby_hr.cs` | `String.Format()` + ORDER BY injection |
| `vuln_04_integer_injection.cs` | Integer parameter concatenation (no quotes) |
| `vuln_05_like_injection.cs` | `LIKE '%' + input + '%'` pattern |

### Clearly safe (4 files)
All methods use parameterised queries. Expected result: zero findings.

| File | Safe pattern tested |
|---|---|
| `safe_01_ecommerce_params.cs` | `Parameters.AddWithValue()` |
| `safe_02_hospital_transactions.cs` | Transactions + `SqlParameter` objects |
| `safe_03_stored_procedures.cs` | `CommandType.StoredProcedure` |
| `safe_04_sqlparameter_array.cs` | `Parameters.AddRange(new SqlParameter[]{...})` |

### Mixed (5 files)
Files with both safe and vulnerable methods at different ratios.

| File | Ratio | Domain |
|---|---|---|
| `mixed_01_school_highvuln.cs` | 4 vuln / 1 safe | School management |
| `mixed_02_hotel_balanced.cs` | 3 vuln / 3 safe | Hotel booking |
| `mixed_03_library_lowvuln.cs` | 1 vuln / 4 safe | Library system |
| `mixed_04_column_level.cs` | 3 vuln / 2 safe | Pharma supply chain |
| `mixed_05_nested_alias.cs` | 3 vuln / 3 safe | Property management |

### Edge cases (6 files)
Files designed to probe known limitations and boundary conditions.

| File | Edge case tested |
|---|---|
| `edge_01_multiline_literal_fp.cs` | Multi-line literal concat (expected FP) + safe/vuln column conflict |
| `edge_02_stringbuilder_blindspot.cs` | `StringBuilder.Append()` (expected FN — known blind spot) |
| `edge_03_string_concat_method.cs` | `string.Concat()` static method (expected FN — known blind spot) |
| `edge_04_large_schema.cs` | 12-table schema with deep JOIN chains |
| `edge_05_alias_confusion.cs` | C# variable names that resemble SQL aliases |
| `edge_06_partial_stringbuilder.cs` | Mix of standard concat + StringBuilder in same file |

## Ground truth

`ground_truth.json` contains method-level labels for every method in every file, including:
- `status`: `VULNERABLE` or `SAFE`
- `type`: vulnerability pattern type
- `inject_params`: the parameter names that are the injection points
- `edge_note`: for edge case files, what specific behaviour is expected
