#!/bin/bash
# run_evaluation.sh
# Run all 20 corpus files through SecScan and save JSON reports
#
# HOW TO USE:
#   1. Copy this script and all .cs files into your SecScan folder
#      (same directory as cli.py, parser.py, db_builder.py, injector.py, report.py)
#   2. chmod +x run_evaluation.sh
#   3. ./run_evaluation.sh
#   4. Results saved to ./results/ as JSON files
#
# Requirements: Python 3.10+, Flask (for web), standard library only for CLI

RESULTS_DIR="./results"
mkdir -p "$RESULTS_DIR"

CS_FILES=(
    "vuln_01_concat_healthcare.cs"
    "vuln_02_interpolation_banking.cs"
    "vuln_03_format_orderby_hr.cs"
    "vuln_04_integer_injection.cs"
    "vuln_05_like_injection.cs"
    "safe_01_ecommerce_params.cs"
    "safe_02_hospital_transactions.cs"
    "safe_03_stored_procedures.cs"
    "safe_04_sqlparameter_array.cs"
    "mixed_01_school_highvuln.cs"
    "mixed_02_hotel_balanced.cs"
    "mixed_03_library_lowvuln.cs"
    "mixed_04_column_level.cs"
    "mixed_05_nested_alias.cs"
    "edge_01_multiline_literal_fp.cs"
    "edge_02_stringbuilder_blindspot.cs"
    "edge_03_string_concat_method.cs"
    "edge_04_large_schema.cs"
    "edge_05_alias_confusion.cs"
    "edge_06_partial_stringbuilder.cs"
)

PASS=0
FAIL=0

echo "============================================"
echo " SecScan Evaluation Run"
echo " $(date)"
echo "============================================"
echo ""

for FILE in "${CS_FILES[@]}"; do
    STEM="${FILE%.cs}"
    OUTPUT="$RESULTS_DIR/${STEM}_result.json"

    echo -n "Running: $FILE ... "

    python cli.py "$FILE" \
        --inject \
        --report json \
        --output "$OUTPUT" \
        2>/dev/null

    if [ $? -eq 0 ] && [ -f "$OUTPUT" ]; then
        # Quick check: count findings from JSON
        FINDINGS=$(python -c "import json; d=json.load(open('$OUTPUT')); print(d['summary']['total_findings'])" 2>/dev/null)
        TESTS=$(python -c "import json; d=json.load(open('$OUTPUT')); print(len(d['injection_tests']))" 2>/dev/null)
        SUCCESSES=$(python -c "import json; d=json.load(open('$OUTPUT')); print(sum(1 for t in d['injection_tests'] if t.get('rows_returned',0)>0))" 2>/dev/null)
        echo "OK  | findings=$FINDINGS | injection_tests=$TESTS | injections_succeeded=$SUCCESSES"
        PASS=$((PASS + 1))
    else
        echo "FAILED"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "============================================"
echo " Done: $PASS passed, $FAIL failed"
echo " Results in: $RESULTS_DIR/"
echo "============================================"
