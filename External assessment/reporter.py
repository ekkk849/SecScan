"""
Reporter: Terminal summary table and JSON file output
"""

import json
import datetime
from utils.banner import (
    section, finding, status,
    BOLD, RESET, RED, GREEN, YELLOW, CYAN, WHITE, DIM,
    SEVERITY_COLOR, SEVERITY_ICON
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "pass"]


def _count_severities(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _all_findings(results: dict) -> list:
    all_f = []
    for module, data in results.items():
        if not isinstance(data, dict):
            continue
        # Top-level findings list
        for f in data.get("findings", []):
            all_f.append({**f, "_module": module})
        # Nested (email has sub-dicts)
        for key in ("spf", "dkim", "dmarc"):
            if key in data and isinstance(data[key], dict):
                for f in data[key].get("findings", []):
                    all_f.append({**f, "_module": f"{module}.{key}"})
    return all_f


def print_summary(results: dict, cfg: dict):
    use_color = cfg.get("use_color", True)
    quiet     = cfg.get("quiet", False)

    all_f = _all_findings(results)
    counts = _count_severities(all_f)

    section("SCAN SUMMARY", use_color)

    # Per-module status
    module_labels = {
        "http_headers":  "HTTP Headers",
        "tls":           "TLS / SSL",
        "email_security":"Email Security",
        "sri":           "SRI Checks",
        "ports":         "Port Scan",
        "directories":   "Dir Enumeration",
        "subdomains":    "Subdomain Enum",
    }

    for key, label in module_labels.items():
        if key not in results:
            continue
        data = results[key]
        if "error" in data:
            if use_color:
                print(f"  {YELLOW}  ✗  {label:<22}{RESET} error: {data['error'][:60]}")
            else:
                print(f"    ✗  {label:<22} error: {data['error'][:60]}")
        else:
            # Count issues in this module
            mod_findings = []
            for f in data.get("findings", []):
                mod_findings.append(f)
            for sub in ("spf", "dkim", "dmarc"):
                if sub in data:
                    mod_findings.extend(data[sub].get("findings", []))

            worst = "pass"
            for sev in ["critical", "high", "medium", "low"]:
                if any(f.get("severity") == sev for f in mod_findings):
                    worst = sev
                    break

            icon = SEVERITY_ICON.get(worst, "[    ]")
            if use_color:
                col = SEVERITY_COLOR.get(worst, GREEN)
                non_pass = sum(1 for f in mod_findings if f.get("severity") not in ("pass", "info"))
                print(f"  {col}{icon}{RESET} {label:<22} — {non_pass} issue(s)")
            else:
                non_pass = sum(1 for f in mod_findings if f.get("severity") not in ("pass", "info"))
                print(f"  {icon} {label:<22} — {non_pass} issue(s)")

    # Overall severity breakdown
    print()
    if use_color:
        print(f"  {BOLD}{WHITE}Findings by severity:{RESET}")
    else:
        print("  Findings by severity:")

    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        if n == 0:
            continue
        icon = SEVERITY_ICON.get(sev, "")
        if use_color:
            col = SEVERITY_COLOR.get(sev, WHITE)
            print(f"    {col}{icon} {n:>4}  {sev.upper()}{RESET}")
        else:
            print(f"    {icon} {n:>4}  {sev.upper()}")

    # Risk score (simple)
    score = (
        counts.get("critical", 0) * 10 +
        counts.get("high", 0) * 5 +
        counts.get("medium", 0) * 2 +
        counts.get("low", 0) * 1
    )
    if use_color:
        col = RED if score >= 20 else YELLOW if score >= 5 else GREEN
        print(f"\n  {col}{BOLD}Risk Score: {score}{RESET}  "
              f"{DIM}(critical×10 + high×5 + medium×2 + low×1){RESET}")
    else:
        print(f"\n  Risk Score: {score}  (critical×10 + high×5 + medium×2 + low×1)")

    # Top issues
    critical_high = [f for f in all_f if f.get("severity") in ("critical", "high")]
    if critical_high:
        print()
        if use_color:
            print(f"  {RED}{BOLD}Critical / High priority issues:{RESET}")
        else:
            print("  Critical / High priority issues:")
        for f in critical_high[:10]:
            rem = f.get("remediation", "")
            finding(f["severity"], f["message"], rem[:80] if rem else "", use_color)


def save_json(results: dict, output_path: str, cfg: dict):
    all_f = _all_findings(results)
    report = {
        "meta": {
            "tool":      "SecScan",
            "version":   "1.0.0",
            "target":    cfg.get("domain"),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        },
        "summary": {
            "counts":     _count_severities(all_f),
            "risk_score": (
                _count_severities(all_f).get("critical", 0) * 10 +
                _count_severities(all_f).get("high", 0) * 5 +
                _count_severities(all_f).get("medium", 0) * 2 +
                _count_severities(all_f).get("low", 0) * 1
            ),
            "total_findings": len(all_f),
        },
        "modules": results
    }

    # Strip raw nmap output to keep JSON clean (it's large)
    if "ports" in report["modules"] and "raw_output" in report["modules"]["ports"]:
        del report["modules"]["ports"]["raw_output"]

    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
