# report.py — SecScan vulnerability report generator

import json
from datetime import datetime
from typing import Optional


class ReportGenerator:
    """
    Generates vulnerability reports from scan results.
    Supports JSON and HTML output formats.
    """

    SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    def __init__(self, parsed_data: dict, file_name: str = "unknown.cs",
                 injection_results: Optional[list] = None):
        self.parsed_data = parsed_data
        self.file_name = file_name
        self.findings = parsed_data.get("findings", [])
        self.injection_results = injection_results or []
        self.generated_at = datetime.now().isoformat(timespec="seconds")

        # Sort findings by severity
        self.findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "LOW"), 99)
        )

    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        high   = [f for f in self.findings if f["severity"] == "HIGH"]
        medium = [f for f in self.findings if f["severity"] == "MEDIUM"]
        low    = [f for f in self.findings if f["severity"] == "LOW"]

        return {
            "meta": {
                "tool": "SecScan",
                "version": "2.0",
                "file": self.file_name,
                "generated_at": self.generated_at,
                "db_type": self.parsed_data.get("db_type", "unknown"),
            },
            "summary": {
                "total_findings": len(self.findings),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "tables_scanned": len(self.parsed_data.get("columns", {})),
                "joins_detected": len(self.parsed_data.get("joins", [])),
                "safe_columns": sum(len(v) for v in self.parsed_data.get("safe_columns", {}).values()),
                "vulnerable_columns": sum(len(v) for v in self.parsed_data.get("vulnerable_columns", {}).values()),
            },
            "findings": self.findings,
            "injection_tests": self.injection_results,
            "schema": {
                "tables": list(self.parsed_data.get("columns", {}).keys()),
                "joins": self.parsed_data.get("joins", []),
            }
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_html(self) -> str:
        data = self.to_dict()
        s = data["summary"]
        findings = data["findings"]
        inj = data["injection_tests"]

        severity_color = {"HIGH": "#c0392b", "MEDIUM": "#e67e22", "LOW": "#2980b9"}
        severity_bg    = {"HIGH": "#fdecea", "MEDIUM": "#fef9ec", "LOW": "#eaf4fb"}

        findings_html = ""
        for f in findings:
            sev = f["severity"]
            col_display = f['column'] if f['column'] else "—"
            findings_html += f"""
            <div class="finding" style="border-left:4px solid {severity_color.get(sev,'#888')};
                 background:{severity_bg.get(sev,'#f9f9f9')};padding:12px 16px;margin:10px 0;border-radius:4px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <strong style="color:{severity_color.get(sev,'#333')}">[{sev}] {f['vuln_type'].replace('_',' ').title()}</strong>
                <span style="font-size:12px;color:#666">Line {f['line_number']} — {f['file_name']}</span>
              </div>
              <div style="font-size:13px;margin-bottom:4px;">
                <strong>Table:</strong> {f['table']} &nbsp;|&nbsp; <strong>Column:</strong> {col_display}
              </div>
              <div style="font-size:13px;margin-bottom:6px;color:#333">{f['description']}</div>
              <code style="display:block;background:#f4f4f4;padding:6px 10px;border-radius:3px;font-size:12px;
                    white-space:pre-wrap;word-break:break-all;">{self._escape(f['code_snippet'])}</code>
              <div style="margin-top:8px;font-size:12px;color:#27ae60">
                <strong>Fix:</strong> {f['recommendation']}
              </div>
            </div>"""

        inj_html = ""
        for r in inj:
            status = "PASSED" if r.get("rows_returned", 0) > 0 else "NO DATA"
            status_color = "#c0392b" if status == "PASSED" else "#7f8c8d"
            inj_html += f"""
            <tr>
              <td>{r.get('table','')}</td>
              <td>{r.get('column','')}</td>
              <td><code>{self._escape(str(r.get('attack','')))} </code></td>
              <td><code style="font-size:11px">{self._escape(str(r.get('payload','')))}</code></td>
              <td style="color:{status_color};font-weight:bold">{status} ({r.get('rows_returned',0)} rows)</td>
            </tr>"""

        tables_html = "".join(
            f"<li><code>{t}</code> ({len(cols)} columns)</li>"
            for t, cols in self.parsed_data.get("columns", {}).items()
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecScan Report — {self._escape(self.file_name)}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:960px;
        margin:0 auto;padding:24px;color:#222;background:#fafafa;}}
  h1{{color:#1a1a2e;border-bottom:3px solid #c0392b;padding-bottom:8px;}}
  h2{{color:#2c3e50;margin-top:32px;}}
  .summary-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0;}}
  .metric{{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:14px;text-align:center;}}
  .metric .num{{font-size:28px;font-weight:700;}}
  .metric .label{{font-size:12px;color:#666;margin-top:2px;}}
  .high{{color:#c0392b;}}.medium{{color:#e67e22;}}.low{{color:#2980b9;}}.ok{{color:#27ae60;}}
  table{{width:100%;border-collapse:collapse;font-size:13px;background:#fff;}}
  th{{background:#2c3e50;color:#fff;padding:8px 10px;text-align:left;}}
  td{{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top;}}
  tr:hover td{{background:#f5f5f5;}}
  code{{font-family:'Consolas','Monaco',monospace;}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;}}
  .badge-high{{background:#fdecea;color:#c0392b;}}
  .badge-ok{{background:#e8f8f0;color:#27ae60;}}
  footer{{margin-top:40px;font-size:12px;color:#aaa;border-top:1px solid #eee;padding-top:12px;}}
</style>
</head>
<body>
<h1>🔍 SecScan Vulnerability Report</h1>
<p style="color:#666;font-size:14px;">
  File: <strong>{self._escape(self.file_name)}</strong> &nbsp;|&nbsp;
  DB Type: <strong>{data['meta']['db_type'].upper()}</strong> &nbsp;|&nbsp;
  Generated: {self.generated_at}
</p>

<h2>Summary</h2>
<div class="summary-grid">
  <div class="metric"><div class="num {'high' if s['high'] > 0 else 'ok'}">{s['high']}</div><div class="label">HIGH findings</div></div>
  <div class="metric"><div class="num {'medium' if s['medium'] > 0 else 'ok'}">{s['medium']}</div><div class="label">MEDIUM findings</div></div>
  <div class="metric"><div class="num ok">{s['safe_columns']}</div><div class="label">Safe columns</div></div>
  <div class="metric"><div class="num {'high' if s['vulnerable_columns'] > 0 else 'ok'}">{s['vulnerable_columns']}</div><div class="label">Vulnerable columns</div></div>
</div>
<p>Tables scanned: <strong>{s['tables_scanned']}</strong> &nbsp;|&nbsp;
   Joins detected: <strong>{s['joins_detected']}</strong> &nbsp;|&nbsp;
   Total injection tests: <strong>{len(inj)}</strong></p>

<h2>Vulnerability Findings ({s['total_findings']})</h2>
{findings_html if findings_html else '<p style="color:#27ae60">✓ No static vulnerabilities detected.</p>'}

<h2>Injection Test Results</h2>
{"<table><thead><tr><th>Table</th><th>Column</th><th>Attack</th><th>Payload</th><th>Result</th></tr></thead><tbody>" + inj_html + "</tbody></table>" if inj_html else '<p style="color:#888">No injection tests run.</p>'}

<h2>Schema Detected</h2>
<ul>{tables_html}</ul>

<h2>Joins / Foreign Keys</h2>
{"<ul>" + "".join(f"<li><code>{j[0]}.{j[1]}</code> → <code>{j[2]}.{j[3]}</code></li>" for j in data['schema']['joins']) + "</ul>" if data['schema']['joins'] else '<p style="color:#888">No joins detected.</p>'}

<footer>SecScan v2.0 — Educational SQL Injection Simulation Tool</footer>
</body>
</html>"""

    @staticmethod
    def _escape(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
