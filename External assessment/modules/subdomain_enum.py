"""
Module: Subdomain Enumeration
Wraps subfinder, amass, or sublist3r via subprocess.
"""

import subprocess
import re
import tempfile
import os
from utils.banner import section, finding, status

# Subdomains that if found may indicate interesting attack surface
INTERESTING_PATTERNS = [
    ("dev",       "medium", "Development environment exposed"),
    ("staging",   "medium", "Staging environment exposed"),
    ("test",      "medium", "Test environment exposed"),
    ("uat",       "medium", "UAT environment exposed"),
    ("demo",      "low",    "Demo environment found"),
    ("internal",  "high",   "Internal subdomain exposed publicly"),
    ("admin",     "high",   "Admin subdomain found"),
    ("vpn",       "medium", "VPN endpoint found"),
    ("mail",      "info",   "Mail server found"),
    ("ftp",       "medium", "FTP server found"),
    ("jenkins",   "high",   "Jenkins CI found — check auth"),
    ("jira",      "medium", "Jira found"),
    ("confluence",("medium","Confluence found")),
    ("gitlab",    "high",   "GitLab instance found"),
    ("github",    "info",   "GitHub subdomain"),
    ("kibana",    "high",   "Kibana found — check auth"),
    ("grafana",   "medium", "Grafana found — check auth"),
    ("api",       "info",   "API endpoint found"),
    ("backup",    "high",   "Backup subdomain found"),
    ("old",       "medium", "Old/legacy subdomain found"),
    ("legacy",    "medium", "Legacy subdomain found"),
    ("db",        "critical","Database subdomain found"),
    ("database",  "critical","Database subdomain found"),
    ("mysql",     "critical","MySQL subdomain found"),
    ("redis",     "critical","Redis subdomain found"),
]


def _run_subfinder(domain: str, timeout: int) -> tuple[str, list]:
    cmd = ["subfinder", "-d", domain, "-silent", "-all"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 6)
        subs = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        return proc.stdout, subs
    except subprocess.TimeoutExpired:
        return "TIMEOUT", []
    except FileNotFoundError:
        return "NOT_FOUND", []


def _run_amass(domain: str, timeout: int) -> tuple[str, list]:
    cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", str(timeout)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 10)
        subs = [l.strip() for l in proc.stdout.splitlines()
                if l.strip() and domain in l]
        return proc.stdout, subs
    except subprocess.TimeoutExpired:
        return "TIMEOUT", []
    except FileNotFoundError:
        return "NOT_FOUND", []


def _run_sublist3r(domain: str, threads: int, timeout: int) -> tuple[str, list]:
    out_file = tempfile.mktemp(suffix=".txt")
    cmd = ["sublist3r", "-d", domain, "-t", str(threads), "-o", out_file, "-v"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 10)
        subs = []
        if os.path.exists(out_file):
            with open(out_file) as fh:
                subs = [l.strip() for l in fh if l.strip()]
            os.unlink(out_file)
        return proc.stdout, subs
    except subprocess.TimeoutExpired:
        return "TIMEOUT", []
    except FileNotFoundError:
        return "NOT_FOUND", []


def _classify(subdomain: str, base_domain: str) -> tuple[str, str]:
    label = subdomain.replace("." + base_domain, "").lower()
    for pattern, *rest in INTERESTING_PATTERNS:
        if isinstance(rest[0], tuple):
            sev, note = rest[0]
        else:
            sev, note = rest[0], rest[1] if len(rest) > 1 else ""
        if pattern in label:
            return sev, note
    return "info", "Subdomain found"


def run(cfg: dict) -> dict:
    domain    = cfg["domain"]
    tool      = cfg.get("sub_tool", "subfinder")
    threads   = cfg["threads"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]

    if not quiet:
        section(f"Subdomain Enumeration ({tool})", use_color)
        status(f"Target: {domain}", use_color)

    results = {
        "target":     domain,
        "tool":       tool,
        "subdomains": [],
        "findings":   []
    }

    if tool == "subfinder":
        raw, subs = _run_subfinder(domain, timeout)
    elif tool == "amass":
        raw, subs = _run_amass(domain, timeout)
    else:
        raw, subs = _run_sublist3r(domain, threads, timeout)

    if raw == "TIMEOUT":
        results["error"] = "Tool timed out"
        if not quiet:
            finding("medium", "Subdomain enumeration timed out", use_color=use_color)
        return results

    if raw == "NOT_FOUND":
        results["error"] = f"{tool} not installed"
        return results

    # De-duplicate and sort
    subs = sorted(set(s.lower().strip() for s in subs if domain in s))
    results["subdomains"] = subs

    if not quiet:
        status(f"Found {len(subs)} subdomain(s)", use_color)

    for sub in subs:
        severity, note = _classify(sub, domain)
        f = {
            "type":     "subdomain",
            "subdomain": sub,
            "severity": severity,
            "message":  sub,
            "note":     note
        }
        results["findings"].append(f)
        if not quiet:
            finding(severity, sub, note if note != "Subdomain found" else "", use_color)

    if not subs and not quiet:
        finding("info", "No subdomains found (passive scan only)", use_color=use_color)

    return results
