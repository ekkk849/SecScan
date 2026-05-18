"""
Module: Directory / Path Enumeration
Wraps dirsearch, gobuster, or feroxbuster via subprocess.
"""

import subprocess
import os
import re
import tempfile
from utils.banner import section, finding, status

# Paths that if found indicate likely misconfigurations
SENSITIVE_PATHS = {
    ".git":           ("critical", "Git repository exposed — source code leak"),
    ".env":           ("critical", ".env file exposed — credentials likely present"),
    ".htpasswd":      ("critical", "htpasswd file exposed"),
    "wp-config.php":  ("critical", "WordPress config exposed"),
    "config.php":     ("high",     "PHP config file exposed"),
    "web.config":     ("high",     "IIS web.config exposed"),
    "phpinfo.php":    ("high",     "phpinfo() page exposed"),
    "phpinfo":        ("high",     "phpinfo() page exposed"),
    "backup":         ("high",     "Backup directory found"),
    "backup.zip":     ("critical", "Backup archive exposed"),
    "backup.sql":     ("critical", "SQL dump exposed"),
    "admin":          ("medium",   "Admin panel found"),
    "administrator":  ("medium",   "Admin panel found"),
    "login":          ("info",     "Login page found"),
    "phpmyadmin":     ("high",     "phpMyAdmin exposed"),
    "adminer":        ("high",     "Adminer DB UI exposed"),
    "swagger":        ("medium",   "Swagger API docs exposed"),
    "swagger-ui":     ("medium",   "Swagger UI exposed"),
    "api-docs":       ("medium",   "API docs exposed"),
    ".DS_Store":      ("medium",   ".DS_Store file exposed — directory structure leak"),
    "server-status":  ("medium",   "Apache server-status exposed"),
    "server-info":    ("medium",   "Apache server-info exposed"),
    "robots.txt":     ("info",     "robots.txt found — review for hidden paths"),
    "sitemap.xml":    ("info",     "sitemap.xml found"),
    "crossdomain.xml":("low",      "crossdomain.xml found — check Flash policy"),
    "elmah.axd":      ("high",     "ELMAH error log exposed"),
    "trace.axd":      ("high",     "ASP.NET trace exposed"),
    ".svn":           ("critical", "SVN repository exposed"),
    ".hg":            ("critical", "Mercurial repository exposed"),
}


def _run_dirsearch(base_url: str, wordlist: str, threads: int, timeout: int) -> tuple[str, list]:
    out_file = tempfile.mktemp(suffix=".txt")
    cmd = [
        "dirsearch",
        "-u", base_url,
        "-w", wordlist,
        "-t", str(threads),
        "--format", "plain",
        "-o", out_file,
        "--silent",
        "-x", "404,429,500,503",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        raw = proc.stdout + proc.stderr
        results = []
        # Read output file if it exists
        if os.path.exists(out_file):
            with open(out_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        results.append(line)
            os.unlink(out_file)
        # Also parse stdout
        for line in raw.splitlines():
            m = re.search(r"\[(\d{3})\]\s+(\d+)[^/]*(/.+)", line)
            if m:
                results.append(f"{m.group(1)} {m.group(3)}")
        return raw, results
    except subprocess.TimeoutExpired:
        return "TIMEOUT", []
    except FileNotFoundError:
        return "NOT_FOUND", []


def _run_gobuster(base_url: str, wordlist: str, threads: int, timeout: int) -> tuple[str, list]:
    cmd = [
        "gobuster", "dir",
        "-u", base_url,
        "-w", wordlist,
        "-t", str(threads),
        "-q",
        "--no-progress",
        "-o", "/dev/stdout",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        raw = proc.stdout
        results = []
        for line in raw.splitlines():
            # gobuster format: /path (Status: 200) [Size: 1234]
            m = re.match(r"^(/.+?)\s+\(Status:\s*(\d+)\)", line)
            if m:
                results.append(f"{m.group(2)} {m.group(1)}")
        return raw, results
    except subprocess.TimeoutExpired:
        return "TIMEOUT", []
    except FileNotFoundError:
        return "NOT_FOUND", []


def _run_feroxbuster(base_url: str, wordlist: str, threads: int, timeout: int) -> tuple[str, list]:
    cmd = [
        "feroxbuster",
        "--url", base_url,
        "--wordlist", wordlist,
        "--threads", str(threads),
        "--quiet",
        "--no-recursion",
        "--filter-status", "404,429,500,503",
        "--output", "/dev/stdout",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        raw = proc.stdout
        results = []
        for line in raw.splitlines():
            # feroxbuster: 200      GET   ...   https://example.com/path
            m = re.match(r"^(\d{3})\s+\w+\s+.*?(https?://\S+)", line)
            if m:
                from urllib.parse import urlparse
                path = urlparse(m.group(2)).path
                results.append(f"{m.group(1)} {path}")
        return raw, results
    except subprocess.TimeoutExpired:
        return "TIMEOUT", []
    except FileNotFoundError:
        return "NOT_FOUND", []


def _classify(path: str) -> tuple[str, str]:
    """Return (severity, note) for a discovered path."""
    path_lower = path.lower().lstrip("/")
    for key, (sev, note) in SENSITIVE_PATHS.items():
        if key.lower() in path_lower:
            return sev, note
    return "info", "Path accessible"


def run(cfg: dict) -> dict:
    domain    = cfg["domain"]
    base_url  = cfg["base_url"]
    wordlist  = cfg["wordlist"]
    tool      = cfg.get("dir_tool", "dirsearch")
    threads   = cfg["threads"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]

    if not quiet:
        section(f"Directory Enumeration ({tool})", use_color)
        status(f"Target: {base_url}", use_color)
        status(f"Wordlist: {wordlist}", use_color)
        if not os.path.exists(wordlist):
            finding("medium", f"Wordlist not found: {wordlist}",
                    "Try: /usr/share/wordlists/dirb/common.txt", use_color)

    results = {
        "target":   base_url,
        "tool":     tool,
        "wordlist": wordlist,
        "findings": [],
        "paths":    []
    }

    if tool == "dirsearch":
        raw, found = _run_dirsearch(base_url, wordlist, threads, timeout)
    elif tool == "gobuster":
        raw, found = _run_gobuster(base_url, wordlist, threads, timeout)
    else:
        raw, found = _run_feroxbuster(base_url, wordlist, threads, timeout)

    if raw == "TIMEOUT":
        results["error"] = "Tool timed out"
        if not quiet:
            finding("medium", "Directory enumeration timed out", use_color=use_color)
        return results

    if raw == "NOT_FOUND":
        results["error"] = f"{tool} not installed"
        return results

    # De-duplicate
    seen = set()
    for entry in found:
        parts  = entry.split(None, 1)
        if len(parts) < 2:
            continue
        status_code = parts[0]
        path        = parts[1].strip()
        if path in seen:
            continue
        seen.add(path)

        severity, note = _classify(path)
        f = {
            "type":       "path_found",
            "path":       path,
            "status":     status_code,
            "severity":   severity,
            "message":    f"[{status_code}] {path}",
            "note":       note
        }
        results["findings"].append(f)
        results["paths"].append(path)

        if not quiet:
            finding(severity, f"[{status_code}] {path}", note, use_color)

    if not results["paths"] and not quiet:
        finding("info", "No paths found (try a larger wordlist)", use_color=use_color)

    return results
