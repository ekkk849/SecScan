"""
Module: Directory / Path Enumeration
Wraps dirsearch, gobuster, or feroxbuster via subprocess.

Improvements over previous version:
  - Correct CLI flags for each tool (the old --silent / -x usage was broken for dirsearch).
  - JSON output parsing where supported (dirsearch, feroxbuster) instead of brittle regex.
  - Tech-aware extension fuzzing (auto-detect from headers / homepage and pick extensions).
  - Auto wordlist selection based on detected stack (PHP, ASP.NET, Java, Node, generic).
  - Optional vhost (subdomain via Host header) enumeration with ffuf or gobuster vhost.
  - Recursion on directory hits (configurable depth).
  - Word-boundary path classification so "/login-history" doesn't match "login".
  - User-supplied timeout actually honoured.
  - Follow redirects and consider 200/204/301/302/307/401/403 as "interesting" by default.
  - Per-tool capability gating: if a feature isn't supported by the chosen backend,
    we still run, just without that feature, and log a warning.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from utils.banner import section, finding, status, warn

# ---------------------------------------------------------------------------
# Sensitive path classification
# ---------------------------------------------------------------------------
# Each rule: (regex pattern, severity, note)
# Patterns are anchored to path segments to avoid substring false positives.
# We compile them once at import time.
SENSITIVE_RULES: list[tuple[re.Pattern, str, str]] = [
    # Source control exposure --------------------------------------------------
    (re.compile(r"(?:^|/)\.git(?:/|$)"),         "critical", "Git repository exposed — source code leak"),
    (re.compile(r"(?:^|/)\.svn(?:/|$)"),         "critical", "SVN repository exposed"),
    (re.compile(r"(?:^|/)\.hg(?:/|$)"),          "critical", "Mercurial repository exposed"),
    (re.compile(r"(?:^|/)\.bzr(?:/|$)"),         "critical", "Bazaar repository exposed"),
    (re.compile(r"(?:^|/)CVS(?:/|$)"),           "high",     "CVS metadata exposed"),

    # Secrets / config ---------------------------------------------------------
    (re.compile(r"(?:^|/)\.env(?:\..+)?$"),      "critical", ".env file exposed — credentials likely present"),
    (re.compile(r"(?:^|/)\.htpasswd$"),          "critical", "htpasswd file exposed"),
    (re.compile(r"(?:^|/)\.htaccess$"),          "medium",   ".htaccess exposed — review for secrets"),
    (re.compile(r"(?:^|/)wp-config\.php(?:\..+)?$"), "critical", "WordPress config exposed"),
    (re.compile(r"(?:^|/)config\.(?:php|inc|json|yml|yaml|xml)$"), "high", "Application config file exposed"),
    (re.compile(r"(?:^|/)web\.config$"),         "high",     "IIS web.config exposed"),
    (re.compile(r"(?:^|/)appsettings(?:\.\w+)?\.json$"), "high", "ASP.NET appsettings exposed"),
    (re.compile(r"(?:^|/)credentials?(?:\.\w+)?$"), "critical", "Credentials file exposed"),
    (re.compile(r"(?:^|/)secrets?(?:\.\w+)?$"),  "critical", "Secrets file exposed"),
    (re.compile(r"(?:^|/)id_rsa(?:\.pub)?$"),    "critical", "SSH private key exposed"),

    # Debug / info disclosure --------------------------------------------------
    (re.compile(r"(?:^|/)phpinfo(?:\.php)?$"),   "high",     "phpinfo() page exposed"),
    (re.compile(r"(?:^|/)server-status$"),       "medium",   "Apache server-status exposed"),
    (re.compile(r"(?:^|/)server-info$"),         "medium",   "Apache server-info exposed"),
    (re.compile(r"(?:^|/)elmah\.axd$"),          "high",     "ELMAH error log exposed"),
    (re.compile(r"(?:^|/)trace\.axd$"),          "high",     "ASP.NET trace exposed"),
    (re.compile(r"(?:^|/)actuator(?:/|$)"),      "high",     "Spring Boot actuator exposed"),
    (re.compile(r"(?:^|/)debug(?:/|$)"),         "medium",   "Debug endpoint exposed"),
    (re.compile(r"(?:^|/)\.DS_Store$"),          "medium",   ".DS_Store file exposed — directory structure leak"),

    # Backups / dumps ----------------------------------------------------------
    (re.compile(r"(?:^|/)backups?(?:/|$)"),      "high",     "Backup directory found"),
    (re.compile(r"\.(?:bak|old|orig|backup|save|swp|swo|tmp)$"), "high", "Backup/temp file exposed"),
    (re.compile(r"\.(?:zip|tar|tar\.gz|tgz|7z|rar|sql|sql\.gz|dump)$"), "critical", "Archive/dump exposed"),

    # Admin panels -------------------------------------------------------------
    (re.compile(r"(?:^|/)(?:admin|administrator)(?:/|$)"), "medium", "Admin panel found"),
    (re.compile(r"(?:^|/)wp-admin(?:/|$)"),      "medium",   "WordPress admin found"),
    (re.compile(r"(?:^|/)phpmyadmin(?:/|$)"),    "high",     "phpMyAdmin exposed"),
    (re.compile(r"(?:^|/)adminer(?:\.php)?$"),   "high",     "Adminer DB UI exposed"),
    (re.compile(r"(?:^|/)manager(?:/html)?$"),   "high",     "Tomcat manager exposed"),

    # API docs -----------------------------------------------------------------
    (re.compile(r"(?:^|/)swagger(?:-ui)?(?:/|\.\w+|$)"), "medium", "Swagger/OpenAPI docs exposed"),
    (re.compile(r"(?:^|/)api[-_]docs?(?:/|$)"),  "medium",   "API docs exposed"),
    (re.compile(r"(?:^|/)graphql(?:/|$)"),       "medium",   "GraphQL endpoint exposed — check introspection"),
    (re.compile(r"(?:^|/)\.well-known(?:/|$)"),  "info",     ".well-known directory present"),

    # Misc ---------------------------------------------------------------------
    (re.compile(r"(?:^|/)login(?:\.\w+)?$"),     "info",     "Login page found"),
    (re.compile(r"(?:^|/)robots\.txt$"),         "info",     "robots.txt — review for hidden paths"),
    (re.compile(r"(?:^|/)sitemap\.xml$"),        "info",     "sitemap.xml found"),
    (re.compile(r"(?:^|/)crossdomain\.xml$"),    "low",      "crossdomain.xml — check Flash policy"),
    (re.compile(r"(?:^|/)clientaccesspolicy\.xml$"), "low",  "Silverlight policy file"),
]


# ---------------------------------------------------------------------------
# Tech-aware fuzzing
# ---------------------------------------------------------------------------
TECH_EXTENSIONS: dict[str, list[str]] = {
    "php":    ["php", "php3", "php4", "php5", "phtml", "phps", "inc"],
    "asp":    ["asp", "aspx", "ashx", "asmx", "axd", "config"],
    "java":   ["jsp", "jspx", "do", "action", "war", "jar"],
    "node":   ["js", "mjs", "json", "map"],
    "python": ["py", "wsgi", "pyc"],
    "ruby":   ["rb", "erb"],
    "generic":["html", "htm", "txt", "xml", "json", "yml", "yaml", "bak", "old", "zip", "tar.gz", "sql"],
}

TECH_WORDLISTS: dict[str, list[str]] = {
    # Preferred order — first one that exists wins.
    "php":     ["/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
                "/usr/share/wordlists/dirb/common.txt"],
    "asp":     ["/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"],
    "java":    ["/usr/share/seclists/Discovery/Web-Content/Java.fuzz.txt",
                "/usr/share/seclists/Discovery/Web-Content/tomcat.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"],
    "node":    ["/usr/share/seclists/Discovery/Web-Content/nodejs.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"],
    "python":  ["/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"],
    "generic": ["/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/common.txt"],
}


def _detect_tech(base_url: str, timeout: int) -> str:
    """Best-effort technology detection from HTTP headers and homepage HTML.

    Returns one of TECH_EXTENSIONS keys. Falls back to 'generic'.
    Uses curl since requests may not be importable in all environments;
    fail-open to 'generic' on any error.
    """
    try:
        proc = subprocess.run(
            ["curl", "-skI", "--max-time", str(min(timeout, 10)), base_url],
            capture_output=True, text=True, timeout=min(timeout, 15),
        )
        headers = (proc.stdout + proc.stderr).lower()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "generic"

    # Strong signals from headers first
    if "x-powered-by: php" in headers or "php" in headers.split("server:", 1)[-1][:200]:
        return "php"
    if "x-powered-by: asp.net" in headers or "x-aspnet-version" in headers:
        return "asp"
    if "x-powered-by: express" in headers or "x-powered-by: next.js" in headers:
        return "node"
    if "tomcat" in headers or "jetty" in headers or "jboss" in headers or "x-powered-by: jsp" in headers:
        return "java"
    if "werkzeug" in headers or "gunicorn" in headers or "wsgi" in headers:
        return "python"

    # Fall back to body sniffing
    try:
        proc = subprocess.run(
            ["curl", "-sk", "--max-time", str(min(timeout, 10)), base_url],
            capture_output=True, text=True, timeout=min(timeout, 15),
        )
        body = proc.stdout.lower()[:8192]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "generic"

    if "wp-content" in body or "wp-includes" in body:
        return "php"
    if "__viewstate" in body or ".aspx" in body:
        return "asp"
    if "/jsessionid" in body or ".jsp" in body:
        return "java"
    return "generic"


def _pick_wordlist(user_supplied: str, tech: str) -> str:
    """User-supplied wordlist wins if it exists. Otherwise pick the first
    available wordlist for the detected tech."""
    if user_supplied and os.path.exists(user_supplied):
        return user_supplied
    for candidate in TECH_WORDLISTS.get(tech, []) + TECH_WORDLISTS["generic"]:
        if os.path.exists(candidate):
            return candidate
    # Last resort: return whatever the user said even if it doesn't exist,
    # so the error is visible upstream.
    return user_supplied


# ---------------------------------------------------------------------------
# Backend runners
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    raw: str = ""
    findings: list[dict] = field(default_factory=list)
    error: Optional[str] = None


# dirsearch plain-line format: "[HH:MM:SS] STATUS - SIZE - /path"
_DIRSEARCH_PLAIN = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+(?P<status>\d{3})\s+-\s+(?P<size>\S+)\s+-\s+(?P<path>\S+)"
)


def _run_dirsearch(
    base_url: str,
    wordlist: str,
    extensions: list[str],
    threads: int,
    timeout: int,
    recursive: bool,
    follow_redirects: bool,
    exclude_status: str,
) -> RunResult:
    if not shutil.which("dirsearch"):
        return RunResult(error="dirsearch not installed")

    out_file = tempfile.mktemp(suffix=".json")
    cmd = [
        "dirsearch",
        "-u", base_url,
        "-w", wordlist,
        "-t", str(threads),
        "--format", "json",
        "-o", out_file,
        "--quiet-mode",
        "--exclude-status", exclude_status,
        "--timeout", str(min(timeout, 30)),
    ]
    if extensions:
        cmd += ["-e", ",".join(extensions)]
    if recursive:
        cmd += ["-r", "--recursion-depth", "2"]
    if follow_redirects:
        cmd += ["--follow-redirects"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return RunResult(error="dirsearch timed out", raw="TIMEOUT")

    raw = proc.stdout + proc.stderr
    findings: list[dict] = []

    # Prefer the JSON report
    if os.path.exists(out_file):
        try:
            with open(out_file) as fh:
                data = json.load(fh)
            # dirsearch JSON is {"results": [{"url": ..., "status": ..., "content-length": ...}, ...]}
            for entry in data.get("results", []):
                url = entry.get("url", "")
                path = urlparse(url).path or "/"
                findings.append({
                    "path":   path,
                    "status": str(entry.get("status", "")),
                    "size":   str(entry.get("content-length", "")),
                    "url":    url,
                })
        except (OSError, json.JSONDecodeError):
            pass
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    # Fall back to / supplement with stdout parsing
    if not findings:
        for line in raw.splitlines():
            m = _DIRSEARCH_PLAIN.match(line.strip())
            if m:
                findings.append({
                    "path":   urlparse(m.group("path")).path or m.group("path"),
                    "status": m.group("status"),
                    "size":   m.group("size"),
                    "url":    m.group("path"),
                })

    return RunResult(raw=raw, findings=findings)


# gobuster format: "/path                 (Status: 200) [Size: 1234]"
_GOBUSTER_LINE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s+\[Size:\s*(?P<size>\d+)\])?"
)


def _run_gobuster(
    base_url: str,
    wordlist: str,
    extensions: list[str],
    threads: int,
    timeout: int,
    recursive: bool,        # gobuster dir has no recursion; flag is accepted but ignored
    follow_redirects: bool,
    exclude_status: str,
) -> RunResult:
    if not shutil.which("gobuster"):
        return RunResult(error="gobuster not installed")

    cmd = [
        "gobuster", "dir",
        "-u", base_url,
        "-w", wordlist,
        "-t", str(threads),
        "--no-progress",
        "-q",
        "-b", exclude_status,
        "--timeout", f"{min(timeout, 30)}s",
    ]
    if extensions:
        cmd += ["-x", ",".join(extensions)]
    if follow_redirects:
        cmd += ["-r"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return RunResult(error="gobuster timed out", raw="TIMEOUT")

    raw = proc.stdout
    findings: list[dict] = []
    for line in raw.splitlines():
        m = _GOBUSTER_LINE.match(line.strip())
        if m:
            findings.append({
                "path":   m.group("path"),
                "status": m.group("status"),
                "size":   m.group("size") or "",
                "url":    base_url.rstrip("/") + m.group("path"),
            })
    return RunResult(raw=raw, findings=findings)


def _run_feroxbuster(
    base_url: str,
    wordlist: str,
    extensions: list[str],
    threads: int,
    timeout: int,
    recursive: bool,
    follow_redirects: bool,
    exclude_status: str,
) -> RunResult:
    if not shutil.which("feroxbuster"):
        return RunResult(error="feroxbuster not installed")

    out_file = tempfile.mktemp(suffix=".json")
    cmd = [
        "feroxbuster",
        "--url", base_url,
        "--wordlist", wordlist,
        "--threads", str(threads),
        "--silent",
        "--json",
        "--output", out_file,
        "--filter-status", exclude_status,
        "--timeout", str(min(timeout, 30)),
    ]
    if extensions:
        cmd += ["-x", ",".join(extensions)]
    if not recursive:
        cmd += ["--no-recursion"]
    else:
        cmd += ["--depth", "2"]
    if follow_redirects:
        cmd += ["--redirects"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return RunResult(error="feroxbuster timed out", raw="TIMEOUT")

    raw = proc.stdout + proc.stderr
    findings: list[dict] = []

    # feroxbuster --json writes one JSON object per line (NDJSON)
    if os.path.exists(out_file):
        try:
            with open(out_file) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Only response records have status + url
                    if entry.get("type") != "response":
                        continue
                    url = entry.get("url", "")
                    findings.append({
                        "path":   urlparse(url).path or "/",
                        "status": str(entry.get("status", "")),
                        "size":   str(entry.get("content_length", "")),
                        "url":    url,
                    })
        except OSError:
            pass
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    return RunResult(raw=raw, findings=findings)


# ---------------------------------------------------------------------------
# vhost enumeration (optional)
# ---------------------------------------------------------------------------
def _run_vhost(base_url: str, wordlist: str, threads: int, timeout: int) -> list[dict]:
    """Use ffuf if available, else gobuster vhost. Returns list of {host, status, size}."""
    host = urlparse(base_url).hostname or ""
    findings: list[dict] = []
    if not host:
        return findings

    if shutil.which("ffuf"):
        cmd = [
            "ffuf",
            "-u", base_url,
            "-H", f"Host: FUZZ.{host}",
            "-w", wordlist,
            "-t", str(threads),
            "-mc", "200,204,301,302,307,401,403",
            "-fs", "0",
            "-of", "json",
            "-o", "/dev/stdout",
            "-s",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            data = json.loads(proc.stdout or "{}")
            for r in data.get("results", []):
                findings.append({
                    "host":   f"{r.get('input', {}).get('FUZZ', '')}.{host}",
                    "status": str(r.get("status", "")),
                    "size":   str(r.get("length", "")),
                })
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass
    elif shutil.which("gobuster"):
        cmd = [
            "gobuster", "vhost",
            "-u", base_url,
            "-w", wordlist,
            "-t", str(threads),
            "-q",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            for line in proc.stdout.splitlines():
                m = re.search(r"Found:\s+(\S+)\s+Status:\s+(\d+)(?:\s+\[Size:\s+(\d+)\])?", line)
                if m:
                    findings.append({"host": m.group(1), "status": m.group(2), "size": m.group(3) or ""})
        except subprocess.TimeoutExpired:
            pass
    return findings


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def _classify(path: str) -> tuple[str, str]:
    """Return (severity, note) for a discovered path using anchored regex rules."""
    for pattern, sev, note in SENSITIVE_RULES:
        if pattern.search(path):
            return sev, note
    return "info", "Path accessible"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
BACKENDS = {
    "dirsearch":   _run_dirsearch,
    "gobuster":    _run_gobuster,
    "feroxbuster": _run_feroxbuster,
}


def run(cfg: dict) -> dict:
    """Run directory enumeration with the configured backend.

    Expected cfg keys (all optional unless noted):
      domain (str, required)
      base_url (str, required)
      wordlist (str) — user-supplied wordlist; if missing/absent, we auto-pick
      dir_tool (str) — "dirsearch" (default) | "gobuster" | "feroxbuster"
      threads (int)  — default 40
      timeout (int)  — overall subprocess timeout in seconds, default 900
      use_color (bool)
      quiet (bool)
      recursive (bool)         — default True
      follow_redirects (bool)  — default True
      tech (str)               — force a tech ("php"/"asp"/...); else auto-detect
      extensions (list[str])   — override auto extensions
      exclude_status (str)     — CSV of statuses to ignore, default "404,429,500,502,503"
      vhost (bool)             — also run vhost enumeration, default False
      vhost_wordlist (str)     — wordlist for vhost (defaults to subdomain list)
    """
    domain    = cfg["domain"]
    base_url  = cfg["base_url"]
    tool      = cfg.get("dir_tool", "dirsearch")
    threads   = int(cfg.get("threads", 40))
    timeout   = int(cfg.get("timeout", 900))
    use_color = cfg.get("use_color", True)
    quiet     = cfg.get("quiet", False)
    recursive = cfg.get("recursive", True)
    follow_r  = cfg.get("follow_redirects", True)
    exclude_s = cfg.get("exclude_status", "404,429,500,502,503")

    if tool not in BACKENDS:
        return {"target": base_url, "error": f"unknown dir_tool: {tool}"}

    # ---- Tech detection & wordlist/extension selection -------------------
    tech = cfg.get("tech") or _detect_tech(base_url, timeout)
    extensions = cfg.get("extensions") or (TECH_EXTENSIONS.get(tech, []) + TECH_EXTENSIONS["generic"])
    # De-dupe while preserving order
    seen_e: set[str] = set()
    extensions = [e for e in extensions if not (e in seen_e or seen_e.add(e))]

    wordlist = _pick_wordlist(cfg.get("wordlist", ""), tech)

    if not quiet:
        section(f"Directory Enumeration ({tool})", use_color)
        status(f"Target:     {base_url}", use_color)
        status(f"Tech:       {tech}", use_color)
        status(f"Wordlist:   {wordlist}", use_color)
        status(f"Extensions: {','.join(extensions[:12])}{'…' if len(extensions) > 12 else ''}", use_color)
        if not os.path.exists(wordlist):
            warn(f"Wordlist not found: {wordlist} — tool will likely fail",
                 use_color=use_color)

    results: dict = {
        "target":     base_url,
        "tool":       tool,
        "tech":       tech,
        "wordlist":   wordlist,
        "extensions": extensions,
        "findings":   [],
        "paths":      [],
        "vhosts":     [],
    }

    runner = BACKENDS[tool]
    rr = runner(
        base_url=base_url,
        wordlist=wordlist,
        extensions=extensions,
        threads=threads,
        timeout=timeout,
        recursive=recursive,
        follow_redirects=follow_r,
        exclude_status=exclude_s,
    )

    if rr.error:
        results["error"] = rr.error
        if not quiet:
            finding("medium", rr.error, use_color=use_color)
        # Still try vhost below if requested
    else:
        # De-duplicate by path
        seen: set[str] = set()
        for entry in rr.findings:
            path = entry["path"]
            if path in seen:
                continue
            seen.add(path)
            severity, note = _classify(path)
            f = {
                "type":     "path_found",
                "path":     path,
                "url":      entry.get("url", ""),
                "status":   entry["status"],
                "size":     entry.get("size", ""),
                "severity": severity,
                "message":  f"[{entry['status']}] {path}",
                "note":     note,
            }
            results["findings"].append(f)
            results["paths"].append(path)
            if not quiet:
                finding(severity, f"[{entry['status']}] {path}", note, use_color)

        if not results["paths"] and not quiet:
            finding("info", "No paths found (try a larger wordlist or different tech)",
                    use_color=use_color)

    # ---- Optional vhost enumeration --------------------------------------
    if cfg.get("vhost"):
        vh_wl = cfg.get("vhost_wordlist") or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if os.path.exists(vh_wl):
            if not quiet:
                section("vhost enumeration", use_color)
                status(f"Wordlist: {vh_wl}", use_color)
            vh = _run_vhost(base_url, vh_wl, threads, timeout)
            results["vhosts"] = vh
            for v in vh:
                if not quiet:
                    finding("medium", f"[{v['status']}] {v['host']}",
                            "Virtual host responds — investigate", use_color)
        elif not quiet:
            warn(f"vhost wordlist not found: {vh_wl}", use_color=use_color)

    return results
