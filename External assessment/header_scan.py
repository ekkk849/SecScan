"""
Module: HTTP Security Header Analysis
Checks for presence and correct configuration of security headers.
Uses only stdlib urllib — no third-party HTTP libs.
"""

import urllib.request
import urllib.error
import ssl
from utils.banner import section, finding, status

# (header, severity_if_missing, recommended_value_hint)
SECURITY_HEADERS = [
    ("Strict-Transport-Security",   "high",   "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy",     "high",   "define policy restricting sources"),
    ("X-Content-Type-Options",      "medium", "nosniff"),
    ("X-Frame-Options",             "medium", "DENY or SAMEORIGIN"),
    ("Referrer-Policy",             "low",    "strict-origin-when-cross-origin"),
    ("Permissions-Policy",          "low",    "restrict camera, microphone, geolocation"),
    ("Cross-Origin-Opener-Policy",  "low",    "same-origin"),
    ("Cross-Origin-Resource-Policy","low",    "same-origin"),
]

INSECURE_VALUES = {
    "X-Powered-By":  ("info",   "Reveals technology stack"),
    "Server":        ("info",   "Reveals server software"),
    "X-AspNet-Version": ("low", "Reveals ASP.NET version"),
}


def run(cfg: dict) -> dict:
    domain    = cfg["domain"]
    base_url  = cfg["base_url"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]

    if not quiet:
        section("HTTP Security Headers", use_color)
        status(f"Fetching headers from {base_url}", use_color)

    results = {
        "target":   base_url,
        "findings": [],
        "raw_headers": {}
    }

    # Fetch headers — ignore cert errors for analysis purposes
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "SecScan/1.0 (security-audit)"}
        )
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw = dict(resp.headers)
        results["raw_headers"] = {k.lower(): v for k, v in raw.items()}
        status_code = resp.status
    except urllib.error.HTTPError as e:
        raw = dict(e.headers)
        results["raw_headers"] = {k.lower(): v for k, v in raw.items()}
        status_code = e.code
    except Exception as e:
        results["error"] = str(e)
        if not quiet:
            finding("high", f"Could not fetch headers: {e}", use_color=use_color)
        return results

    headers_lc = results["raw_headers"]

    if not quiet:
        status(f"Response: HTTP {status_code}", use_color)

    # Check for missing security headers
    for header, severity, hint in SECURITY_HEADERS:
        key = header.lower()
        if key in headers_lc:
            val = headers_lc[key]
            f = {
                "type":     "present",
                "header":   header,
                "value":    val,
                "severity": "pass",
                "message":  f"{header} present"
            }
            results["findings"].append(f)
            if not quiet:
                finding("pass", f"{header}", val, use_color)
        else:
            f = {
                "type":       "missing",
                "header":     header,
                "severity":   severity,
                "message":    f"Missing: {header}",
                "remediation": f"Add header: {header}: {hint}"
            }
            results["findings"].append(f)
            if not quiet:
                finding(severity, f"Missing: {header}", f"Recommended: {hint}", use_color)

    # Check for information-leaking headers
    for header, (severity, desc) in INSECURE_VALUES.items():
        key = header.lower()
        if key in headers_lc:
            val = headers_lc[key]
            f = {
                "type":       "info_leak",
                "header":     header,
                "value":      val,
                "severity":   severity,
                "message":    f"Information disclosure: {header}: {val}",
                "remediation": f"Remove or obfuscate {header} header"
            }
            results["findings"].append(f)
            if not quiet:
                finding(severity, f"Info leak: {header}: {val}", desc, use_color)

    # HSTS depth check
    hsts_key = "strict-transport-security"
    if hsts_key in headers_lc:
        val = headers_lc[hsts_key].lower()
        age = 0
        for part in val.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    age = int(part.split("=")[1])
                except ValueError:
                    pass
        if age < 31536000:
            f = {
                "type":       "weak_config",
                "header":     "Strict-Transport-Security",
                "value":      headers_lc[hsts_key],
                "severity":   "medium",
                "message":    f"HSTS max-age too short ({age}s)",
                "remediation": "Set max-age to at least 31536000 (1 year)"
            }
            results["findings"].append(f)
            if not quiet:
                finding("medium", f"HSTS max-age too short: {age}s", "Minimum: 31536000", use_color)

        if "includesubdomains" not in val:
            f = {
                "type":       "weak_config",
                "header":     "Strict-Transport-Security",
                "severity":   "low",
                "message":    "HSTS missing includeSubDomains",
                "remediation": "Add includeSubDomains directive"
            }
            results["findings"].append(f)
            if not quiet:
                finding("low", "HSTS missing includeSubDomains", use_color=use_color)

    return results
