"""
Module: Sub-Resource Integrity (SRI) Check
Fetches the page HTML and checks external <script> and <link> tags
for missing or present integrity= attributes.
Uses only stdlib.
"""

import urllib.request
import urllib.error
import ssl
import re
from utils.banner import section, finding, status


def run(cfg: dict) -> dict:
    base_url  = cfg["base_url"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]
    domain    = cfg["domain"]

    if not quiet:
        section("Sub-Resource Integrity (SRI)", use_color)
        status(f"Fetching page: {base_url}", use_color)

    results = {
        "target":   base_url,
        "findings": [],
        "scripts":  [],
        "links":    []
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "SecScan/1.0 (security-audit)"}
        )
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        html = resp.read().decode(errors="replace")
    except Exception as e:
        results["error"] = str(e)
        if not quiet:
            finding("medium", f"Could not fetch page: {e}", use_color=use_color)
        return results

    # Find all <script src="..."> tags
    script_pattern = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE
    )
    link_pattern = re.compile(
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE
    )
    integrity_pattern = re.compile(r'\bintegrity=["\'][^"\']+["\']', re.IGNORECASE)
    crossorigin_pattern = re.compile(r'\bcrossorigin\b', re.IGNORECASE)

    def is_external(url: str) -> bool:
        return url.startswith("http://") or url.startswith("https://") or url.startswith("//")

    def is_third_party(url: str) -> bool:
        return is_external(url) and domain not in url

    # Scripts
    for m in script_pattern.finditer(html):
        src     = m.group(1)
        tag     = m.group(0)
        has_sri = bool(integrity_pattern.search(tag))
        has_co  = bool(crossorigin_pattern.search(tag))
        external = is_external(src)
        third_p  = is_third_party(src)

        entry = {
            "src":       src,
            "external":  external,
            "third_party": third_p,
            "has_sri":   has_sri,
            "has_crossorigin": has_co
        }
        results["scripts"].append(entry)

        if third_p and not has_sri:
            f = {
                "type":       "missing_sri_script",
                "severity":   "medium",
                "resource":   src,
                "message":    f"External script without SRI: {src[:80]}",
                "remediation": "Add integrity= and crossorigin= attributes to the <script> tag"
            }
            results["findings"].append(f)
            if not quiet:
                finding("medium", f"No SRI on script: {src[:70]}", use_color=use_color)
        elif third_p and has_sri and not has_co:
            f = {
                "type":       "missing_crossorigin",
                "severity":   "low",
                "resource":   src,
                "message":    f"SRI present but crossorigin missing: {src[:80]}",
                "remediation": "Add crossorigin=\"anonymous\" to the <script> tag"
            }
            results["findings"].append(f)
            if not quiet:
                finding("low", f"Missing crossorigin on: {src[:70]}", use_color=use_color)
        elif third_p and has_sri:
            if not quiet:
                finding("pass", f"SRI OK: {src[:70]}", use_color=use_color)

    # Stylesheets
    for m in link_pattern.finditer(html):
        href    = m.group(1)
        tag     = m.group(0)
        rel_match = re.search(r'rel=["\']([^"\']+)["\']', tag, re.I)
        if not rel_match or "stylesheet" not in rel_match.group(1).lower():
            continue

        has_sri = bool(integrity_pattern.search(tag))
        has_co  = bool(crossorigin_pattern.search(tag))
        third_p = is_third_party(href)

        entry = {
            "href":      href,
            "third_party": third_p,
            "has_sri":   has_sri,
            "has_crossorigin": has_co
        }
        results["links"].append(entry)

        if third_p and not has_sri:
            f = {
                "type":       "missing_sri_stylesheet",
                "severity":   "low",
                "resource":   href,
                "message":    f"External stylesheet without SRI: {href[:80]}",
                "remediation": "Add integrity= and crossorigin= to the <link> tag"
            }
            results["findings"].append(f)
            if not quiet:
                finding("low", f"No SRI on stylesheet: {href[:70]}", use_color=use_color)

    if not results["findings"] and not quiet:
        finding("pass", "All external resources have SRI (or none found)", use_color=use_color)

    ext_no_sri = [f for f in results["findings"] if "missing_sri" in f.get("type", "")]
    if not quiet:
        status(f"Checked {len(results['scripts'])} scripts, "
               f"{len(results['links'])} stylesheets — "
               f"{len(ext_no_sri)} missing SRI", use_color)

    return results
