"""
Module: Email Security Record Verification
Checks SPF, DKIM, DMARC via subprocess dig/nslookup — no dnspython.
"""

import subprocess
import re
from utils.banner import section, finding, status


def _dig(name: str, record_type: str, timeout: int) -> list[str]:
    """Run dig and return answer lines. Falls back to nslookup."""
    try:
        result = subprocess.run(
            ["dig", "+short", record_type, name],
            capture_output=True, text=True, timeout=timeout
        )
        lines = [l.strip().strip('"') for l in result.stdout.splitlines() if l.strip()]
        return lines
    except FileNotFoundError:
        pass

    # Fallback: nslookup
    try:
        result = subprocess.run(
            ["nslookup", "-type=" + record_type, name],
            capture_output=True, text=True, timeout=timeout
        )
        lines = []
        for l in result.stdout.splitlines():
            if "=" in l or "text" in l.lower():
                lines.append(l.strip())
        return lines
    except Exception:
        return []


# ── SPF ─────────────────────────────────────────────────────────────────────

def check_spf(domain: str, timeout: int) -> dict:
    records = _dig(domain, "TXT", timeout)
    spf_records = [r for r in records if "v=spf1" in r.lower()]

    result = {"record": None, "findings": []}

    if not spf_records:
        result["findings"].append({
            "type": "spf_missing", "severity": "high",
            "message": "No SPF record found",
            "remediation": f'Add TXT record: {domain} "v=spf1 ... -all"'
        })
        return result

    if len(spf_records) > 1:
        result["findings"].append({
            "type": "spf_multiple", "severity": "high",
            "message": f"Multiple SPF records found ({len(spf_records)}) — only one is valid",
            "remediation": "Merge into a single SPF record"
        })

    spf = spf_records[0]
    result["record"] = spf

    # All mechanism check
    if "-all" in spf:
        result["findings"].append({"type": "spf_all", "severity": "pass",
                                    "message": "SPF uses -all (hard fail)"})
    elif "~all" in spf:
        result["findings"].append({"type": "spf_all", "severity": "medium",
                                    "message": "SPF uses ~all (soft fail) — consider -all",
                                    "remediation": "Change ~all to -all for strict enforcement"})
    elif "+all" in spf:
        result["findings"].append({"type": "spf_all", "severity": "critical",
                                    "message": "SPF uses +all — allows ANY sender to spoof",
                                    "remediation": "Replace +all with -all immediately"})
    else:
        result["findings"].append({"type": "spf_all", "severity": "medium",
                                    "message": "SPF has no explicit 'all' mechanism"})

    # DNS lookup count (max 10 allowed per RFC)
    lookup_mechanisms = re.findall(r'\b(include|a|mx|ptr|exists):', spf)
    if len(lookup_mechanisms) > 10:
        result["findings"].append({
            "type": "spf_lookup_limit", "severity": "medium",
            "message": f"SPF has {len(lookup_mechanisms)} DNS lookups (RFC limit is 10)",
            "remediation": "Reduce include/a/mx mechanisms"
        })

    return result


# ── DKIM ─────────────────────────────────────────────────────────────────────

def check_dkim(domain: str, selector: str, timeout: int) -> dict:
    name = f"{selector}._domainkey.{domain}"
    records = _dig(name, "TXT", timeout)

    result = {"selector": selector, "record": None, "findings": []}

    dkim_records = [r for r in records if "v=dkim1" in r.lower() or "p=" in r.lower()]

    if not dkim_records:
        result["findings"].append({
            "type": "dkim_missing", "severity": "medium",
            "message": f"No DKIM record found for selector '{selector}'",
            "remediation": f"Add DKIM TXT record at {name}"
        })
        return result

    dkim = dkim_records[0]
    result["record"] = dkim[:120] + "..." if len(dkim) > 120 else dkim

    # Key type check
    if "k=rsa" in dkim.lower() or "k=" not in dkim.lower():
        key_type = "RSA"
    else:
        key_type = re.search(r"k=([^;]+)", dkim, re.I)
        key_type = key_type.group(1) if key_type else "unknown"

    # Check for revoked (p=)
    p_match = re.search(r"p=([^;\"]+)", dkim)
    if p_match and p_match.group(1).strip() == "":
        result["findings"].append({
            "type": "dkim_revoked", "severity": "info",
            "message": f"DKIM key revoked (p=) for selector '{selector}'"
        })
    else:
        result["findings"].append({"type": "dkim_present", "severity": "pass",
                                    "message": f"DKIM record present (selector: {selector}, key: {key_type})"})

    return result


# ── DMARC ────────────────────────────────────────────────────────────────────

def check_dmarc(domain: str, timeout: int) -> dict:
    name = f"_dmarc.{domain}"
    records = _dig(name, "TXT", timeout)
    dmarc_records = [r for r in records if "v=dmarc1" in r.lower()]

    result = {"record": None, "findings": []}

    if not dmarc_records:
        result["findings"].append({
            "type": "dmarc_missing", "severity": "high",
            "message": "No DMARC record found",
            "remediation": f'Add TXT at _dmarc.{domain}: "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"'
        })
        return result

    dmarc = dmarc_records[0]
    result["record"] = dmarc

    # Policy check
    p_match = re.search(r"\bp=(\w+)", dmarc, re.I)
    if p_match:
        policy = p_match.group(1).lower()
        if policy == "none":
            result["findings"].append({
                "type": "dmarc_policy", "severity": "medium",
                "message": "DMARC policy is 'none' — monitoring only, no enforcement",
                "remediation": "Gradually move to p=quarantine then p=reject"
            })
        elif policy == "quarantine":
            result["findings"].append({"type": "dmarc_policy", "severity": "low",
                                        "message": "DMARC policy is 'quarantine'",
                                        "remediation": "Consider upgrading to p=reject"})
        elif policy == "reject":
            result["findings"].append({"type": "dmarc_policy", "severity": "pass",
                                        "message": "DMARC policy is 'reject' (strongest)"})
    else:
        result["findings"].append({
            "type": "dmarc_no_policy", "severity": "high",
            "message": "DMARC record has no policy (p=) tag"
        })

    # PCT
    pct_match = re.search(r"\bpct=(\d+)", dmarc, re.I)
    if pct_match and int(pct_match.group(1)) < 100:
        result["findings"].append({
            "type": "dmarc_pct", "severity": "low",
            "message": f"DMARC pct={pct_match.group(1)}% — policy not applied to all mail"
        })

    # Reporting
    if "rua=" not in dmarc.lower():
        result["findings"].append({
            "type": "dmarc_rua", "severity": "info",
            "message": "DMARC has no aggregate report address (rua=)",
            "remediation": "Add rua=mailto:... to receive DMARC reports"
        })

    return result


# ── Runner ───────────────────────────────────────────────────────────────────

def run(cfg: dict) -> dict:
    domain    = cfg["domain"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]
    selector  = cfg.get("dkim_selector", "default")

    if not quiet:
        section("Email Security Records (SPF / DKIM / DMARC)", use_color)

    results = {"domain": domain, "spf": {}, "dkim": {}, "dmarc": {}}

    # SPF
    if not quiet:
        status("Checking SPF...", use_color)
    spf = check_spf(domain, timeout)
    results["spf"] = spf
    if not quiet:
        if spf.get("record"):
            finding("info", f"SPF record: {spf['record'][:80]}", use_color=use_color)
        for f in spf["findings"]:
            finding(f["severity"], f["message"],
                    f.get("remediation", ""), use_color)

    # DKIM
    if not quiet:
        status(f"Checking DKIM (selector: {selector})...", use_color)
    dkim = check_dkim(domain, selector, timeout)
    results["dkim"] = dkim
    if not quiet:
        for f in dkim["findings"]:
            finding(f["severity"], f["message"],
                    f.get("remediation", ""), use_color)

    # DMARC
    if not quiet:
        status("Checking DMARC...", use_color)
    dmarc = check_dmarc(domain, timeout)
    results["dmarc"] = dmarc
    if not quiet:
        if dmarc.get("record"):
            finding("info", f"DMARC: {dmarc['record'][:80]}", use_color=use_color)
        for f in dmarc["findings"]:
            finding(f["severity"], f["message"],
                    f.get("remediation", ""), use_color)

    return results
