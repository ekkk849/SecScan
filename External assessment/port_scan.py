"""
Module: Port Scanning via nmap
Wraps nmap subprocess, parses output, flags risky open ports.
"""

import subprocess
import re
from utils.banner import section, finding, status

# Ports commonly exposed unnecessarily in production
RISKY_PORTS = {
    21:   ("FTP — plaintext credential exposure", "high"),
    22:   ("SSH — ensure key-based auth, no root login", "info"),
    23:   ("Telnet — plaintext protocol, should be disabled", "critical"),
    25:   ("SMTP open relay risk", "medium"),
    53:   ("DNS — check for zone transfer exposure", "low"),
    110:  ("POP3 — plaintext email retrieval", "medium"),
    111:  ("RPC portmapper — often unnecessary exposure", "medium"),
    135:  ("MS RPC — should not be internet-facing", "high"),
    139:  ("NetBIOS — should not be internet-facing", "high"),
    143:  ("IMAP — plaintext without STARTTLS", "medium"),
    445:  ("SMB — should never be internet-facing", "critical"),
    1433: ("MSSQL — database directly exposed", "critical"),
    1521: ("Oracle DB — database directly exposed", "critical"),
    2375: ("Docker daemon (unencrypted) — critical exposure", "critical"),
    2376: ("Docker TLS — verify auth required", "medium"),
    3306: ("MySQL — database directly exposed", "critical"),
    3389: ("RDP — high-value attack target", "high"),
    4444: ("Common reverse shell port", "high"),
    5432: ("PostgreSQL — database directly exposed", "critical"),
    5900: ("VNC — remote desktop exposure", "high"),
    6379: ("Redis — often unauthenticated when exposed", "critical"),
    8080: ("HTTP alternate — may expose dev/staging", "low"),
    8443: ("HTTPS alternate", "info"),
    8888: ("Jupyter/dev server — often unauthenticated", "high"),
    9200: ("Elasticsearch — often unauthenticated", "critical"),
    27017:("MongoDB — often unauthenticated", "critical"),
}


def _parse_nmap_output(output: str) -> list[dict]:
    """Parse nmap text output into structured port entries."""
    ports = []
    # Match lines like: 80/tcp   open  http    Apache httpd 2.4.41
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)?$",
        re.MULTILINE
    )
    for m in pattern.finditer(output):
        port_num  = int(m.group(1))
        protocol  = m.group(2)
        state     = m.group(3)
        service   = m.group(4)
        version   = m.group(5).strip() if m.group(5) else ""
        ports.append({
            "port":     port_num,
            "protocol": protocol,
            "state":    state,
            "service":  service,
            "version":  version,
        })
    return ports


def _parse_nmap_xml_lite(output: str) -> dict:
    """Extract OS and timing info from nmap output (no xml parser needed)."""
    info = {}
    os_match = re.search(r"OS details?: ([^\n]+)", output)
    if os_match:
        info["os_guess"] = os_match.group(1).strip()
    latency = re.search(r"Host is up \(([^)]+) latency\)", output)
    if latency:
        info["latency"] = latency.group(1)
    return info


def run(cfg: dict) -> dict:
    domain    = cfg["domain"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]
    extra_args = cfg.get("ports_args", "-sV --open -T4")

    if not quiet:
        section("Port Scanning (nmap)", use_color)
        status(f"Scanning {domain} — args: {extra_args}", use_color)
        status("This may take a minute...", use_color)

    results = {
        "target":    domain,
        "command":   f"nmap {extra_args} {domain}",
        "ports":     [],
        "findings":  []
    }

    cmd = ["nmap"] + extra_args.split() + [domain]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 min max
        )
        output = proc.stdout + proc.stderr
        results["raw_output"] = output
    except subprocess.TimeoutExpired:
        results["error"] = "nmap timed out after 300s"
        if not quiet:
            finding("medium", "nmap timed out — try a narrower port range", use_color=use_color)
        return results
    except FileNotFoundError:
        results["error"] = "nmap not found"
        return results
    except Exception as e:
        results["error"] = str(e)
        return results

    ports = _parse_nmap_output(output)
    results["ports"] = ports
    info  = _parse_nmap_xml_lite(output)
    results.update(info)

    if not quiet and info.get("os_guess"):
        finding("info", f"OS guess: {info['os_guess']}", use_color=use_color)

    open_ports = [p for p in ports if p["state"] == "open"]

    if not open_ports:
        results["findings"].append({"type": "no_open_ports", "severity": "info",
                                     "message": "No open ports found in scanned range"})
        if not quiet:
            finding("info", "No open ports found in scanned range", use_color=use_color)
        return results

    if not quiet:
        status(f"Found {len(open_ports)} open port(s)", use_color)

    for p in open_ports:
        port_num = p["port"]
        svc      = p["service"]
        ver      = p["version"]
        label    = f"{port_num}/{p['protocol']} — {svc}"
        if ver:
            label += f" ({ver[:60]})"

        if port_num in RISKY_PORTS:
            note, severity = RISKY_PORTS[port_num]
            f = {
                "type":       "risky_port",
                "port":       port_num,
                "service":    svc,
                "version":    ver,
                "severity":   severity,
                "message":    f"Open: {label}",
                "note":       note,
                "remediation": f"Review exposure of port {port_num}: {note}"
            }
            results["findings"].append(f)
            if not quiet:
                finding(severity, f"Open: {label}", note, use_color)
        else:
            f = {
                "type":     "open_port",
                "port":     port_num,
                "service":  svc,
                "version":  ver,
                "severity": "info",
                "message":  f"Open: {label}"
            }
            results["findings"].append(f)
            if not quiet:
                finding("info", f"Open: {label}", use_color=use_color)

    return results
