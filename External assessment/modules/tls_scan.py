"""
Module: TLS/SSL Certificate and Cipher Analysis
Uses stdlib ssl + subprocess openssl — no third-party libs.
"""

import ssl
import socket
import subprocess
import datetime
from utils.banner import section, finding, status

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "SHA1withRSA"
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def _get_cert_info(domain: str, port: int, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert      = ssock.getpeercert()
                der_cert  = ssock.getpeercert(binary_form=True)
                cipher    = ssock.cipher()
                version   = ssock.version()
                return {
                    "cert":    cert,
                    "cipher":  cipher,
                    "version": version,
                    "error":   None
                }
    except Exception as e:
        return {"error": str(e)}


def _check_weak_protocols(domain: str, timeout: int) -> list:
    """Try connecting with legacy protocols using openssl s_client."""
    issues = []
    for proto in ["-ssl2", "-ssl3", "-tls1", "-tls1_1"]:
        try:
            result = subprocess.run(
                ["openssl", "s_client", proto, "-connect", f"{domain}:443"],
                input=b"",
                capture_output=True,
                timeout=timeout
            )
            output = result.stdout.decode(errors="ignore") + result.stderr.decode(errors="ignore")
            if "CONNECTED" in output and "handshake failure" not in output.lower():
                proto_name = proto.lstrip("-").replace("tls", "TLS v").replace("ssl", "SSL v")
                issues.append(proto_name)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return issues


def run(cfg: dict) -> dict:
    domain    = cfg["domain"]
    timeout   = cfg["timeout"]
    use_color = cfg["use_color"]
    quiet     = cfg["quiet"]
    port      = 443

    if not quiet:
        section("TLS / SSL Analysis", use_color)
        status(f"Connecting to {domain}:{port}", use_color)

    results = {
        "target":   f"{domain}:{port}",
        "findings": []
    }

    info = _get_cert_info(domain, port, timeout)

    if info.get("error"):
        results["error"] = info["error"]
        if not quiet:
            finding("high", f"TLS connection failed: {info['error']}", use_color=use_color)
        return results

    # --- Protocol version ---
    version = info["version"]
    results["protocol"] = version
    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        f = {
            "type":       "weak_protocol",
            "severity":   "high",
            "message":    f"Weak protocol in use: {version}",
            "remediation": "Disable TLS 1.0/1.1 and SSLv2/3; use TLS 1.2+ only"
        }
        results["findings"].append(f)
        if not quiet:
            finding("high", f"Weak protocol: {version}", use_color=use_color)
    else:
        results["findings"].append({"type": "protocol", "severity": "pass", "message": f"Protocol: {version}"})
        if not quiet:
            finding("pass", f"Protocol: {version}", use_color=use_color)

    # --- Cipher suite ---
    cipher_name, cipher_proto, cipher_bits = info["cipher"]
    results["cipher"] = {"name": cipher_name, "bits": cipher_bits}

    weak = any(w.upper() in cipher_name.upper() for w in WEAK_CIPHERS)
    if weak:
        f = {
            "type":       "weak_cipher",
            "severity":   "high",
            "message":    f"Weak cipher in use: {cipher_name}",
            "remediation": "Disable RC4, DES, NULL, EXPORT, anon ciphers"
        }
        results["findings"].append(f)
        if not quiet:
            finding("high", f"Weak cipher: {cipher_name}", use_color=use_color)
    else:
        if cipher_bits and cipher_bits < 128:
            results["findings"].append({
                "type": "weak_cipher", "severity": "medium",
                "message": f"Short key length: {cipher_bits} bits"
            })
            if not quiet:
                finding("medium", f"Short key: {cipher_bits} bits", use_color=use_color)
        else:
            results["findings"].append({"type": "cipher", "severity": "pass",
                                         "message": f"Cipher: {cipher_name} ({cipher_bits} bits)"})
            if not quiet:
                finding("pass", f"Cipher: {cipher_name} ({cipher_bits} bits)", use_color=use_color)

    # --- Certificate expiry ---
    cert = info["cert"]
    if cert:
        not_after_str = cert.get("notAfter", "")
        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            days_left = (not_after - now).days
            results["cert_expiry"] = {"date": not_after_str, "days_remaining": days_left}

            if days_left < 0:
                sev, msg = "critical", f"Certificate EXPIRED {abs(days_left)} days ago"
            elif days_left < 14:
                sev, msg = "high", f"Certificate expires in {days_left} days"
            elif days_left < 30:
                sev, msg = "medium", f"Certificate expires in {days_left} days"
            else:
                sev, msg = "pass", f"Certificate valid for {days_left} days (expires {not_after_str})"

            results["findings"].append({"type": "cert_expiry", "severity": sev, "message": msg})
            if not quiet:
                finding(sev, msg, use_color=use_color)

        except ValueError:
            pass

        # Subject / SAN
        subject = dict(x[0] for x in cert.get("subject", []))
        san_list = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        results["cert_subject"] = subject
        results["cert_san"]     = san_list

        cn = subject.get("commonName", "")
        if not quiet:
            finding("info", f"CN: {cn}", f"SANs: {', '.join(san_list[:5])}", use_color)

        # Self-signed check
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject == issuer:
            f = {
                "type": "self_signed", "severity": "high",
                "message": "Certificate is self-signed",
                "remediation": "Use a certificate from a trusted CA"
            }
            results["findings"].append(f)
            if not quiet:
                finding("high", "Self-signed certificate detected", use_color=use_color)

    # --- Legacy protocol checks via openssl ---
    if not quiet:
        status("Checking legacy protocol support...", use_color)
    weak_protos = _check_weak_protocols(domain, timeout)
    if weak_protos:
        for p in weak_protos:
            f = {
                "type": "legacy_protocol", "severity": "high",
                "message": f"Server accepts legacy protocol: {p}",
                "remediation": f"Disable {p} on the server"
            }
            results["findings"].append(f)
            if not quiet:
                finding("high", f"Legacy protocol accepted: {p}", use_color=use_color)
    else:
        results["findings"].append({"type": "legacy_protocol", "severity": "pass",
                                     "message": "No legacy protocols (SSLv2/3, TLS1.0/1.1) accepted"})
        if not quiet:
            finding("pass", "No legacy protocols accepted", use_color=use_color)

    return results
