#!/usr/bin/env python3
"""
SecScan - Lightweight External Network Security Scanner
Kali Linux CLI Tool
"""

import argparse
import sys
import os
from modules import (
    header_scan,
    tls_scan,
    email_sec,
    port_scan,
    dir_enum,
    subdomain_enum,
    sri_check,
    reporter
)
from utils.banner import print_banner
from utils.checks import check_dependencies


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="SecScan - External Network & Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secscan -t example.com --all
  secscan -t example.com --headers --tls --email
  secscan -t example.com --ports --ports-args "-sV -p 1-1000"
  secscan -t example.com --dirs --wordlist /usr/share/wordlists/dirb/common.txt
  secscan -t example.com --subs --sub-tool subfinder
  secscan -t example.com --all --output report.json

⚠  Only scan systems you own or have explicit authorisation to test.
        """
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help="Target domain or URL (e.g. example.com or https://example.com)"
    )

    # --- Module flags ---
    modules = parser.add_argument_group("Scan Modules")
    modules.add_argument("--all",        action="store_true", help="Run all modules")
    modules.add_argument("--headers",    action="store_true", help="HTTP security header analysis")
    modules.add_argument("--tls",        action="store_true", help="TLS/SSL certificate and cipher checks")
    modules.add_argument("--email",      action="store_true", help="Email security records (SPF, DKIM, DMARC)")
    modules.add_argument("--ports",      action="store_true", help="Port scan via nmap")
    modules.add_argument("--dirs",       action="store_true", help="Directory enumeration via dirsearch or gobuster")
    modules.add_argument("--subs",       action="store_true", help="Subdomain enumeration via subfinder/amass/sublist3r")
    modules.add_argument("--sri",        action="store_true", help="Sub-Resource Integrity checks on external scripts")

    # --- Tool options ---
    opts = parser.add_argument_group("Module Options")
    opts.add_argument("--ports-args",   metavar="ARGS",     default="-sV --open -T4",
                      help='Extra nmap args (default: "-sV --open -T4")')
    opts.add_argument("--wordlist",     metavar="PATH",
                      default="/usr/share/wordlists/dirb/common.txt",
                      help="Wordlist for directory enumeration")
    opts.add_argument("--dir-tool",     choices=["dirsearch", "gobuster", "feroxbuster"],
                      default="dirsearch", help="Directory brute-force tool (default: dirsearch)")
    opts.add_argument("--sub-tool",     choices=["subfinder", "amass", "sublist3r"],
                      default="subfinder", help="Subdomain enumeration tool (default: subfinder)")
    opts.add_argument("--dkim-selector", metavar="SEL", default="default",
                      help="DKIM selector to check (default: default)")
    opts.add_argument("--threads",      type=int, default=10,
                      help="Thread count for tools that support it (default: 10)")
    opts.add_argument("--timeout",      type=int, default=10,
                      help="Per-request timeout in seconds (default: 10)")

    # --- Output ---
    out = parser.add_argument_group("Output")
    out.add_argument("--output",  metavar="FILE", help="Save JSON report to file")
    out.add_argument("--no-color", action="store_true", help="Disable coloured terminal output")
    out.add_argument("--quiet",   action="store_true", help="Suppress banner and progress messages")

    return parser


def confirm_authorisation(target: str, quiet: bool):
    if quiet:
        return
    print(f"\n⚠  AUTHORISATION CHECK")
    print(f"   Target: {target}")
    print("   Active scanning modules (ports, dirs, subs) will send network requests")
    print("   to the target. Only proceed if you own or are explicitly authorised to")
    print("   test this system.\n")
    answer = input("   Type 'yes' to confirm authorisation and continue: ").strip().lower()
    if answer != "yes":
        print("   Aborted.")
        sys.exit(0)


def main():
    parser = build_parser()
    args = parser.parse_args()

    use_color = not args.no_color

    if not args.quiet:
        print_banner(use_color)

    # Normalise target
    target = args.target.strip().rstrip("/")
    if target.startswith("http://") or target.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.netloc
        base_url = target
    else:
        domain = target
        base_url = f"https://{target}"

    # Determine active modules
    run_all     = args.all
    run_headers = run_all or args.headers
    run_tls     = run_all or args.tls
    run_email   = run_all or args.email
    run_ports   = run_all or args.ports
    run_dirs    = run_all or args.dirs
    run_subs    = run_all or args.subs
    run_sri     = run_all or args.sri

    active_modules = [run_headers, run_tls, run_email, run_ports, run_dirs, run_subs, run_sri]
    if not any(active_modules):
        parser.print_help()
        sys.exit(1)

    # Authorisation gate for active scanning
    if run_ports or run_dirs or run_subs:
        confirm_authorisation(target, args.quiet)

    # Dependency check
    needed = []
    if run_ports:               needed.append("nmap")
    if run_dirs:                needed.append(args.dir_tool)
    if run_subs:                needed.append(args.sub_tool)
    check_dependencies(needed, use_color)

    # Config passed to every module
    cfg = {
        "domain":        domain,
        "base_url":      base_url,
        "timeout":       args.timeout,
        "threads":       args.threads,
        "quiet":         args.quiet,
        "use_color":     use_color,
        "dkim_selector": args.dkim_selector,
        "wordlist":      args.wordlist,
        "dir_tool":      args.dir_tool,
        "sub_tool":      args.sub_tool,
        "ports_args":    args.ports_args,
    }

    results = {}

    if run_headers:
        results["http_headers"] = header_scan.run(cfg)

    if run_tls:
        results["tls"] = tls_scan.run(cfg)

    if run_email:
        results["email_security"] = email_sec.run(cfg)

    if run_sri:
        results["sri"] = sri_check.run(cfg)

    if run_ports:
        results["ports"] = port_scan.run(cfg)

    if run_dirs:
        results["directories"] = dir_enum.run(cfg)

    if run_subs:
        results["subdomains"] = subdomain_enum.run(cfg)

    # Final report
    reporter.print_summary(results, cfg)

    if args.output:
        reporter.save_json(results, args.output, cfg)
        if not args.quiet:
            print(f"\n  Report saved → {args.output}")


if __name__ == "__main__":
    main()
