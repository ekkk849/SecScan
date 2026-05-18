# SecScan — Lightweight External Network & Web Security Scanner

A modular, Kali-native CLI tool for authorised external network and web security assessments.  
Pure Python 3 + subprocess — no third-party Python libs required.

---

## Modules

| Flag | Module | External Tool |
|---|---|---|
| `--headers` | HTTP security header analysis | none (stdlib urllib) |
| `--tls` | TLS/SSL cert, cipher, protocol checks | openssl (optional) |
| `--email` | SPF, DKIM, DMARC verification | dig / nslookup |
| `--sri` | Sub-Resource Integrity on external scripts | none (stdlib) |
| `--ports` | Port scan + service/version detection | **nmap** |
| `--dirs` | Directory / path enumeration | **dirsearch / gobuster / feroxbuster** |
| `--subs` | Subdomain enumeration | **subfinder / amass / sublist3r** |
| `--all` | Run every module | all of the above |

---

## Requirements

- Python 3.9+
- Kali Linux (or any Debian-based distro with security tools)
- External tools installed as needed per module (see above)

Install missing tools on Kali:
```bash
sudo apt update
sudo apt install nmap dirsearch gobuster feroxbuster amass openssl dnsutils
# subfinder (Go):
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# sublist3r:
pip install sublist3r
```

---

## Usage

```bash
# Full scan
python3 secscan.py -t example.com --all --output report.json

# Headers + TLS + email only (passive, no active scanning)
python3 secscan.py -t example.com --headers --tls --email

# Port scan with custom nmap args
python3 secscan.py -t example.com --ports --ports-args "-sV -p 1-65535 -T4"

# Directory brute-force with gobuster
python3 secscan.py -t example.com --dirs --dir-tool gobuster \
  --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Subdomain enumeration with subfinder
python3 secscan.py -t example.com --subs --sub-tool subfinder

# DKIM with custom selector
python3 secscan.py -t example.com --email --dkim-selector google

# Quiet mode (no banner/progress), JSON only
python3 secscan.py -t example.com --all --quiet --output report.json

# No colour (for piping / logging)
python3 secscan.py -t example.com --all --no-color | tee scan.log
```

---

## Output

Results print to terminal in real-time with severity-coded findings:

```
[CRIT]  Open: 3306/tcp — mysql (MySQL 8.0.32)
[HIGH]  Missing: Strict-Transport-Security
[MED ]  DMARC policy is 'none' — monitoring only
[LOW ]  HSTS missing includeSubDomains
[PASS]  Protocol: TLSv1.3
[INFO]  CN: example.com
```

JSON report saved with `--output report.json`:

```json
{
  "meta": { "tool": "SecScan", "target": "example.com", "timestamp": "..." },
  "summary": { "risk_score": 42, "counts": { "critical": 2, "high": 5, ... } },
  "modules": { "http_headers": {...}, "tls": {...}, ... }
}
```

---

## Structure

```
secscan/
├── secscan.py          — CLI entry point
├── modules/
│   ├── header_scan.py  — HTTP headers
│   ├── tls_scan.py     — TLS/SSL
│   ├── email_sec.py    — SPF/DKIM/DMARC
│   ├── sri_check.py    — SRI
│   ├── port_scan.py    — nmap wrapper
│   ├── dir_enum.py     — dirsearch/gobuster/feroxbuster wrapper
│   ├── subdomain_enum.py — subfinder/amass/sublist3r wrapper
│   └── reporter.py     — terminal summary + JSON
└── utils/
    ├── banner.py       — colours, icons, print helpers
    └── checks.py       — dependency checker
```

---

## Legal

Only scan systems you own or have **explicit written authorisation** to test.  
Unauthorised scanning may violate computer crime laws in your jurisdiction.
