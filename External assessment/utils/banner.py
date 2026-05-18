"""
Terminal utilities - banner, colours, status printers
"""

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"

SEVERITY_COLOR = {
    "critical": RED,
    "high":     RED,
    "medium":   YELLOW,
    "low":      CYAN,
    "info":     DIM,
    "pass":     GREEN,
}

SEVERITY_ICON = {
    "critical": "[CRIT]",
    "high":     "[HIGH]",
    "medium":   "[MED] ",
    "low":      "[LOW] ",
    "info":     "[INFO]",
    "pass":     "[PASS]",
}

BANNER = r"""
  ____            ____
 / ___|  ___  ___/ ___|  ___ __ _ _ __
 \___ \ / _ \/ __\___ \ / __/ _` | '_ \
  ___) |  __/ (__ ___) | (_| (_| | | | |
 |____/ \___|\___|____/ \___\__,_|_| |_|

"""


def print_banner(use_color=True):
    if use_color:
        print(f"{CYAN}{BOLD}{BANNER}{RESET}", end="")
        print(f"  {WHITE}External Network & Web Security Scanner{RESET}")
        print(f"  {DIM}SecScan — for authorised testing only{RESET}\n")
    else:
        print(BANNER, end="")
        print("  External Network & Web Security Scanner")
        print("  SecScan — for authorised testing only\n")


def status(msg: str, use_color=True):
    if use_color:
        print(f"  {CYAN}»{RESET} {msg}")
    else:
        print(f"  » {msg}")


def section(title: str, use_color=True):
    bar = "─" * (len(title) + 4)
    if use_color:
        print(f"\n  {BOLD}{WHITE}┌{bar}┐")
        print(f"  │  {title}  │")
        print(f"  └{bar}┘{RESET}")
    else:
        print(f"\n  +{bar}+")
        print(f"  |  {title}  |")
        print(f"  +{bar}+")


def finding(severity: str, message: str, detail: str = "", use_color=True):
    sev = severity.lower()
    icon = SEVERITY_ICON.get(sev, "[    ]")
    if use_color:
        col = SEVERITY_COLOR.get(sev, WHITE)
        line = f"  {col}{icon}{RESET} {message}"
        if detail:
            line += f"\n         {DIM}{detail}{RESET}"
    else:
        line = f"  {icon} {message}"
        if detail:
            line += f"\n         {detail}"
    print(line)
