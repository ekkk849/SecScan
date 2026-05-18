"""
Dependency checker — verifies required external tools are installed
"""

import shutil
import sys
from utils.banner import YELLOW, RED, GREEN, RESET, BOLD


def check_dependencies(tools: list, use_color: bool = True):
    if not tools:
        return

    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)

    if missing:
        if use_color:
            print(f"\n  {RED}{BOLD}Missing dependencies:{RESET}")
            for t in missing:
                print(f"    {YELLOW}✗ {t}{RESET}  — not found in PATH")
        else:
            print("\n  Missing dependencies:")
            for t in missing:
                print(f"    ✗ {t}  — not found in PATH")

        print("\n  Install hints (Kali):")
        hints = {
            "nmap":        "sudo apt install nmap",
            "dirsearch":   "sudo apt install dirsearch  OR  pip install dirsearch",
            "gobuster":    "sudo apt install gobuster",
            "feroxbuster": "sudo apt install feroxbuster",
            "subfinder":   "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass":       "sudo apt install amass",
            "sublist3r":   "pip install sublist3r",
        }
        for t in missing:
            hint = hints.get(t, f"check https://github.com/{t}")
            print(f"    {t}: {hint}")

        print()
        answer = input("  Continue without missing tools? [y/N] ").strip().lower()
        if answer != "y":
            sys.exit(1)
