#!/usr/bin/env python3
"""PrivScope - Modular Linux Privilege Escalation & Security Auditing Engine"""

import argparse
import json
import sys
from typing import List

from privscope.checks.base import BaseCheck, CheckResult, Severity
from privscope.checks.capabilities import CapabilitiesCheck
from privscope.checks.cron import CronCheck
from privscope.checks.kernel import KernelCheck
from privscope.checks.path import PathCheck
from privscope.checks.permissions import PermissionsCheck
from privscope.checks.suid import SUIDCheck

BANNER = r"""
  ____       _       ____                       
 |  _ \ _ __(_)_   _/ ___|  ___ ___  _ __   ___ 
 | |_) | '__| \ \ / /\___ \ / __/ _ \| '_ \ / _ \
 |  __/| |  | |\ V /  ___) | (_| (_) | |_) |  __/
 |_|   |_|  |_| \_/  |____/ \___\___/| .__/ \___|
                                     |_|         
 :: Linux Misconfiguration & PrivEsc Vector Auditor ::
"""

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[90m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "GREEN": "\033[32m",
}


def get_registered_checks() -> List[BaseCheck]:
    return [
        KernelCheck(),
        CapabilitiesCheck(),
        SUIDCheck(),
        PermissionsCheck(),
        CronCheck(),
        PathCheck(),
    ]


def main():
    parser = argparse.ArgumentParser(
        description="PrivScope: Zero-Dependency Linux Privilege Escalation & Security Auditor"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in machine-readable JSON format",
    )
    parser.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="Filter findings by minimum severity threshold (default: INFO)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress ASCII banner",
    )
    args = parser.parse_args()

    if not args.json and not args.no_banner:
        print(BANNER)

    all_results: List[CheckResult] = []
    checks = get_registered_checks()

    for check in checks:
        try:
            findings = check.run()
            for res in findings:
                if Severity.is_gte(res.severity, args.min_severity):
                    all_results.append(res)
        except Exception as e:
            if not args.json:
                print(f"[!] Error executing check '{check.name}': {e}", file=sys.stderr)

    if args.json:
        payload = [r.to_dict() for r in all_results]
        print(json.dumps(payload, indent=2))
        return

    if not all_results:
        print(f"{COLORS['GREEN']}[+] No issues found meeting or exceeding severity: {args.min_severity}{COLORS['RESET']}")
        return

    for res in all_results:
        col = COLORS.get(res.severity, COLORS["RESET"])
        print(f"{col}[{res.severity}]{COLORS['RESET']} {COLORS['BOLD']}{res.title}{COLORS['RESET']}")
        print(f"  {res.description}")
        for item in res.findings:
            print(f"  -> {item}")
        if res.remediation:
            print(f"  {COLORS['GREEN']}Remediation:{COLORS['RESET']} {res.remediation}")
        print("-" * 60)


if __name__ == "__main__":
    main()
