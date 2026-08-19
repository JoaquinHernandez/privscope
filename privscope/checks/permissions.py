"""Audit critical system file permissions and passwordless sudo configurations."""

import os
import subprocess
from typing import List
from privscope.checks.base import BaseCheck, CheckResult, Severity

CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/root",
    "/etc/security/opasswd",
    "/etc/pam.d/su",
]


class PermissionsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "File Permissions & Sudo Check"

    def run(self) -> List[CheckResult]:
        results = []
        writable_files = []

        is_unprivileged = (os.getuid() != 0)

        for path in CRITICAL_PATHS:
            if os.path.exists(path) and os.access(path, os.W_OK) and is_unprivileged:
                writable_files.append(path)

        if writable_files:
            results.append(
                CheckResult(
                    title="Writable Critical System Files",
                    severity=Severity.CRITICAL,
                    description="Sensitive configuration files are writable by the current unprivileged user.",
                    findings=writable_files,
                    remediation="Restrict file ownership and permissions immediately: `chown root:root <path> && chmod 644 <path>`.",
                )
            )

        # Check sudo -l without prompting for a password (-n)
        try:
            proc = subprocess.run(
                ["sudo", "-n", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if proc.returncode == 0:
                nopasswd_lines = [
                    line.strip() for line in proc.stdout.splitlines() if "NOPASSWD" in line
                ]
                if nopasswd_lines:
                    results.append(
                        CheckResult(
                            title="Passwordless Sudo Privileges Detected",
                            severity=Severity.HIGH,
                            description="User can execute commands with elevated privileges without providing a password.",
                            findings=nopasswd_lines,
                            remediation="Audit /etc/sudoers and remove NOPASSWD directives where not strictly necessary.",
                        )
                    )
        except FileNotFoundError:
            pass

        return results
