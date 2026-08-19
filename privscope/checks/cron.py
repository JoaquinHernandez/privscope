"""Audit cron jobs, scheduled tasks, writable scripts, and wildcard injection vectors."""

import os
import re
import shlex
from typing import List
from privscope.checks.base import BaseCheck, CheckResult, Severity

CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]

WILDCARD_COMMANDS = {"tar", "rsync", "chmod", "chown", "cp", "zip"}


class CronCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Cron Security Audit"

    def _is_user_writable(self, path: str) -> bool:
        return os.path.exists(path) and os.access(path, os.W_OK) and (os.getuid() != 0)

    def _extract_executables(self, command_str: str) -> List[str]:
        found = []
        try:
            tokens = shlex.split(command_str)
            for token in tokens:
                if token.startswith("/") or token.startswith("./"):
                    target = token.split()[0]
                    if os.path.isfile(target):
                        found.append(target)
        except ValueError:
            pass
        return found

    def run(self) -> List[CheckResult]:
        results = []
        writable_cron_files: List[str] = []
        writable_cron_scripts: List[str] = []
        wildcard_abuses: List[str] = []

        files_to_inspect: List[str] = []
        if os.path.isfile("/etc/crontab"):
            files_to_inspect.append("/etc/crontab")

        for directory in CRON_DIRS:
            if os.path.isdir(directory):
                if self._is_user_writable(directory):
                    writable_cron_files.append(f"Directory: {directory}")
                try:
                    for entry in os.listdir(directory):
                        full_path = os.path.join(directory, entry)
                        if os.path.isfile(full_path):
                            files_to_inspect.append(full_path)
                except PermissionError:
                    continue

        for cron_file in files_to_inspect:
            if self._is_user_writable(cron_file):
                writable_cron_files.append(f"File: {cron_file}")

            try:
                with open(cron_file, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        if "*" in line:
                            for cmd in WILDCARD_COMMANDS:
                                if re.search(rf"\b{cmd}\b", line):
                                    wildcard_abuses.append(f"{cron_file} -> '{line}' (Vulnerable to {cmd} wildcard injection)")

                        for script in self._extract_executables(line):
                            if self._is_user_writable(script):
                                writable_cron_scripts.append(f"{script} (referenced in {cron_file})")
            except PermissionError:
                continue

        if writable_cron_files:
            results.append(
                CheckResult(
                    title="Writable Cron Job Definition Files/Dirs",
                    severity=Severity.CRITICAL,
                    description="Unprivileged users can modify or plant new cron definitions executed as root.",
                    findings=writable_cron_files,
                    remediation="Change cron file/dir ownership to root:root and restrict write permissions.",
                )
            )

        if writable_cron_scripts:
            results.append(
                CheckResult(
                    title="Writable Executables Run by Cron",
                    severity=Severity.CRITICAL,
                    description="Scheduled tasks execute scripts that can be rewritten by unprivileged users.",
                    findings=writable_cron_scripts,
                    remediation="Set script ownership to root:root and permissions to 0755 or 0700.",
                )
            )

        if wildcard_abuses:
            results.append(
                CheckResult(
                    title="Wildcard Injection Pattern in Cron",
                    severity=Severity.HIGH,
                    description="Cron runs commands using wildcards (*) with tools vulnerable to argument injection.",
                    findings=wildcard_abuses,
                    remediation="Avoid '*' expansion in scheduled commands; pass explicit file lists or wrapper scripts.",
                )
            )

        return results
