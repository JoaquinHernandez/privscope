"""Audit PATH environment variable for hijacking vectors and writable directories."""

import os
from typing import List
from privscope.checks.base import BaseCheck, CheckResult, Severity

STANDARD_SYSTEM_PATHS = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}


class PathCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "PATH Environment & Hijacking Audit"

    def run(self) -> List[CheckResult]:
        results = []
        raw_path = os.environ.get("PATH", "")

        if not raw_path:
            return [
                CheckResult(
                    title="PATH Variable Empty or Missing",
                    severity=Severity.MEDIUM,
                    description="The PATH variable is not defined in the current shell environment.",
                    findings=[],
                )
            ]

        relative_findings = []
        if "::" in raw_path or raw_path.startswith(":") or raw_path.endswith(":"):
            relative_findings.append("PATH contains empty elements (evaluates to current working directory '.')")

        path_elements = raw_path.split(":")
        writable_path_dirs = []
        preempting_dirs = []

        standard_seen = False

        for idx, directory in enumerate(path_elements):
            if directory == "." or not os.path.isabs(directory):
                relative_findings.append(f"Relative entry at index {idx}: '{directory}'")
                continue

            if directory in STANDARD_SYSTEM_PATHS:
                standard_seen = True

            if os.path.isdir(directory):
                if os.access(directory, os.W_OK) and (os.getuid() != 0):
                    writable_path_dirs.append(directory)
                    if not standard_seen:
                        preempting_dirs.append(directory)

        if relative_findings:
            results.append(
                CheckResult(
                    title="Insecure Relative Entries in PATH",
                    severity=Severity.HIGH,
                    description="Current working directory is implicitly or explicitly evaluated in PATH.",
                    findings=relative_findings,
                    remediation="Remove '.' and empty colon entries ('::') from PATH configurations.",
                )
            )

        if preempting_dirs:
            results.append(
                CheckResult(
                    title="Writable Directories Preempt System Binaries in PATH",
                    severity=Severity.CRITICAL,
                    description="Writable directories appear before /usr/bin or /bin, allowing trojanized binary injection.",
                    findings=preempting_dirs,
                    remediation="Ensure system directories appear first in PATH and remove write permissions from custom PATH folders.",
                )
            )
        elif writable_path_dirs:
            results.append(
                CheckResult(
                    title="Writable Directories in PATH",
                    severity=Severity.MEDIUM,
                    description="Directories located in PATH are writable by the current user.",
                    findings=writable_path_dirs,
                    remediation="Restrict PATH directory permissions using: `chmod 755 <directory>`.",
                )
            )

        return results
