"""Audit Linux file and process capabilities for elevation vectors."""

import os
import shutil
import subprocess
from typing import Dict, List
from privscope.checks.base import BaseCheck, CheckResult, Severity

DANGEROUS_CAPABILITIES: Dict[str, str] = {
    "cap_setuid": "Allows changing process UID arbitrarily (instant root shell via scripting engines).",
    "cap_setgid": "Allows changing process GID arbitrarily (impersonate groups like shadow/sudo).",
    "cap_dac_override": "Bypasses all file read, write, and execute permission checks.",
    "cap_dac_read_search": "Bypasses all file read and directory traversal checks.",
    "cap_sys_ptrace": "Allows arbitrary process debugging and memory code injection.",
    "cap_sys_admin": "Grants wide-ranging administrative calls and container escape vectors.",
    "cap_sys_module": "Allows direct loading and unloading of kernel modules.",
    "cap_chown": "Allows arbitrary file ownership changes.",
    "cap_fowner": "Bypasses file permission checks on operations requiring file ownership.",
}

TARGET_DIRS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"]


class CapabilitiesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Linux Capabilities Audit"

    def _get_file_caps(self) -> List[str]:
        if not shutil.which("getcap"):
            return []

        existing_dirs = [d for d in TARGET_DIRS if os.path.isdir(d)]
        if not existing_dirs:
            return []

        try:
            cmd = ["getcap", "-r"] + existing_dirs
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _get_process_effective_caps(self) -> str:
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        return line.split(":")[1].strip()
        except IOError:
            pass
        return ""

    def run(self) -> List[CheckResult]:
        results = []
        raw_caps = self._get_file_caps()

        critical_findings = []
        info_findings = []

        for entry in raw_caps:
            parts = entry.split()
            if len(parts) < 2:
                continue

            filepath = parts[0]
            cap_string = parts[1].lower()

            matched = False
            for cap, reason in DANGEROUS_CAPABILITIES.items():
                if cap in cap_string:
                    critical_findings.append(f"{filepath} [{cap_string}] -> {reason}")
                    matched = True
                    break

            if not matched:
                info_findings.append(entry)

        if critical_findings:
            results.append(
                CheckResult(
                    title="High-Risk File Capabilities Detected",
                    severity=Severity.CRITICAL,
                    description="Binaries have elevated capabilities enabled that can bypass security boundaries.",
                    findings=critical_findings,
                    remediation="Remove capabilities using: `setcap -r <path>`.",
                )
            )

        if info_findings:
            results.append(
                CheckResult(
                    title="Standard File Capabilities Present",
                    severity=Severity.INFO,
                    description="Capabilities configured on standard system utilities.",
                    findings=info_findings[:10],
                )
            )

        capeff = self._get_process_effective_caps()
        if capeff and capeff != "0000000000000000":
            results.append(
                CheckResult(
                    title="Active Process Possesses Effective Capabilities",
                    severity=Severity.MEDIUM,
                    description="Current process inherited non-zero capability masks (possible privileged container).",
                    findings=[f"CapEff Mask: {capeff}"],
                    remediation="Decode mask via `capsh --decode={capeff}` to evaluate exposed privileges.",
                )
            )

        return results
