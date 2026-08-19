"""Audit SUID and SGID executables against GTFOBins exploitation vectors."""

import os
import subprocess
from typing import List
from privscope.checks.base import BaseCheck, CheckResult, Severity

KNOWN_GTFOBINS = {
    "aria2c", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown",
    "cp", "csh", "curl", "cut", "dash", "date", "dd", "diff", "dmsetup",
    "docker", "env", "find", "flock", "fmt", "gawk", "gdb", "grep", "head",
    "ionice", "jq", "ksh", "ld.so", "less", "logsave", "lua", "make", "more",
    "mv", "nano", "nmap", "node", "nohup", "openssl", "perl", "php", "pkexec",
    "python", "python3", "ruby", "sed", "setfacl", "sh", "socat", "sort",
    "sqlite3", "strace", "systemctl", "tar", "taskset", "tclsh", "tee",
    "time", "timeout", "ul", "unshare", "vi", "vim", "watch", "wget", "xargs",
    "xxd", "zip", "zsh"
}


class SUIDCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "SUID / SGID Audit"

    def run(self) -> List[CheckResult]:
        results = []
        suid_binaries = []

        try:
            cmd = ["find", "/", "-perm", "-4000", "-type", "f", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            suid_binaries = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception as e:
            return [
                CheckResult(
                    title="SUID Scan Execution Failed",
                    severity=Severity.INFO,
                    description="Could not complete filesystem SUID search.",
                    findings=[str(e)],
                )
            ]

        gtfo_matches = []
        for path in suid_binaries:
            binary_name = os.path.basename(path)
            if binary_name in KNOWN_GTFOBINS:
                gtfo_matches.append(f"{path} (GTFOBins exploitation vector)")

        if gtfo_matches:
            results.append(
                CheckResult(
                    title="Exploitable SUID Binaries Found",
                    severity=Severity.CRITICAL,
                    description="Binaries with the SUID bit set match known GTFOBins bypass vectors.",
                    findings=gtfo_matches,
                    remediation="Remove SUID bit if not strictly required: `chmod u-s <binary_path>`.",
                )
            )
        elif suid_binaries:
            results.append(
                CheckResult(
                    title="Standard SUID Executables Detected",
                    severity=Severity.INFO,
                    description="Standard system SUID binaries detected with no direct default GTFOBins vector.",
                    findings=suid_binaries[:15],
                )
            )

        return results
