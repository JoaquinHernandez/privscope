# privscope
<div align="center">

# 🛡️ PrivScope

**A Modular, Zero-Dependency Linux Privilege Escalation & System Hardening Engine**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20POSIX-E95420.svg?style=flat-square&logo=linux&logoColor=white)]()
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg?style=flat-square)](https://github.com/astral-sh/ruff)
[![Tests: Passing](https://img.shields.io/badge/tests-passing-brightgreen.svg?style=flat-square&logo=githubactions&logoColor=white)]()

*PrivScope performs deep, non-destructive privilege escalation enumeration and security compliance checks on Linux endpoints using only Python standard library components.*

[Key Features](#-key-features) • [Quick Start](#-quick-start) • [Audit Modules](#-audit-modules--threat-coverage) • [CLI Reference](#-cli-reference) • [CI/CD & JSON Export](#-cicd-pipeline--json-export) • [Docker Testbed](#-docker-testbed-safe-testing) • [Contributing](#-contributing)

---

</div>

## 📌 Executive Summary

**PrivScope** bridges the gap between offensive enumeration scripts (like LinPEAS / LinEnum) and enterprise security auditing tools (like Lynis). 

When auditing minimal Linux environments—such as stripped-down container base images, CTF challenge boxes, restricted bastion hosts, or hardened servers—external dependencies like compiler toolchains, package managers, or `pip` modules are rarely available.

PrivScope solves this by operating under a strict constraint: **Zero Third-Party Dependencies**. It runs natively using standard library Python 3 (`os`, `platform`, `subprocess`, `shlex`, `re`) while providing structured, colorized terminal reporting and machine-readable JSON exports.

---

## 🚀 Key Features

* ⚡ **Zero Third-Party Dependencies:** Requires only standard Python $\ge$ 3.8. No `pip install` or external packages required.
* 🎯 **GTFOBins Signature Correlation:** Cross-references active SUID/SGID binaries directly against known binary bypass and escalation patterns.
* 🧬 **Semantic Kernel CVE Matching:** Parses kernel release numbers against unpatched Local Privilege Escalation (LPE) boundaries (e.g., Dirty Pipe, Dirty COW, Netfilter UAF).
* ⚙️ **Process & File Capabilities:** Scans for dangerous binary capabilities (`cap_setuid`, `cap_dac_override`) and inspects inherited process capability masks (`CapEff`).
* ⏰ **Cron & Wildcard Abuse Detection:** Flags writable cron jobs, modifiable script targets, and argument injection patterns (`*` wildcards with `tar`, `rsync`, etc.).
* 🛤️ **PATH Environment Integrity:** Detects empty entries (`::`), relative search directories (`.`), and high-priority writable paths that allow command hijacking.
* 🛡️ **Actionable Remediation Commands:** Every finding provides exact shell commands to patch and harden the target system.

---

## 📥 Quick Start

### Method 1: Clone & Run Locally

```bash
# Clone the repository
git clone [https://github.com/yourusername/privscope.git](https://github.com/yourusername/privscope.git)
cd privscope

# Execute the audit runner
python3 -m privscope.cli

python3 -m privscope.cli --json > audit_results.json

[
  {
    "title": "High-Risk File Capabilities Detected",
    "severity": "CRITICAL",
    "description": "Binaries have elevated capabilities enabled that can lead to direct privilege escalation.",
    "findings": [
      "/usr/bin/python3.10 [cap_setuid=ep] -> Allows changing UID arbitrarily (instant root shell via scripting runtimes)."
    ],
    "remediation": "Remove capabilities with: `setcap -r <path>` or restrict execution permissions."
  }
]

# Build and spin up the intentionally misconfigured test environment
docker build -t privscope-testbed tests/docker/
docker run --rm -it privscope-testbed

Legal & Disclaimer
Disclaimer: PrivScope is developed strictly for educational purposes, authorized penetration testing, security auditing, and defensive system hardening. Running this tool against environments without prior written authorization is strictly prohibited. The authors assume no liability for misuse or damage caused by this software.
