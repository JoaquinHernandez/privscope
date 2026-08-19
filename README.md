# privscope
____       _       ____                       
 |  _ \ _ __(_)_   _/ ___|  ___ ___  _ __   ___ 
 | |_) | '__| \ \ / /\___ \ / __/ _ \| '_ \ / _ \
 |  __/| |  | |\ V /  ___) | (_| (_) | |_) |  __/
 |_|   |_|  |_| \_/  |____/ \___\___/| .__/ \___|
                                     |_|         
 :: Linux Misconfiguration & PrivEsc Vector Auditor ::

[CRITICAL] Dangerous SUID Binaries Found
  SUID binaries detected that allow arbitrary file read/write or root shell execution.
  -> /usr/bin/find (Known GTFOBins exploit vector)
  Remediation: Remove the SUID bit: `chmod u-s <path>` if elevated execution is not strictly required.
------------------------------------------------------------
[HIGH] Wildcard Injection in Scheduled Jobs
  Cron commands use '*' wildcards with tools that support dangerous CLI flags.
  -> /etc/crontab -> 'tar -czf /var/backups/backup.tar.gz *' (Vulnerable to tar argument injection)
  Remediation: Avoid '*' expansions in cron commands; use explicit file paths or write wrapper scripts.
------------------------------------------------------------

privscope/
├── .github/
│   └── workflows/
│       └── lint-and-test.yml    # Automated CI tests
├── docs/
│   └── architecture.md
├── privscope/
│   ├── __init__.py
│   ├── cli.py                   # Argument parsing & execution flow
│   ├── output.py                # Terminal formatting & JSON exporter
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py              # Abstract check base class
│   │   ├── sudo.py              # Sudo rules & NOPASSWD checks
│   │   ├── suid.py              # SUID/SGID binaries & GTFOBins match
│   │   ├── capabilities.py      # Linux capabilities inspection
│   │   ├── cron.py              # Writable cron jobs & path injection
│   │   └── permissions.py       # Sensitive world-writable files (/etc/passwd, etc.)
│   └── data/
│       └── gtfobins.json        # Curated list of known dangerous binaries
├── tests/
│   └── test_checks.py
├── .gitignore
├── LICENSE                      # MIT or Apache 2.0
├── pyproject.toml
└── README.md                    # Detailed documentation with badges and GIF demo

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
