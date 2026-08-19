"""Test cases for PrivScope check logic and parsers."""

import os
import unittest
from privscope.checks.base import CheckResult, Severity
from privscope.checks.kernel import KernelCheck, KNOWN_KERNEL_VULNS
from privscope.checks.path import PathCheck


class TestSeverityFiltering(unittest.TestCase):
    def test_severity_ordering(self):
        self.assertTrue(Severity.is_gte(Severity.CRITICAL, Severity.HIGH))
        self.assertTrue(Severity.is_gte(Severity.HIGH, Severity.LOW))
        self.assertTrue(Severity.is_gte(Severity.INFO, Severity.INFO))
        self.assertFalse(Severity.is_gte(Severity.LOW, Severity.CRITICAL))


class TestKernelCheck(unittest.TestCase):
    def setUp(self):
        self.checker = KernelCheck()

    def test_kernel_version_parsing(self):
        self.assertEqual(self.checker._parse_version("5.15.0-101-generic"), (5, 15, 0))
        self.assertEqual(self.checker._parse_version("6.8.0"), (6, 8, 0))
        self.assertEqual(self.checker._parse_version("4.19.232"), (4, 19, 232))

    def test_dirty_pipe_logic(self):
        dirty_pipe = next(v for v in KNOWN_KERNEL_VULNS if v.cve == "CVE-2022-0847")
        vulnerable_ver = (5, 10, 0)
        patched_ver = (5, 16, 12)
        
        self.assertTrue(dirty_pipe.min_ver <= vulnerable_ver < dirty_pipe.max_fixed)
        self.assertFalse(dirty_pipe.min_ver <= patched_ver < dirty_pipe.max_fixed)


class TestPathCheck(unittest.TestCase):
    def setUp(self):
        self.checker = PathCheck()

    def test_relative_path_detection(self):
        original_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = "/usr/bin:/bin:.:/usr/local/bin"
            results = self.checker.run()
            has_relative_finding = any("Insecure Relative Entries" in r.title for r in results)
            self.assertTrue(has_relative_finding)
        finally:
            os.environ["PATH"] = original_path


if __name__ == "__main__":
    unittest.main()
