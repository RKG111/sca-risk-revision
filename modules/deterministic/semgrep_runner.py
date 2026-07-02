"""
Module 3 — Semgrep Runner

Executes Semgrep rules against the target codebase to verify
deterministic blueprint conditions (CWE-89, CWE-327, CWE-798, CWE-1104, etc.)

Semgrep is invoked as a subprocess with JSON output.
Rules can be:
  1. Auto-generated from blueprint indicators (simple pattern rules)
  2. From the Semgrep registry (semgrep --config=auto)
  3. Custom YAML rules written per CVE
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class SemgrepFinding(dict):
    """A single Semgrep match result."""

    @property
    def file(self) -> str:
        return self.get("path", "")

    @property
    def line(self) -> int:
        return self.get("start", {}).get("line", 0)

    @property
    def message(self) -> str:
        return self.get("extra", {}).get("message", "")

    @property
    def rule_id(self) -> str:
        return self.get("check_id", "")


class SemgrepRunner:
    """
    Wraps the semgrep CLI to run targeted scans.
    """

    def scan_with_pattern(
        self,
        codebase_path: Path,
        pattern: str,
        language: str = "python",
    ) -> list[SemgrepFinding]:
        """
        Runs a single inline pattern scan.
        Useful for checking presence of an indicator string or call pattern.

        Example:
            runner.scan_with_pattern(path, "yaml.load(...)", "python")
        """
        cmd = [
            "semgrep",
            "--pattern", pattern,
            "--lang", language,
            "--json",
            "--quiet",
            str(codebase_path),
        ]
        return self._run(cmd)

    def scan_with_rule_file(
        self,
        codebase_path: Path,
        rule_path: Path,
    ) -> list[SemgrepFinding]:
        """Runs a full Semgrep rule YAML file against the codebase."""
        cmd = [
            "semgrep",
            "--config", str(rule_path),
            "--json",
            "--quiet",
            str(codebase_path),
        ]
        return self._run(cmd)

    def scan_with_inline_rule(
        self,
        codebase_path: Path,
        rule: dict[str, Any],
    ) -> list[SemgrepFinding]:
        """
        Writes a rule dict to a temp YAML file and runs it.
        Use this to dynamically generate rules from blueprint indicators.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as f:
            yaml.dump({"rules": [rule]}, f)
            temp_path = Path(f.name)

        try:
            return self.scan_with_rule_file(codebase_path, temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def build_import_check_rule(self, package_name: str, cve_id: str) -> dict[str, Any]:
        """
        Generates a Semgrep rule that checks if a vulnerable package is imported.
        Used for CWE-1104 (dependency reachability).
        """
        return {
            "id": f"check-import-{cve_id.lower().replace('-', '_')}",
            "patterns": [
                {"pattern": f"import {package_name}"},
            ],
            "message": f"Package {package_name} is imported ({cve_id})",
            "languages": ["python"],
            "severity": "WARNING",
        }

    def build_call_check_rule(self, symbol: str, cve_id: str) -> dict[str, Any]:
        """
        Generates a rule that detects calls to a vulnerable function/method.
        Used to verify the vulnerable_symbol is actually invoked.
        """
        return {
            "id": f"check-call-{cve_id.lower().replace('-', '_')}",
            "pattern": f"{symbol}(...)",
            "message": f"Call to vulnerable symbol {symbol} ({cve_id})",
            "languages": ["python"],
            "severity": "ERROR",
        }

    def _run(self, cmd: list[str]) -> list[SemgrepFinding]:
        logger.debug("Running: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode not in (0, 1):
            logger.error("Semgrep error (exit %d): %s", result.returncode, result.stderr)
            return []

        try:
            output = json.loads(result.stdout)
            findings = [SemgrepFinding(f) for f in output.get("results", [])]
            logger.info("Semgrep: %d finding(s)", len(findings))
            return findings
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output: %s", result.stdout[:200])
            return []
