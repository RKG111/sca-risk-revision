"""
Shared test fixtures.

The suite runs fully offline. Anything needing Ollama / Joern / MCP must be
marked `@pytest.mark.live` and is deselected unless explicitly requested.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Pin config before any module imports `settings`, so tests never depend on a
# developer's local .env.
os.environ.setdefault("CODEBASE_ROOT", str(ROOT))
os.environ.setdefault("BLUEPRINT_STORE_PATH", str(ROOT / "blueprints"))
os.environ.setdefault("JOERN_WORKSPACE_PATH", "")
os.environ.setdefault("SCAN_OUTPUT_DIR", str(ROOT / "tests" / "results" / "runs"))


BASELINE_CVE = "CVE-2020-14343"


@pytest.fixture(autouse=True)
def _isolate_scan_output(tmp_path, monkeypatch):
    """Keep per-scan artefacts out of the repo during tests."""
    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("SCAN_OUTPUT_DIR", str(runs))
    from core.config import settings

    monkeypatch.setattr(settings, "scan_output_dir", str(runs))
    return runs


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def sample_codebase() -> Path:
    return ROOT / "tests" / "fixtures" / "sample_project"


@pytest.fixture(scope="session")
def sample_sbom_dict() -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / "sample.sbom.json").read_text())


@pytest.fixture(scope="session")
def blueprint_dir() -> Path:
    return ROOT / "blueprints"


@pytest.fixture(scope="session")
def baseline_cve() -> str:
    return BASELINE_CVE


def pytest_collection_modifyitems(config, items):
    """Deselect `live` tests unless -m live was passed explicitly."""
    if "live" in (config.getoption("-m") or ""):
        return
    skip_live = pytest.mark.skip(reason="needs a running stack; run with -m live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
