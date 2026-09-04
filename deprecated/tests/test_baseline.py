"""
Golden baseline — pins the decision the pipeline reaches for the sample project.

Captured from the pre-rebuild pipeline and re-asserted against the new `core`
pipeline, so the rebuild is provably behaviour-preserving on the fixture.
Regenerate deliberately with REWRITE_GOLDEN=1 when a decision change is intended.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.snapshot import stable_snapshot

GOLDEN = Path(__file__).parent / "golden" / "baseline_verdict.json"


def _assert_matches_golden(snapshot: dict) -> None:
    if os.environ.get("REWRITE_GOLDEN") == "1" or not GOLDEN.is_file():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
        pytest.skip(f"golden written to {GOLDEN}; re-run to assert against it")

    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert snapshot == expected


async def test_core_pipeline_matches_golden(sample_codebase, sample_sbom_dict, baseline_cve):
    """The rebuilt core reaches the same decision as the pipeline it replaces."""
    from core.models import CycloneDXSBOM
    from core.pipeline import assess

    sbom = CycloneDXSBOM.model_validate(sample_sbom_dict)
    report = await assess(
        sbom=sbom,
        cve_id=baseline_cve,
        codebase_path=sample_codebase,
        evidence=_recorded_evidence(),
    )
    _assert_matches_golden(stable_snapshot(report))


def _recorded_evidence():
    """Replay the recorded probe evidence instead of calling live agents."""
    from tests.cassettes import load_recorded_evidence

    return load_recorded_evidence("baseline")
