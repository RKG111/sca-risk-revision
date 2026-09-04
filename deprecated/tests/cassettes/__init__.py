"""
Recorded probe evidence, for offline deterministic tests.

An agent-only pipeline has no reproducible code path to compare against, so the
evidence a real run produced is recorded once and replayed. Tests then assert on
policy and scoring, which *are* deterministic given fixed evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.models import (
    DeploymentFinding,
    EvidenceSet,
    ExploitPath,
    MisconfigurationFinding,
    PathMitigationResult,
    ProbeId,
)

_DIR = Path(__file__).parent


def load_recorded_evidence(name: str) -> EvidenceSet:
    """Build an EvidenceSet from a recorded cassette."""
    raw = json.loads((_DIR / f"{name}.json").read_text(encoding="utf-8"))

    exploit = raw.get("s1") or {}
    misconfig = raw.get("s2") or {}
    deployment = raw.get("s3") or {}
    mitigation = raw.get("s4") or {}

    evidence = EvidenceSet(
        exploit_paths=[ExploitPath.model_validate(p) for p in exploit.get("exploit_paths", [])],
        misconfigurations=[
            MisconfigurationFinding.model_validate(f)
            for f in misconfig.get("misconfigurations", [])
        ],
        deployment_findings=[
            DeploymentFinding.model_validate(f) for f in deployment.get("deployment_findings", [])
        ],
        mitigations=[
            PathMitigationResult.model_validate(m)
            for m in mitigation.get("mitigations_by_path", [])
        ],
        applicability_falsified=bool(deployment.get("applicability_falsified", False)),
    )

    for key, probe in (
        ("s1", ProbeId.EXPLOIT_PATH),
        ("s2", ProbeId.MISCONFIG),
        ("s3", ProbeId.DEPLOYMENT),
        ("s4", ProbeId.MITIGATION),
    ):
        section = raw.get(key)
        if section is None:
            continue
        evidence.ran.append(probe)
        if section.get("notes"):
            evidence.notes[probe.value] = section["notes"]

    return evidence
