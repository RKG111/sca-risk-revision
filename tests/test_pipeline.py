"""
Pipeline tests: probe orchestration, evidence gaps, and end-to-end assessment.

Joern and MCP are stubbed out, so these run offline. The model is scripted per
probe, which is what makes an agent-only pipeline testable at all.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import pytest

from core import pipeline
from core.errors import BlueprintNotFound, CoreError
from core.models import (
    ActivationState,
    CycloneDXSBOM,
    ProbeId,
    Severity,
)
from core.policy import plan
from core.probes import PROBES
from tests.fake_llm import ProbeScriptedChatModel
from tests.test_policy import blueprint as make_blueprint

S1_PAYLOAD = json.dumps(
    {
        "exploit_paths": [
            {
                "path_id": "path-1",
                "sink": "yaml.full_load",
                "summary": "handler passes body to yaml.full_load",
                "steps": [{"file": "app.py", "line": 13, "symbol": "yaml.full_load"}],
                "confidence": 0.9,
                "reachable": True,
            }
        ],
        "notes": "one path",
    }
)
S2_PAYLOAD = json.dumps(
    {
        "misconfigurations": [
            {
                "finding_id": "miscfg-1",
                "description": "FullLoader in use",
                "evidence": "app.py:18",
                "relevant_to_cve": True,
                "location": "app.py:18",
                "confidence": 0.8,
            }
        ],
        "notes": "one finding",
    }
)
S3_PAYLOAD = json.dumps(
    {
        "deployment_findings": [
            {
                "finding_id": "deploy-1",
                "condition_type": "network_access",
                "description": "public HTTP handler",
                "product_value": "http",
                "applies": True,
                "network_exposed": True,
                "evidence": "app.py:10",
                "confidence": 0.7,
            }
        ],
        "applicability_falsified": False,
        "notes": "exposed",
    }
)
S4_PAYLOAD = json.dumps(
    {
        "mitigations_by_path": [
            {
                "path_id": "path-1",
                "mitigation_description": "upgrade to 5.4",
                "present": False,
                "strength": "none",
                "evidence": "Not found",
                "confidence": 0.6,
            }
        ],
        "notes": "unmitigated",
    }
)

ALL_PAYLOADS = {"S1": S1_PAYLOAD, "S2": S2_PAYLOAD, "S3": S3_PAYLOAD, "S4": S4_PAYLOAD}


@pytest.fixture
def offline(monkeypatch):
    """Stub the Joern CPG and the MCP toolbelt so gather() runs offline."""

    @asynccontextmanager
    async def no_cpg_tools():
        yield []

    async def no_index(_path):
        return None

    monkeypatch.setattr(pipeline, "joern_mcp_tools", no_cpg_tools)
    monkeypatch.setattr(pipeline, "_try_index", no_index)


class TestWaves:
    def test_independent_probes_share_one_wave(self):
        waves = pipeline._waves([ProbeId.EXPLOIT_PATH, ProbeId.MISCONFIG, ProbeId.DEPLOYMENT])
        assert len(waves) == 1

    def test_a_dependent_probe_waits_for_its_prerequisite(self):
        waves = pipeline._waves([ProbeId.MITIGATION, ProbeId.EXPLOIT_PATH])
        assert waves == [[ProbeId.EXPLOIT_PATH], [ProbeId.MITIGATION]]

    def test_every_probe_is_scheduled_exactly_once(self):
        requested = list(PROBES)
        scheduled = [probe for wave in pipeline._waves(requested) for probe in wave]
        assert sorted(scheduled, key=lambda p: p.value) == sorted(requested, key=lambda p: p.value)

    def test_dropping_a_probe_drops_its_dependents(self):
        remaining = pipeline._without(
            [ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION, ProbeId.MISCONFIG], ProbeId.EXPLOIT_PATH
        )
        assert remaining == [ProbeId.MISCONFIG]


class TestGather:
    async def test_runs_the_planned_probes_and_collects_evidence(self, offline, sample_codebase):
        blueprint = make_blueprint(sinks=["yaml.full_load"])
        model = ProbeScriptedChatModel(payloads=ALL_PAYLOADS)

        evidence = await pipeline.gather(
            blueprint=blueprint,
            plan=plan(blueprint),
            codebase_path=sample_codebase,
            model=model,
        )

        assert evidence.ran == [ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION]
        assert len(evidence.exploit_paths) == 1
        assert len(evidence.mitigations) == 1
        assert evidence.gaps == []

    async def test_a_failing_probe_becomes_a_gap_not_a_silent_pass(
        self, offline, sample_codebase
    ):
        blueprint = make_blueprint(sinks=["yaml.full_load"])
        # S1 answers with unusable prose, so S4 has nothing to work from.
        model = ProbeScriptedChatModel(payloads={"S1": "not json", "S4": S4_PAYLOAD})

        evidence = await pipeline.gather(
            blueprint=blueprint,
            plan=plan(blueprint),
            codebase_path=sample_codebase,
            model=model,
        )

        gaps = {gap.probe: gap.reason for gap in evidence.gaps}
        assert ProbeId.EXPLOIT_PATH in gaps
        assert ProbeId.MITIGATION in gaps
        assert evidence.ran == []

    async def test_a_dependent_probe_is_skipped_when_there_is_nothing_to_check(
        self, offline, sample_codebase
    ):
        blueprint = make_blueprint(sinks=["yaml.full_load"])
        empty_s1 = json.dumps({"exploit_paths": [], "notes": "no call sites"})
        model = ProbeScriptedChatModel(payloads={"S1": empty_s1, "S4": S4_PAYLOAD})

        evidence = await pipeline.gather(
            blueprint=blueprint,
            plan=plan(blueprint),
            codebase_path=sample_codebase,
            model=model,
        )

        assert evidence.ran == [ProbeId.EXPLOIT_PATH]
        assert [gap.probe for gap in evidence.gaps] == [ProbeId.MITIGATION]

    async def test_an_unknown_basis_runs_nothing(self, offline, sample_codebase):
        blueprint = make_blueprint()
        evidence = await pipeline.gather(
            blueprint=blueprint,
            plan=plan(blueprint),
            codebase_path=sample_codebase,
            model=ProbeScriptedChatModel(payloads=ALL_PAYLOADS),
        )
        assert evidence.ran == []
        assert evidence.exploit_paths == []


class TestAssess:
    def _sbom(self, purl: str = "pkg:pypi/pyyaml@5.3.1") -> CycloneDXSBOM:
        return CycloneDXSBOM.model_validate(
            {
                "components": [
                    {"bom-ref": "c1", "name": "pyyaml", "version": "5.3.1", "purl": purl}
                ],
                "vulnerabilities": [
                    {"id": "CVE-2020-14343", "affects": [{"ref": "c1"}]}
                ],
            }
        )

    async def test_full_assessment_with_scripted_agents(self, offline, sample_codebase):
        report = await pipeline.assess(
            sbom=self._sbom(),
            cve_id="CVE-2020-14343",
            codebase_path=sample_codebase,
            model=ProbeScriptedChatModel(payloads=ALL_PAYLOADS),
        )

        assert report.verdict.activation_state is ActivationState.ACTIVATED
        assert report.exploitable is True
        assert report.score == 9.8
        assert report.severity is Severity.CRITICAL
        assert report.environmental_vector.startswith(report.original_base_vector)
        assert report.score_delta == 0.0

    async def test_a_mitigated_finding_scores_zero(self, offline, sample_codebase):
        mitigated = json.dumps(
            {
                "mitigations_by_path": [
                    {
                        "path_id": "path-1",
                        "mitigation_description": "upgraded to 5.4",
                        "present": True,
                        "strength": "high",
                        "evidence": "requirements.txt: pyyaml==5.4",
                        "confidence": 0.9,
                    }
                ],
                "notes": "mitigated",
            }
        )
        report = await pipeline.assess(
            sbom=self._sbom(),
            cve_id="CVE-2020-14343",
            codebase_path=sample_codebase,
            model=ProbeScriptedChatModel(payloads={**ALL_PAYLOADS, "S4": mitigated}),
        )

        assert report.verdict.fully_mitigated is True
        assert report.exploitable is False
        assert report.score == 0.0
        assert report.severity is Severity.NONE
        invariants = {a.metric for a in report.metric_answers if a.source.value == "invariant"}
        assert invariants == {"MC", "MI", "MA"}

    async def test_an_sbom_that_does_not_name_the_component_is_rejected(self, sample_codebase):
        sbom = CycloneDXSBOM.model_validate({"components": [], "vulnerabilities": []})
        with pytest.raises(CoreError, match="does not say which component"):
            await pipeline.assess(
                sbom=sbom, cve_id="CVE-2020-14343", codebase_path=sample_codebase
            )

    async def test_a_missing_blueprint_is_rejected(self, sample_codebase):
        with pytest.raises(BlueprintNotFound):
            await pipeline.assess(
                sbom=self._sbom("pkg:pypi/pyyaml@9.9.9"),
                cve_id="CVE-2020-14343",
                codebase_path=sample_codebase,
            )
