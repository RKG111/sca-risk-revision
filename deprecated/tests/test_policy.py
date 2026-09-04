"""
Policy is the only place risk decisions are made, so this is where the rules
are pinned. Every test here runs offline on hand-built evidence.
"""

from __future__ import annotations

import pytest

from core.models import (
    ActivationBasis,
    ActivationState,
    Blueprint,
    BlueprintCondition,
    BlueprintCVSS,
    ConditionType,
    DeploymentFinding,
    EvidenceSet,
    ExploitPath,
    MisconfigurationFinding,
    MitigationStrength,
    PathMitigationResult,
    ProbeId,
)
from core.policy import clamps, decide, impact_is_impossible, plan

BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def blueprint(
    *,
    sinks: list[str] | None = None,
    conditions: list[ConditionType] | None = None,
    cwe_ids: list[str] | None = None,
    exploit_type: str = "",
) -> Blueprint:
    return Blueprint(
        cve_id="CVE-0000-0000",
        cvss=BlueprintCVSS(score=9.8, vector=BASE_VECTOR),
        affected_components=[{"name": "thing", "purl": "pkg:pypi/thing@1.0.0"}],
        cwe_ids=cwe_ids or [],
        exploit_type=exploit_type,
        conditions=[
            BlueprintCondition(type=condition, value="x") for condition in (conditions or [])
        ],
        upstream_artifacts={"functions": sinks or []},
    )


def path(path_id: str = "path-1", sink: str = "danger") -> ExploitPath:
    return ExploitPath(path_id=path_id, sink=sink, summary="s")


# ─── planning ────────────────────────────────────────────────────────────────


class TestPlan:
    def test_sinks_alone_mean_invocation(self):
        result = plan(blueprint(sinks=["yaml.full_load"]))
        assert result.activation_basis is ActivationBasis.INVOCATION
        assert result.probes == [ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION]
        assert result.sink_gate is True

    def test_sinks_plus_config_mean_hybrid(self):
        result = plan(
            blueprint(
                sinks=["yaml.full_load"],
                conditions=[ConditionType.CONFIGURATION_REQUIREMENT],
            )
        )
        assert result.activation_basis is ActivationBasis.HYBRID
        assert set(result.probes) == {ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION, ProbeId.MISCONFIG}

    def test_config_without_sinks_means_configuration(self):
        result = plan(blueprint(conditions=[ConditionType.CONFIGURATION_REQUIREMENT]))
        assert result.activation_basis is ActivationBasis.CONFIGURATION
        assert result.probes == [ProbeId.MISCONFIG]
        assert result.sink_gate is False

    def test_deployment_conditions_add_the_deployment_probe(self):
        result = plan(
            blueprint(sinks=["danger"], conditions=[ConditionType.NETWORK_ACCESS])
        )
        assert ProbeId.DEPLOYMENT in result.probes

    def test_malicious_package_means_inclusion(self):
        result = plan(blueprint(cwe_ids=["CWE-506"]))
        assert result.activation_basis is ActivationBasis.INCLUSION
        assert result.presence_check is True

    def test_malicious_exploit_type_means_inclusion(self):
        result = plan(blueprint(exploit_type="supply chain compromise with malicious payload"))
        assert result.activation_basis is ActivationBasis.INCLUSION
        assert result.presence_check is True
        assert result.probes == []

    def test_inclusion_with_deployment_conditions_still_runs_deployment(self):
        result = plan(
            blueprint(cwe_ids=["CWE-506"], conditions=[ConditionType.NETWORK_ACCESS])
        )
        assert result.activation_basis is ActivationBasis.INCLUSION
        assert result.presence_check is True
        assert result.probes == [ProbeId.DEPLOYMENT]

    def test_deployment_only_means_environment(self):
        result = plan(blueprint(conditions=[ConditionType.NETWORK_ACCESS]))
        assert result.activation_basis is ActivationBasis.ENVIRONMENT
        assert result.probes == [ProbeId.DEPLOYMENT]

    def test_hybrid_with_deployment_includes_all_needed_probes(self):
        result = plan(
            blueprint(
                sinks=["danger"],
                conditions=[
                    ConditionType.CONFIGURATION_REQUIREMENT,
                    ConditionType.NETWORK_ACCESS,
                ],
            )
        )
        assert result.activation_basis is ActivationBasis.HYBRID
        assert set(result.probes) == {
            ProbeId.EXPLOIT_PATH,
            ProbeId.MITIGATION,
            ProbeId.MISCONFIG,
            ProbeId.DEPLOYMENT,
        }

    def test_reachability_claim_without_sinks_is_unknown(self):
        """An incomplete blueprint must not be rescored on a guess."""
        result = plan(blueprint(conditions=[ConditionType.DEPENDENCY_REACHABILITY]))
        assert result.activation_basis is ActivationBasis.UNKNOWN
        assert result.probes == []
        assert result.skip_rescoring is True

    def test_empty_blueprint_is_unknown(self):
        assert plan(blueprint()).activation_basis is ActivationBasis.UNKNOWN


# ─── deciding ────────────────────────────────────────────────────────────────


class TestDecide:
    def test_invocation_with_paths_is_exploitable(self):
        verdict = decide(
            plan(blueprint(sinks=["danger"])),
            EvidenceSet(exploit_paths=[path()], ran=[ProbeId.EXPLOIT_PATH]),
        )
        assert verdict.activation_state is ActivationState.ACTIVATED
        assert verdict.exploitable is True
        assert verdict.unmitigated_path_count == 1

    def test_invocation_without_paths_is_not_activated(self):
        verdict = decide(
            plan(blueprint(sinks=["danger"])),
            EvidenceSet(ran=[ProbeId.EXPLOIT_PATH]),
        )
        assert verdict.activation_state is ActivationState.NOT_ACTIVATED
        assert verdict.exploitable is False

    def test_probe_that_never_ran_is_inconclusive_not_safe(self):
        """The core distinction of the rebuild: 'did not look' is not 'is safe'."""
        verdict = decide(plan(blueprint(sinks=["danger"])), EvidenceSet())
        assert verdict.activation_state is ActivationState.INCONCLUSIVE
        assert verdict.exploitable is False

    def test_high_strength_mitigation_on_every_path_removes_exploitability(self):
        evidence = EvidenceSet(
            exploit_paths=[path()],
            mitigations=[
                PathMitigationResult(
                    path_id="path-1",
                    mitigation_description="upgraded",
                    present=True,
                    strength=MitigationStrength.HIGH,
                )
            ],
            ran=[ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION],
        )
        verdict = decide(plan(blueprint(sinks=["danger"])), evidence)
        assert verdict.fully_mitigated is True
        assert verdict.exploitable is False

    def test_weak_mitigation_does_not_remove_exploitability(self):
        evidence = EvidenceSet(
            exploit_paths=[path()],
            mitigations=[
                PathMitigationResult(
                    path_id="path-1",
                    mitigation_description="documented workaround",
                    present=True,
                    strength=MitigationStrength.MEDIUM,
                )
            ],
            ran=[ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION],
        )
        verdict = decide(plan(blueprint(sinks=["danger"])), evidence)
        assert verdict.fully_mitigated is False
        assert verdict.exploitable is True

    def test_one_unmitigated_path_among_many_stays_exploitable(self):
        evidence = EvidenceSet(
            exploit_paths=[path("path-1"), path("path-2")],
            mitigations=[
                PathMitigationResult(
                    path_id="path-1",
                    mitigation_description="upgraded",
                    present=True,
                    strength=MitigationStrength.HIGH,
                )
            ],
            ran=[ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION],
        )
        verdict = decide(plan(blueprint(sinks=["danger"])), evidence)
        assert verdict.unmitigated_path_count == 1
        assert verdict.exploitable is True

    def test_falsified_applicability_wins_over_paths(self):
        evidence = EvidenceSet(
            exploit_paths=[path()],
            applicability_falsified=True,
            ran=[ProbeId.EXPLOIT_PATH, ProbeId.DEPLOYMENT],
        )
        verdict = decide(plan(blueprint(sinks=["danger"])), evidence)
        assert verdict.activation_state is ActivationState.NOT_ACTIVATED
        assert verdict.exploitable is False

    def test_configuration_unsafe_finding_activates(self):
        assessment = plan(blueprint(conditions=[ConditionType.CONFIGURATION_REQUIREMENT]))
        evidence = EvidenceSet(
            misconfigurations=[
                MisconfigurationFinding(
                    finding_id="m1", description="unsafe mode", relevant_to_cve=True
                )
            ],
            ran=[ProbeId.MISCONFIG],
        )
        verdict = decide(assessment, evidence)
        assert verdict.activation_state is ActivationState.ACTIVATED
        assert verdict.exploitable is True

    def test_configuration_clean_search_is_not_activated(self):
        assessment = plan(blueprint(conditions=[ConditionType.CONFIGURATION_REQUIREMENT]))
        verdict = decide(assessment, EvidenceSet(ran=[ProbeId.MISCONFIG]))
        assert verdict.activation_state is ActivationState.NOT_ACTIVATED
        assert verdict.exploitable is False

    def test_configuration_without_running_misconfig_is_inconclusive(self):
        assessment = plan(blueprint(conditions=[ConditionType.CONFIGURATION_REQUIREMENT]))
        verdict = decide(assessment, EvidenceSet())
        assert verdict.activation_state is ActivationState.INCONCLUSIVE

    def test_environment_applies_when_deployment_says_so(self):
        assessment = plan(blueprint(conditions=[ConditionType.NETWORK_ACCESS]))
        evidence = EvidenceSet(
            deployment_findings=[
                DeploymentFinding(
                    finding_id="d1",
                    condition_type=ConditionType.NETWORK_ACCESS,
                    description="public",
                    applies=True,
                )
            ],
            ran=[ProbeId.DEPLOYMENT],
        )
        assert decide(assessment, evidence).activation_state is ActivationState.ACTIVATED

    def test_environment_without_applicable_finding_is_inconclusive(self):
        """No applies=True is not proof of safety — only that we lack a positive signal."""
        assessment = plan(blueprint(conditions=[ConditionType.NETWORK_ACCESS]))
        evidence = EvidenceSet(
            deployment_findings=[
                DeploymentFinding(
                    finding_id="d1",
                    condition_type=ConditionType.NETWORK_ACCESS,
                    description="unclear",
                    applies=False,
                )
            ],
            ran=[ProbeId.DEPLOYMENT],
        )
        assert decide(assessment, evidence).activation_state is ActivationState.INCONCLUSIVE

    def test_environment_probe_never_ran_is_inconclusive(self):
        assessment = plan(blueprint(conditions=[ConditionType.NETWORK_ACCESS]))
        assert decide(assessment, EvidenceSet()).activation_state is ActivationState.INCONCLUSIVE

    def test_inclusion_imported_is_activated(self):
        from core.models import PresenceEvidence

        assessment = plan(blueprint(cwe_ids=["CWE-506"]))
        evidence = EvidenceSet(
            presence=PresenceEvidence(imported=True, tokens=["thing"], hit_count=1)
        )
        verdict = decide(assessment, evidence)
        assert verdict.activation_state is ActivationState.ACTIVATED
        assert verdict.exploitable is True

    def test_inclusion_not_imported_is_not_activated(self):
        from core.models import PresenceEvidence

        assessment = plan(blueprint(cwe_ids=["CWE-506"]))
        evidence = EvidenceSet(
            presence=PresenceEvidence(imported=False, tokens=["thing"], hit_count=0)
        )
        verdict = decide(assessment, evidence)
        assert verdict.activation_state is ActivationState.NOT_ACTIVATED
        assert verdict.exploitable is False

    def test_inclusion_without_presence_evidence_is_inconclusive(self):
        assessment = plan(blueprint(cwe_ids=["CWE-506"]))
        verdict = decide(assessment, EvidenceSet())
        assert verdict.activation_state is ActivationState.INCONCLUSIVE
        assert verdict.exploitable is False

    def test_hybrid_needs_both_paths_and_unsafe_config(self):
        assessment = plan(
            blueprint(sinks=["danger"], conditions=[ConditionType.CONFIGURATION_REQUIREMENT])
        )
        both = EvidenceSet(
            exploit_paths=[path()],
            misconfigurations=[
                MisconfigurationFinding(finding_id="m1", description="unsafe", relevant_to_cve=True)
            ],
            ran=[ProbeId.EXPLOIT_PATH, ProbeId.MISCONFIG],
        )
        assert decide(assessment, both).activation_state is ActivationState.ACTIVATED

        clean_config = EvidenceSet(
            exploit_paths=[path()], ran=[ProbeId.EXPLOIT_PATH, ProbeId.MISCONFIG]
        )
        assert decide(assessment, clean_config).activation_state is ActivationState.NOT_ACTIVATED

    def test_hybrid_without_a_config_answer_is_inconclusive(self):
        assessment = plan(
            blueprint(sinks=["danger"], conditions=[ConditionType.CONFIGURATION_REQUIREMENT])
        )
        evidence = EvidenceSet(exploit_paths=[path()], ran=[ProbeId.EXPLOIT_PATH])
        assert decide(assessment, evidence).activation_state is ActivationState.INCONCLUSIVE

    def test_unknown_basis_is_skipped(self):
        verdict = decide(plan(blueprint()), EvidenceSet())
        assert verdict.activation_state is ActivationState.SKIPPED
        assert verdict.exploitable is False

    def test_rationale_names_the_gap_when_inconclusive(self):
        evidence = EvidenceSet(gaps=[{"probe": ProbeId.EXPLOIT_PATH, "reason": "Joern was down"}])
        verdict = decide(plan(blueprint(sinks=["danger"])), evidence)
        assert "Joern was down" in verdict.rationale


# ─── clamps ──────────────────────────────────────────────────────────────────


class TestClamps:
    def _verdict(self, state: ActivationState, *, fully_mitigated: bool = False):
        from core.models import RiskVerdict

        return RiskVerdict(
            activation_basis=ActivationBasis.INVOCATION,
            activation_state=state,
            exploitable=False,
            fully_mitigated=fully_mitigated,
        )

    def test_not_activated_zeroes_impact(self):
        forced = clamps(self._verdict(ActivationState.NOT_ACTIVATED), EvidenceSet())
        assert {c.metric: c.value for c in forced} == {"MC": "N", "MI": "N", "MA": "N"}

    def test_fully_mitigated_zeroes_impact(self):
        forced = clamps(
            self._verdict(ActivationState.ACTIVATED, fully_mitigated=True), EvidenceSet()
        )
        assert {c.metric for c in forced} == {"MC", "MI", "MA"}

    def test_skipped_zeroes_impact_when_clamps_run(self):
        forced = clamps(self._verdict(ActivationState.SKIPPED), EvidenceSet())
        assert {c.metric: c.value for c in forced} == {"MC": "N", "MI": "N", "MA": "N"}

    def test_inconclusive_does_not_zero_impact(self):
        """Not knowing must not silently look like knowing there is no risk."""
        verdict = self._verdict(ActivationState.INCONCLUSIVE)
        assert impact_is_impossible(verdict) is False
        assert clamps(verdict, EvidenceSet()) == []

    def test_isolated_deployment_forces_local_attack_vector(self):
        evidence = EvidenceSet(
            deployment_findings=[
                DeploymentFinding(
                    finding_id="d1",
                    condition_type=ConditionType.NETWORK_ACCESS,
                    description="air-gapped",
                    network_exposed=False,
                )
            ]
        )
        forced = clamps(self._verdict(ActivationState.ACTIVATED), evidence)
        assert {c.metric: c.value for c in forced} == {"MAV": "L"}

    def test_exposure_does_not_clamp(self):
        evidence = EvidenceSet(
            deployment_findings=[
                DeploymentFinding(
                    finding_id="d1",
                    condition_type=ConditionType.NETWORK_ACCESS,
                    description="public ingress",
                    network_exposed=True,
                )
            ]
        )
        assert clamps(self._verdict(ActivationState.ACTIVATED), evidence) == []

    @pytest.mark.parametrize("flags,expected", [((True, False), False), ((True, True), True), ((), None)])
    def test_isolation_evidence_beats_exposure_evidence(self, flags, expected):
        evidence = EvidenceSet(
            deployment_findings=[
                DeploymentFinding(
                    finding_id=f"d{i}",
                    condition_type=ConditionType.NETWORK_ACCESS,
                    description="d",
                    network_exposed=flag,
                )
                for i, flag in enumerate(flags)
            ]
        )
        assert evidence.network_exposed is expected
