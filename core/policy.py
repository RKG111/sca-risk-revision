"""
The only place that decides anything about risk.

Three steps, in order:

    plan(blueprint)          which probes to run, and how activation is judged
    decide(plan, evidence)   the single RiskVerdict
    invariants(...)          clamps that must hold whatever the model said

Nothing outside this module may compute activation or exploitability. If you
need a new rule, it goes here — that is the whole point of the file.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.models import (
    ActivationBasis,
    ActivationState,
    AssessmentPlan,
    Blueprint,
    ConditionType,
    EvidenceSet,
    ProbeId,
    RiskVerdict,
)

_MALWARE_HINTS = ("malicious", "supply chain", "trojan")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Planning — blueprint in, plan out
# ─────────────────────────────────────────────────────────────────────────────


def plan(blueprint: Blueprint) -> AssessmentPlan:
    """Choose the activation basis and the probes that can establish it."""
    has_sinks = bool(blueprint.sinks)
    has_config = blueprint.has_condition(ConditionType.CONFIGURATION_REQUIREMENT)
    has_deployment = blueprint.has_condition(
        ConditionType.NETWORK_ACCESS,
        ConditionType.PRIVILEGE_REQUIRED,
        ConditionType.USER_INTERACTION,
    )
    claims_reachability = blueprint.has_condition(
        ConditionType.DEPENDENCY_REACHABILITY,
        ConditionType.FEATURE_EXPOSED_BY_COMPONENT,
    )

    basis, notes = _choose_basis(
        has_sinks=has_sinks,
        has_config=has_config,
        has_deployment=has_deployment,
        claims_reachability=claims_reachability,
        blueprint=blueprint,
    )

    if basis == ActivationBasis.UNKNOWN:
        return AssessmentPlan(activation_basis=basis, notes=notes)

    probes: list[ProbeId] = []
    if basis in (ActivationBasis.INVOCATION, ActivationBasis.HYBRID):
        probes += [ProbeId.EXPLOIT_PATH, ProbeId.MITIGATION]
    if basis in (ActivationBasis.CONFIGURATION, ActivationBasis.HYBRID):
        probes.append(ProbeId.MISCONFIG)
    if has_deployment or basis == ActivationBasis.ENVIRONMENT:
        probes.append(ProbeId.DEPLOYMENT)

    return AssessmentPlan(
        activation_basis=basis,
        probes=list(dict.fromkeys(probes)),
        sink_gate=basis in (ActivationBasis.INVOCATION, ActivationBasis.HYBRID),
        presence_check=basis == ActivationBasis.INCLUSION,
        notes=notes,
    )


def _choose_basis(
    *,
    has_sinks: bool,
    has_config: bool,
    has_deployment: bool,
    claims_reachability: bool,
    blueprint: Blueprint,
) -> tuple[ActivationBasis, str]:
    """Pick how activation will be judged. Order matters: most specific first."""
    if has_sinks and has_config:
        return ActivationBasis.HYBRID, "sinks plus a configuration requirement"
    if has_sinks:
        return ActivationBasis.INVOCATION, "upstream sinks are known"
    if has_config:
        return ActivationBasis.CONFIGURATION, "a configuration requirement without sinks"

    cwes = {c.upper() for c in blueprint.all_cwe_ids}
    exploit_type = (blueprint.exploit_type or "").lower()
    if "CWE-506" in cwes or any(hint in exploit_type for hint in _MALWARE_HINTS):
        return ActivationBasis.INCLUSION, "malicious-package indicators; inclusion is enough"

    if has_deployment:
        return ActivationBasis.ENVIRONMENT, "only deployment conditions are known"
    if claims_reachability:
        return (
            ActivationBasis.UNKNOWN,
            "blueprint claims reachability but names no sinks; research is incomplete",
        )
    return ActivationBasis.UNKNOWN, "not enough blueprint signal to judge activation"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Deciding — the single verdict
# ─────────────────────────────────────────────────────────────────────────────


def decide(plan: AssessmentPlan, evidence: EvidenceSet) -> RiskVerdict:
    """Turn evidence into the one risk decision the report carries."""
    state = _activation_state(plan, evidence)

    paths = evidence.exploit_paths
    unmitigated = evidence.unmitigated_paths
    fully_mitigated = bool(paths) and not unmitigated

    exploitable = (
        state == ActivationState.ACTIVATED
        and not fully_mitigated
        and not evidence.applicability_falsified
    )

    return RiskVerdict(
        activation_basis=plan.activation_basis,
        activation_state=state,
        exploitable=exploitable,
        fully_mitigated=fully_mitigated,
        unmitigated_path_count=len(unmitigated),
        sinks_hit=evidence.sinks_hit,
        rationale=_rationale(plan, evidence, state, exploitable, len(unmitigated)),
    )


def _activation_state(plan: AssessmentPlan, evidence: EvidenceSet) -> ActivationState:
    """Is the CVE live here? Answered per basis, from evidence only."""
    if plan.skip_rescoring:
        return ActivationState.SKIPPED
    if evidence.applicability_falsified:
        return ActivationState.NOT_ACTIVATED

    basis = plan.activation_basis
    paths = bool(evidence.exploit_paths)
    unsafe_config = _unsafe_config(evidence)

    if basis == ActivationBasis.INVOCATION:
        if not evidence.has_run(ProbeId.EXPLOIT_PATH):
            return ActivationState.INCONCLUSIVE
        return ActivationState.ACTIVATED if paths else ActivationState.NOT_ACTIVATED

    if basis == ActivationBasis.CONFIGURATION:
        return _from_tristate(unsafe_config)

    if basis == ActivationBasis.HYBRID:
        if not evidence.has_run(ProbeId.EXPLOIT_PATH):
            return ActivationState.INCONCLUSIVE
        if paths and unsafe_config is True:
            return ActivationState.ACTIVATED
        if not paths or unsafe_config is False:
            return ActivationState.NOT_ACTIVATED
        return ActivationState.INCONCLUSIVE

    if basis == ActivationBasis.ENVIRONMENT:
        if not evidence.has_run(ProbeId.DEPLOYMENT):
            return ActivationState.INCONCLUSIVE
        applies = any(f.applies for f in evidence.deployment_findings)
        return ActivationState.ACTIVATED if applies else ActivationState.INCONCLUSIVE

    if basis == ActivationBasis.INCLUSION:
        if not evidence.presence or evidence.presence.imported is None:
            return ActivationState.INCONCLUSIVE
        return (
            ActivationState.ACTIVATED
            if evidence.presence.imported
            else ActivationState.NOT_ACTIVATED
        )

    return ActivationState.INCONCLUSIVE


def _unsafe_config(evidence: EvidenceSet) -> bool | None:
    """True if unsafe config found, False if searched and clean, None if unknown.

    The distinction matters: "we did not look" must never read as "it is safe",
    which is why this consults `ran` and not just the finding list.
    """
    if not evidence.has_run(ProbeId.MISCONFIG):
        return None
    if any(f.relevant_to_cve for f in evidence.misconfigurations):
        return True
    return False


def _from_tristate(value: bool | None) -> ActivationState:
    if value is None:
        return ActivationState.INCONCLUSIVE
    return ActivationState.ACTIVATED if value else ActivationState.NOT_ACTIVATED


def _rationale(
    plan: AssessmentPlan,
    evidence: EvidenceSet,
    state: ActivationState,
    exploitable: bool,
    unmitigated: int,
) -> str:
    basis = plan.activation_basis.value

    if state == ActivationState.SKIPPED:
        return f"Not rescored: {plan.notes or 'activation basis unknown'}; needs analyst review"
    if evidence.applicability_falsified:
        return "Not exploitable: the deployment context makes this CVE inapplicable"
    if state == ActivationState.NOT_ACTIVATED:
        return f"Not exploitable: activation conditions for {basis} are not met"
    if state == ActivationState.INCONCLUSIVE:
        gaps = ", ".join(f"{g.probe.value} ({g.reason})" for g in evidence.gaps)
        detail = f"; evidence gaps: {gaps}" if gaps else ""
        return f"Inconclusive: not enough evidence to establish {basis}{detail}"
    if not exploitable:
        return "Not exploitable: activation confirmed but fully mitigated by high-strength controls"

    sinks = ", ".join(evidence.sinks_hit) or "no named sink"
    return f"Exploitable: {unmitigated} unmitigated path(s) via {basis}, reaching {sinks}"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Invariants — clamps applied after the model has spoken
# ─────────────────────────────────────────────────────────────────────────────



@dataclass(frozen=True)
class Clamp:
    """A metric value that the evidence forces, whatever the model answered."""

    metric: str
    value: str
    reason: str


def impact_is_impossible(verdict: RiskVerdict) -> bool:
    """True when the evidence rules out impact, so modified impacts must be None.

    Applies to a decided negative only. `INCONCLUSIVE` deliberately does *not*
    clamp: not knowing is not the same as knowing there is no impact, and
    silently zeroing it would hide unresolved risk behind a low score.
    """
    return verdict.activation_state in (
        ActivationState.NOT_ACTIVATED,
        ActivationState.SKIPPED,
    ) or verdict.fully_mitigated


def clamps(verdict: RiskVerdict, evidence: EvidenceSet) -> list[Clamp]:
    """Metric values the evidence forces. Applied after adjudication, and recorded.

    These are physical impossibilities, not preferences: an unexploitable
    finding cannot have impact, and an isolated deployment cannot be attacked
    over the network.
    """
    forced: list[Clamp] = []

    if impact_is_impossible(verdict):
        reason = _no_impact_reason(verdict, evidence)
        forced += [Clamp(metric, "N", reason) for metric in ("MC", "MI", "MA")]

    if evidence.network_exposed is False:
        forced.append(
            Clamp("MAV", "L", "Deployment evidence shows the product is network-isolated")
        )

    return forced


def _no_impact_reason(verdict: RiskVerdict, evidence: EvidenceSet) -> str:
    if evidence.applicability_falsified:
        return "Deployment context makes the CVE inapplicable, so impact is None"
    if verdict.activation_state == ActivationState.NOT_ACTIVATED:
        return f"Activation for {verdict.activation_basis.value} is not met, so impact is None"
    if verdict.fully_mitigated:
        return "Every exploit path is blocked by a high-strength mitigation, so impact is None"
    return "Rescoring was skipped, so impact is None"
