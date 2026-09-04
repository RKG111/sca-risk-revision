"""
Scoring tests: the vector value object, metric adjudication, and the arithmetic.

No LLM is called — the adjudicator is injected, which is the point of making it
a parameter.
"""

from __future__ import annotations

import pytest

from core.models import (
    ActivationBasis,
    ActivationState,
    AnswerSource,
    Blueprint,
    BlueprintCVSS,
    ConditionType,
    DeploymentFinding,
    EvidenceSet,
    RiskVerdict,
    Severity,
)
from core.scoring import (
    MetricJudgement,
    MetricJudgements,
    Vector,
    adjudicate,
    score,
)

BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def blueprint() -> Blueprint:
    return Blueprint(
        cve_id="CVE-0000-0000",
        cvss=BlueprintCVSS(score=9.8, vector=BASE_VECTOR),
        affected_components=[{"name": "thing", "purl": "pkg:pypi/thing@1.0.0"}],
    )


def verdict(
    state: ActivationState = ActivationState.ACTIVATED, *, fully_mitigated: bool = False
) -> RiskVerdict:
    return RiskVerdict(
        activation_basis=ActivationBasis.INVOCATION,
        activation_state=state,
        exploitable=state is ActivationState.ACTIVATED and not fully_mitigated,
        fully_mitigated=fully_mitigated,
    )


def answers_of(answers) -> dict[str, str]:
    return {a.metric: a.answer for a in answers}


class TestVector:
    def test_parses_base_metrics(self):
        vector = Vector.parse(BASE_VECTOR)
        assert vector.get("AV") == "N"
        assert vector.get("C") == "H"
        assert vector.base == BASE_VECTOR

    def test_tolerates_lowercase_and_whitespace(self):
        assert Vector.parse("  cvss:3.1/av:n/ac:l  ").get("AV") == "N"

    def test_environmental_leaves_base_segments_untouched(self):
        """The published base vector is a fact; findings go in the M* metrics."""
        environmental = Vector.parse(BASE_VECTOR).environmental(
            {"CR": "H", "IR": "H", "AR": "H", "MC": "N", "MI": "N", "MA": "N"}
        )
        assert environmental.startswith(BASE_VECTOR)
        assert "/MC:N/MI:N/MA:N" in environmental
        assert "/C:N" not in environmental

    def test_environmental_orders_base_then_requirements_then_modified(self):
        environmental = Vector.parse(BASE_VECTOR).environmental(
            {"MAV": "L", "CR": "M", "MC": "N"}
        )
        assert environmental.index("CR:M") < environmental.index("MAV:L")
        assert environmental.index("A:H") < environmental.index("CR:M")


class TestScore:
    def test_unchanged_metrics_reproduce_the_base_score(self):
        environmental = Vector.parse(BASE_VECTOR).environmental(
            {
                "CR": "H", "IR": "H", "AR": "H",
                "MAV": "N", "MAC": "L", "MPR": "N", "MUI": "N",
                "MS": "U", "MC": "H", "MI": "H", "MA": "H",
            }
        )
        value, severity = score(environmental)
        assert value == 9.8
        assert severity is Severity.CRITICAL

    def test_zeroed_impact_scores_zero(self):
        environmental = Vector.parse(BASE_VECTOR).environmental(
            {"CR": "H", "IR": "H", "AR": "H", "MC": "N", "MI": "N", "MA": "N"}
        )
        value, severity = score(environmental)
        assert value == 0.0
        assert severity is Severity.NONE

    def test_local_attack_vector_lowers_the_score(self):
        environmental = Vector.parse(BASE_VECTOR).environmental(
            {"CR": "H", "IR": "H", "AR": "H", "MAV": "L"}
        )
        value, _ = score(environmental)
        assert value < 9.8

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0.0, Severity.NONE),
            (3.9, Severity.LOW),
            (4.0, Severity.MEDIUM),
            (6.9, Severity.MEDIUM),
            (7.0, Severity.HIGH),
            (8.9, Severity.HIGH),
            (9.0, Severity.CRITICAL),
            (10.0, Severity.CRITICAL),
        ],
    )
    def test_severity_bands(self, value, expected):
        assert Severity.from_score(value) is expected


class TestAdjudicate:
    def test_without_an_adjudicator_every_metric_falls_back_to_base(self):
        answers = adjudicate(blueprint(), verdict(), EvidenceSet())
        assert answers_of(answers) == {
            "CR": "H", "IR": "H", "AR": "H",
            "MAV": "N", "MAC": "L", "MPR": "N", "MUI": "N",
            "MS": "U", "MC": "H", "MI": "H", "MA": "H",
        }
        assert {a.source for a in answers} == {AnswerSource.BASE}

    def test_model_answers_are_used_and_attributed(self):
        def adjudicator(_bp, _verdict, _evidence, unresolved):
            assert "MAV" in unresolved
            return MetricJudgements(
                answers=[MetricJudgement(metric="MAV", answer="L", reason="internal only")]
            )

        answers = adjudicate(blueprint(), verdict(), EvidenceSet(), adjudicator=adjudicator)
        mav = next(a for a in answers if a.metric == "MAV")
        assert mav.answer == "L"
        assert mav.source is AnswerSource.LLM
        assert mav.reason == "internal only"

    def test_off_vocabulary_answers_are_rejected(self):
        def adjudicator(*_args):
            return MetricJudgements(
                answers=[
                    MetricJudgement(metric="MAC", answer="Z"),
                    MetricJudgement(metric="MUI", answer="Nope"),
                ]
            )

        answers = adjudicate(blueprint(), verdict(), EvidenceSet(), adjudicator=adjudicator)
        by_metric = {a.metric: a for a in answers}
        assert by_metric["MAC"].answer == "L"
        assert by_metric["MAC"].source is AnswerSource.BASE
        # "Nope" truncates to a valid "N", which happens to be the base value too.
        assert by_metric["MUI"].answer == "N"

    def test_unrequested_metrics_are_ignored(self):
        def adjudicator(*_args):
            return MetricJudgements(answers=[MetricJudgement(metric="CR", answer="L")])

        answers = adjudicate(blueprint(), verdict(), EvidenceSet(), adjudicator=adjudicator)
        assert answers_of(answers)["CR"] == "H"

    def test_a_clamp_overrides_the_model(self):
        def adjudicator(*_args):
            return MetricJudgements(
                answers=[MetricJudgement(metric="MC", answer="H", reason="model insists")]
            )

        answers = adjudicate(
            blueprint(),
            verdict(ActivationState.NOT_ACTIVATED),
            EvidenceSet(),
            adjudicator=adjudicator,
        )
        mc = next(a for a in answers if a.metric == "MC")
        assert mc.answer == "N"
        assert mc.source is AnswerSource.INVARIANT
        assert "not met" in mc.reason

    def test_isolation_clamp_overrides_the_model(self):
        def adjudicator(*_args):
            return MetricJudgements(answers=[MetricJudgement(metric="MAV", answer="N")])

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
        answers = adjudicate(blueprint(), verdict(), evidence, adjudicator=adjudicator)
        mav = next(a for a in answers if a.metric == "MAV")
        assert mav.answer == "L"
        assert mav.source is AnswerSource.INVARIANT

    def test_an_unavailable_adjudicator_keeps_base_metrics(self):
        def adjudicator(*_args):
            return MetricJudgements()

        answers = adjudicate(blueprint(), verdict(), EvidenceSet(), adjudicator=adjudicator)
        assert answers_of(answers)["MAV"] == "N"
        assert {a.source for a in answers} == {AnswerSource.BASE}
