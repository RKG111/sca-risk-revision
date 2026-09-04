"""
CVSS environmental scoring.

Three steps:

    Vector.parse(...)     read the base vector
    adjudicate(...)       answer the environmental metrics
    score(...)            arithmetic, via the `cvss` library

The base vector is never mutated. We add environmental metrics (CR/IR/AR and
the Modified Base metrics) alongside it, which is what CVSS 3.1 specifies, and
let the library do the maths — there is no hand-rolled scoring here.

Metric answers come from the model, are constrained to the CVSS vocabulary, and
are then overridden by any clamp from `core.policy`. Every answer records where
it came from, so a report can always be audited.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from pydantic import BaseModel, Field

from core.errors import LLMUnavailable
from core.llm import structured
from core.models import (
    AnswerSource,
    Blueprint,
    EvidenceSet,
    MetricAnswer,
    RiskVerdict,
    Severity,
)
from core.policy import clamps
from core.telemetry import ScanSession

logger = logging.getLogger(__name__)

#: Base metric order in a CVSS 3.1 vector.
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: Modified Base metrics, and the base metric each one shadows.
MODIFIED_METRICS = {
    "MAV": "AV",
    "MAC": "AC",
    "MPR": "PR",
    "MUI": "UI",
    "MS": "S",
    "MC": "C",
    "MI": "I",
    "MA": "A",
}

#: Security Requirement metrics.
REQUIREMENT_METRICS = ("CR", "IR", "AR")

#: Phase-1 default: product criticality is not ingested yet, so assume High.
#: Replace this once product documentation drives CR/IR/AR.
DEFAULT_REQUIREMENTS = {"CR": "H", "IR": "H", "AR": "H"}

#: The only values each metric may take. Anything else is rejected.
VOCABULARY = {
    "MAV": ("N", "A", "L", "P"),
    "MAC": ("L", "H"),
    "MPR": ("N", "L", "H"),
    "MUI": ("N", "R"),
    "MS": ("U", "C"),
    "MC": ("N", "L", "H"),
    "MI": ("N", "L", "H"),
    "MA": ("N", "L", "H"),
    "CR": ("L", "M", "H"),
    "IR": ("L", "M", "H"),
    "AR": ("L", "M", "H"),
}

QUESTIONS = {
    "MAV": "How can this be reached in this product?",
    "MAC": "How hard is exploitation in this product?",
    "MPR": "What privileges does an attacker need here?",
    "MUI": "Is user interaction required here?",
    "MS": "Can impact cross a security boundary here?",
    "MC": "What confidentiality impact is possible here?",
    "MI": "What integrity impact is possible here?",
    "MA": "What availability impact is possible here?",
    "CR": "How critical is confidentiality for this product?",
    "IR": "How critical is integrity for this product?",
    "AR": "How critical is availability for this product?",
}


# ─────────────────────────────────────────────────────────────────────────────
# The vector
# ─────────────────────────────────────────────────────────────────────────────


class Vector:
    """A CVSS 3.1 vector, immutable, that can emit an environmental variant."""

    def __init__(self, metrics: dict[str, str], prefix: str = "CVSS:3.1"):
        self._metrics = dict(metrics)
        self.prefix = prefix

    @classmethod
    def parse(cls, vector: str) -> "Vector":
        metrics: dict[str, str] = {}
        prefix = "CVSS:3.1"
        for segment in vector.strip().split("/"):
            if segment.upper().startswith("CVSS"):
                prefix = segment
                continue
            key, _, value = segment.partition(":")
            if value:
                metrics[key.upper()] = value.upper()
        return cls(metrics, prefix)

    def get(self, metric: str, default: str = "") -> str:
        return self._metrics.get(metric.upper(), default)

    @property
    def base(self) -> str:
        segments = [f"{m}:{self._metrics[m]}" for m in BASE_METRICS if m in self._metrics]
        return "/".join([self.prefix, *segments])

    def environmental(self, answers: dict[str, str]) -> str:
        """Base metrics, then requirements, then modified metrics.

        Base segments are left exactly as the advisory published them; the
        Modified Base metrics are what express our findings.
        """
        segments = [f"{m}:{self._metrics[m]}" for m in BASE_METRICS if m in self._metrics]
        segments += [f"{m}:{answers[m]}" for m in REQUIREMENT_METRICS if m in answers]
        segments += [f"{m}:{answers[m]}" for m in MODIFIED_METRICS if m in answers]
        return "/".join([self.prefix, *segments])

    def __str__(self) -> str:
        return self.base


# ─────────────────────────────────────────────────────────────────────────────
# Adjudication
# ─────────────────────────────────────────────────────────────────────────────


class MetricJudgement(BaseModel):
    """One metric answer from the model."""

    metric: str = Field(description="Metric id, e.g. MAV or MC")
    answer: str = Field(description="Single-letter CVSS value")
    reason: str = Field(default="", description="Why, citing the evidence")


class MetricJudgements(BaseModel):
    answers: list[MetricJudgement] = Field(default_factory=list)


#: Signature of a metric-answer provider, so tests can supply a fixed one.
Adjudicator = Callable[[Blueprint, RiskVerdict, EvidenceSet, list[str]], MetricJudgements]


def adjudicate(
    blueprint: Blueprint,
    verdict: RiskVerdict,
    evidence: EvidenceSet,
    *,
    adjudicator: Optional[Adjudicator] = None,
) -> list[MetricAnswer]:
    """Answer every environmental metric, then enforce the policy clamps."""
    base = Vector.parse(blueprint.cvss.vector)
    answers: dict[str, MetricAnswer] = {}

    for metric, value in DEFAULT_REQUIREMENTS.items():
        answers[metric] = MetricAnswer(
            metric=metric,
            question=QUESTIONS[metric],
            answer=value,
            reason="Phase-1 default: product criticality is not ingested yet, assuming High",
            source=AnswerSource.BASE,
        )

    unresolved = [m for m in MODIFIED_METRICS if m not in answers]
    if unresolved and adjudicator is not None:
        for judgement in _valid(adjudicator(blueprint, verdict, evidence, unresolved), unresolved):
            answers[judgement.metric] = MetricAnswer(
                metric=judgement.metric,
                question=QUESTIONS[judgement.metric],
                answer=judgement.answer,
                reason=judgement.reason or "Adjudicated from product evidence",
                source=AnswerSource.LLM,
            )

    # Anything the model did not settle keeps the published base value, which is
    # the conservative choice: we do not lower a score without evidence.
    for metric, base_metric in MODIFIED_METRICS.items():
        if metric in answers:
            continue
        answers[metric] = MetricAnswer(
            metric=metric,
            question=QUESTIONS[metric],
            answer=base.get(base_metric, "N"),
            reason=f"No evidence to change this; keeping base {base_metric}",
            source=AnswerSource.BASE,
        )

    for clamp in clamps(verdict, evidence):
        answers[clamp.metric] = MetricAnswer(
            metric=clamp.metric,
            question=QUESTIONS.get(clamp.metric, ""),
            answer=clamp.value,
            reason=clamp.reason,
            source=AnswerSource.INVARIANT,
        )

    return [answers[m] for m in (*REQUIREMENT_METRICS, *MODIFIED_METRICS) if m in answers]


def _valid(judgements: MetricJudgements, requested: list[str]) -> list[MetricJudgement]:
    """Keep only answers that were asked for and are in the CVSS vocabulary."""
    keep: list[MetricJudgement] = []
    for judgement in judgements.answers:
        metric = judgement.metric.strip().upper()
        answer = judgement.answer.strip().upper()[:1]
        if metric not in requested:
            continue
        if answer not in VOCABULARY.get(metric, ()):
            logger.warning("Rejecting %s=%r: not a valid value", metric, judgement.answer)
            continue
        keep.append(judgement.model_copy(update={"metric": metric, "answer": answer}))
    return keep


def llm_adjudicator(
    blueprint: Blueprint,
    verdict: RiskVerdict,
    evidence: EvidenceSet,
    unresolved: list[str],
    *,
    session: Optional[ScanSession] = None,
) -> MetricJudgements:
    """Ask the model to set the modified metrics from the gathered evidence."""
    questions = "\n".join(f"- {m}: {QUESTIONS[m]} (allowed: {', '.join(VOCABULARY[m])})" for m in unresolved)
    prompt = f"""Set the CVSS v3.1 Modified Base metrics for this product.

CVE: {blueprint.cve_id}
Published base vector: {blueprint.cvss.vector}

Verdict:
{verdict.model_dump_json(indent=2)}

Evidence:
{evidence.model_dump_json(indent=2, exclude={"notes"})}

Answer only these metrics, using only the allowed values:
{questions}

Keep the base value unless the evidence positively justifies changing it.
"""
    try:
        return structured(
            MetricJudgements,
            system="You adjudicate CVSS environmental metrics from code evidence. Be conservative.",
            user=prompt,
            session=session,
            skill="MDE",
        )
    except LLMUnavailable as exc:
        logger.warning("Metric adjudication unavailable (%s); keeping base metrics", exc)
        return MetricJudgements()


def make_llm_adjudicator(*, session: Optional[ScanSession] = None) -> Adjudicator:
    """Bind a scan session into the default LLM adjudicator."""

    def _adjudicate(
        blueprint: Blueprint,
        verdict: RiskVerdict,
        evidence: EvidenceSet,
        unresolved: list[str],
    ) -> MetricJudgements:
        return llm_adjudicator(
            blueprint, verdict, evidence, unresolved, session=session
        )

    return _adjudicate


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────


def score(vector: str) -> tuple[float, Severity]:
    """Environmental score for a full vector. The only arithmetic in the system."""
    from cvss import CVSS3

    parsed = CVSS3(vector)
    value = parsed.environmental_score
    if value is None:
        value = parsed.base_score
    value = float(value)
    return value, Severity.from_score(value)
