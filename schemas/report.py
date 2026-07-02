"""
Final rescored vulnerability report schema.
See plan.md §6 for the reference JSON output.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerificationMethod(str, Enum):
    DETERMINISTIC_JOERN = "Deterministic (Joern CPG Analysis)"
    DETERMINISTIC_SEMGREP = "Deterministic (Semgrep AST Analysis)"
    AGENT_LLM = "Agentic (LLM Reasoning)"
    HYBRID = "Hybrid (Deterministic + Agentic)"
    NOT_ASSESSED = "Not Assessed"


class OriginalAssessment(BaseModel):
    cvss_v3_vector: str
    score: float
    severity: Severity


class RescoredAssessment(BaseModel):
    cvss_v3_vector: str
    score: float
    severity: Severity

    @computed_field
    @property
    def score_delta(self) -> float:
        return self.score  # Caller sets this; delta computed in RescoredReport


class ConditionResult(BaseModel):
    """Result of evaluating a single blueprint condition."""

    condition_description: str
    result: bool
    evidence: str
    method: VerificationMethod


class EvidenceJustification(BaseModel):
    reachability_verified: bool
    execution_trace: str = Field(
        description="Human-readable trace showing whether the vulnerable code path is reachable"
    )
    environmental_mitigations: str = Field(
        description="Deployment-level factors that reduce or eliminate exploitability"
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="0.0 = no confidence, 1.0 = fully certain"
    )
    verification_method: VerificationMethod
    condition_results: list[ConditionResult] = Field(default_factory=list)


class RescoredReport(BaseModel):
    """Top-level output document for a single CVE rescoring run."""

    cve_id: str
    component: str = Field(description="PURL of the affected component")
    original_assessment: OriginalAssessment
    rescored_assessment: RescoredAssessment
    evidence_justification: EvidenceJustification
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field
    @property
    def score_delta(self) -> float:
        return round(
            self.rescored_assessment.score - self.original_assessment.score, 1
        )

    @computed_field
    @property
    def risk_reduced(self) -> bool:
        return self.score_delta < 0
