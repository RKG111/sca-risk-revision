"""
Attack Blueprint schema — the structured output from Module 2 (Blueprint Generator).
This is the instruction set that drives Modules 3 (Deterministic) and 4 (Agent).
See plan.md §5 for the reference JSON schema.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class DeterministicFeasibility(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssessmentStrategy(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    AGENT = "AGENT"
    HYBRID = "HYBRID"


class ImpactLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class CodeLevelCondition(BaseModel):
    vulnerable_symbol: str = Field(
        description="The exact function/method/class that is the vulnerable entry point"
    )
    package_context: str = Field(
        description="The fully-qualified package name containing the vulnerable symbol"
    )
    expected_data_flow: str = Field(
        description="Human-readable description of the required taint flow"
    )
    indicators_of_reachability: list[str] = Field(
        default_factory=list,
        description="String/AST patterns whose presence indicates the vulnerable code path is reachable",
    )


class EnvironmentLevelCondition(BaseModel):
    runtime_version_constraints: Optional[str] = None
    required_feature_flags: list[str] = Field(default_factory=list)
    network_exposure: Optional[str] = Field(
        default=None,
        description="e.g. 'public_ingress', 'internal_only', 'isolated_vpc'",
    )
    required_dependencies: list[str] = Field(default_factory=list)


class BlueprintConditions(BaseModel):
    code_level: CodeLevelCondition
    environment_level: EnvironmentLevelCondition


class ExploitationMechanism(BaseModel):
    step_by_step: str = Field(
        description="Numbered steps an attacker would follow to trigger the vulnerability"
    )
    indicators_of_reachability: list[str] = Field(default_factory=list)


class TrueImpactVectors(BaseModel):
    confidentiality: ImpactLevel
    integrity: ImpactLevel
    availability: ImpactLevel


class CVSSMetricOverrides(BaseModel):
    """
    Per-metric reasoning from the LLM, used as input to the CVSS rescoring engine.
    Each field maps to a CVSS v3.1 Base Metric.
    Values must conform to the CVSS v3.1 specification strings.
    """

    attack_vector: Optional[str] = Field(None, description="N, A, L, or P")
    attack_complexity: Optional[str] = Field(None, description="L or H")
    privileges_required: Optional[str] = Field(None, description="N, L, or H")
    user_interaction: Optional[str] = Field(None, description="N or R")
    scope: Optional[str] = Field(None, description="U or C")
    confidentiality_impact: Optional[str] = Field(None, description="N, L, or H")
    integrity_impact: Optional[str] = Field(None, description="N, L, or H")
    availability_impact: Optional[str] = Field(None, description="N, L, or H")


class AttackBlueprint(BaseModel):
    """
    Structured output from the Blueprint Generator (Module 2).
    Acts as the instruction set for Modules 3 and 4.
    """

    cve_id: str
    cwe_id: Optional[str] = None
    capec_ids: list[str] = Field(default_factory=list)
    assessment_strategy: AssessmentStrategy
    deterministic_verification_feasibility: DeterministicFeasibility
    required_conditions: BlueprintConditions
    exploitation_mechanism: ExploitationMechanism
    true_impact_vectors: TrueImpactVectors
    suggested_cvss_overrides: Optional[CVSSMetricOverrides] = None
    llm_reasoning_summary: Optional[str] = Field(
        default=None,
        description="Free-text explanation of why this blueprint was constructed this way",
    )
