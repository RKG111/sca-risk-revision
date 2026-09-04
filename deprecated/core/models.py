"""
Every data shape in the system, in one file.

Read top to bottom to understand the whole domain:

  1. Enums      — the closed vocabularies
  2. Blueprint  — trusted CVE research, the primary input
  3. SBOM       — CycloneDX subset, tells us which component/CVE to assess
  4. Evidence   — what the probes found
  5. Verdict    — the single risk decision
  6. Report     — the output

There is exactly one enum per concept and exactly one model per concept. If you
find yourself wanting a near-duplicate, change the original instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator

# ─────────────────────────────────────────────────────────────────────────────
# 1. Enums
# ─────────────────────────────────────────────────────────────────────────────


class ProbeId(str, Enum):
    """The four evidence questions we can ask about a codebase."""

    EXPLOIT_PATH = "S1"
    MISCONFIG = "S2"
    DEPLOYMENT = "S3"
    MITIGATION = "S4"


class ConditionType(str, Enum):
    """Kinds of precondition a CVE can carry."""

    NETWORK_ACCESS = "network_access"
    PRIVILEGE_REQUIRED = "privilege_required"
    USER_INTERACTION = "user_interaction"
    DEPENDENCY_REACHABILITY = "dependency_reachability"
    FEATURE_EXPOSED_BY_COMPONENT = "feature_exposed_by_component"
    CONFIGURATION_REQUIREMENT = "configuration_requirement"


class Confidence(str, Enum):
    """Qualitative confidence, used wherever a coarse grade is enough."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MitigationStrength(str, Enum):
    """How much a mitigation actually blocks exploitation.

    One scale for both blueprint claims and verified findings; `NONE` means
    "checked and not effective / not present".
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ActivationBasis(str, Enum):
    """How we decide whether a CVE is live in this product."""

    INVOCATION = "invocation"
    CONFIGURATION = "configuration"
    HYBRID = "hybrid"
    ENVIRONMENT = "environment"
    INCLUSION = "inclusion"
    UNKNOWN = "unknown"


class ActivationState(str, Enum):
    """The answer to "is the CVE live here?"."""

    ACTIVATED = "activated"
    NOT_ACTIVATED = "not_activated"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class AnswerSource(str, Enum):
    """Where a CVSS metric answer came from."""

    LLM = "llm"
    BASE = "base"
    INVARIANT = "invariant"


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """CVSS 3.1 severity bands — the only place this mapping exists."""
        if score == 0.0:
            return cls.NONE
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


# ─────────────────────────────────────────────────────────────────────────────
# 2. Blueprint — trusted, cached CVE research keyed by (cve_id, versioned purl)
# ─────────────────────────────────────────────────────────────────────────────


class BlueprintCVSS(BaseModel):
    score: float
    vector: str


class AffectedComponent(BaseModel):
    name: str
    purl: str = Field(description="Versioned PURL, e.g. pkg:pypi/pyyaml@5.3.1")
    cpe: Optional[str] = None


class BlueprintCondition(BaseModel):
    type: ConditionType
    value: str
    source: str = ""
    confidence: Confidence = Confidence.HIGH


class UpstreamArtifacts(BaseModel):
    """Upstream facts about the vulnerability itself, not about our product."""

    functions: list[str] = Field(default_factory=list, description="Sink symbols")
    files: list[str] = Field(default_factory=list)
    fix_commits: list[str] = Field(default_factory=list)
    advisories: list[str] = Field(default_factory=list)


class Remediation(BaseModel):
    fixed_versions: list[str] = Field(default_factory=list)
    patch_indicators: list[str] = Field(default_factory=list)
    security_advisories: list[str] = Field(default_factory=list)


class BlueprintMitigation(BaseModel):
    mitigation: str
    source: str = ""
    confidence: Confidence = Confidence.HIGH
    strength: Optional[MitigationStrength] = None
    detection_hints: list[str] = Field(default_factory=list)


class BlueprintReferences(BaseModel):
    cwe_ids: list[str] = Field(default_factory=list)
    capec_ids: list[str] = Field(default_factory=list)
    osv_ids: list[str] = Field(default_factory=list)
    kev: bool = False


class Blueprint(BaseModel):
    """Component-specific CVE research. Never mentions probes or CVSS policy."""

    schema_version: str = "1.0"
    cve_id: str
    cvss: BlueprintCVSS
    affected_components: list[AffectedComponent]
    cwe_ids: list[str] = Field(default_factory=list)
    capec_ids: list[str] = Field(default_factory=list)
    exploit_type: str = ""
    affected_features: list[str] = Field(default_factory=list)
    conditions: list[BlueprintCondition] = Field(default_factory=list)
    attack_steps: list[str] = Field(default_factory=list)
    attacker_inputs: list[str] = Field(default_factory=list)
    upstream_artifacts: UpstreamArtifacts = Field(default_factory=UpstreamArtifacts)
    remediation: Remediation = Field(default_factory=Remediation)
    mitigations: list[BlueprintMitigation] = Field(default_factory=list)
    references: BlueprintReferences = Field(default_factory=BlueprintReferences)
    confidence: Confidence = Confidence.HIGH
    created_at: Optional[datetime] = None

    @property
    def sinks(self) -> list[str]:
        return list(self.upstream_artifacts.functions)

    @property
    def all_cwe_ids(self) -> list[str]:
        return [*self.cwe_ids, *self.references.cwe_ids]

    def has_condition(self, *types: ConditionType) -> bool:
        wanted = set(types)
        return any(c.type in wanted for c in self.conditions)

    def conditions_of(self, *types: ConditionType) -> list[BlueprintCondition]:
        wanted = set(types)
        return [c for c in self.conditions if c.type in wanted]


# ─────────────────────────────────────────────────────────────────────────────
# 3. SBOM — CycloneDX subset. Unknown keys are ignored, so only what we use.
# ─────────────────────────────────────────────────────────────────────────────


class SBOMComponent(BaseModel):
    bom_ref: Optional[str] = Field(default=None, alias="bom-ref")
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None

    model_config = {"populate_by_name": True}

    @property
    def versioned_purl(self) -> Optional[str]:
        if self.purl:
            return self.purl
        if self.name and self.version:
            return f"pkg:generic/{self.name}@{self.version}"
        return None


class SBOMVulnerability(BaseModel):
    cve_id: str = Field(alias="id")
    affects: list[dict] = Field(default_factory=list)
    affected_purls: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class CycloneDXSBOM(BaseModel):
    """Only the parts we need: which components exist and which CVEs affect them."""

    components: list[SBOMComponent] = Field(default_factory=list)
    vulnerabilities: list[SBOMVulnerability] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _link_affects_to_purls(self) -> "CycloneDXSBOM":
        """Resolve each vulnerability's `affects[].ref` to a versioned PURL."""
        ref_to_purl: dict[str, str] = {}
        for component in self.components:
            purl = component.versioned_purl
            if not purl:
                continue
            if component.bom_ref:
                ref_to_purl[component.bom_ref] = purl
            ref_to_purl[purl] = purl

        for vuln in self.vulnerabilities:
            if vuln.affected_purls:
                continue
            purls = []
            for affect in vuln.affects:
                ref = str(affect.get("ref", ""))
                resolved = ref_to_purl.get(ref)
                if resolved:
                    purls.append(resolved)
                elif ref.startswith("pkg:"):
                    purls.append(ref)
            vuln.affected_purls = purls
        return self

    def affected_purl(self, cve_id: str) -> Optional[str]:
        """The PURL this CVE applies to, or None if the SBOM does not say."""
        vuln = next((v for v in self.vulnerabilities if v.cve_id == cve_id), None)
        if not vuln or not vuln.affected_purls:
            return None
        return vuln.affected_purls[0]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Evidence — what the probes found. Structured all the way; never stringified.
# ─────────────────────────────────────────────────────────────────────────────


class ExploitPathStep(BaseModel):
    file: str = ""
    line: Optional[int] = None
    symbol: str = ""
    detail: str = ""


class ExploitPath(BaseModel):
    path_id: str
    sink: str
    summary: str
    steps: list[ExploitPathStep] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reachable: bool = True


class MisconfigurationFinding(BaseModel):
    finding_id: str
    description: str
    evidence: str = ""
    relevant_to_cve: bool = True
    location: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class DeploymentFinding(BaseModel):
    finding_id: str
    condition_type: ConditionType
    description: str
    product_value: str = ""
    applies: bool = True
    network_exposed: Optional[bool] = Field(
        default=None,
        description="True if reachable from an untrusted network, False if isolated. "
        "Read directly by scoring; never inferred from prose.",
    )
    evidence: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class PathMitigationResult(BaseModel):
    path_id: str
    mitigation_description: str
    present: bool
    strength: MitigationStrength = MitigationStrength.NONE
    evidence: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    @property
    def blocks_exploitation(self) -> bool:
        return self.present and self.strength == MitigationStrength.HIGH


class PresenceEvidence(BaseModel):
    """Whether the vulnerable component is imported at all."""

    imported: Optional[bool] = None
    tokens: list[str] = Field(default_factory=list)
    hit_count: int = 0
    notes: str = ""


class EvidenceGap(BaseModel):
    """A probe that could not run. Never silently treated as a negative result."""

    probe: ProbeId
    reason: str


# Per-probe agent output contracts. These are what the LLM must return.


class ExploitPathEvidence(BaseModel):
    exploit_paths: list[ExploitPath] = Field(default_factory=list)
    notes: str = ""


class MisconfigEvidence(BaseModel):
    misconfigurations: list[MisconfigurationFinding] = Field(default_factory=list)
    notes: str = ""


class DeploymentEvidence(BaseModel):
    deployment_findings: list[DeploymentFinding] = Field(default_factory=list)
    applicability_falsified: bool = Field(
        default=False,
        description="True only when deployment context makes the CVE inapplicable.",
    )
    notes: str = ""


class MitigationEvidence(BaseModel):
    mitigations_by_path: list[PathMitigationResult] = Field(default_factory=list)
    notes: str = ""


class EvidenceSet(BaseModel):
    """Everything the probes established, flattened into one place.

    `ran` and `gaps` carry provenance: absence of a finding only means "not
    present" when the probe actually ran.
    """

    exploit_paths: list[ExploitPath] = Field(default_factory=list)
    misconfigurations: list[MisconfigurationFinding] = Field(default_factory=list)
    deployment_findings: list[DeploymentFinding] = Field(default_factory=list)
    mitigations: list[PathMitigationResult] = Field(default_factory=list)
    presence: Optional[PresenceEvidence] = None
    applicability_falsified: bool = False
    ran: list[ProbeId] = Field(default_factory=list)
    gaps: list[EvidenceGap] = Field(default_factory=list)
    notes: dict[str, str] = Field(default_factory=dict)

    def has_run(self, probe: ProbeId) -> bool:
        return probe in self.ran

    @property
    def sinks_hit(self) -> list[str]:
        return sorted({p.sink for p in self.exploit_paths})

    @property
    def unmitigated_paths(self) -> list[ExploitPath]:
        """Paths with no high-strength mitigation covering them."""
        blocked = {m.path_id for m in self.mitigations if m.blocks_exploitation}
        return [p for p in self.exploit_paths if p.path_id not in blocked]

    @property
    def network_exposed(self) -> Optional[bool]:
        """Tri-state network exposure from deployment findings.

        False wins over True: an explicit isolation finding is a stronger claim
        than a generic exposure one.
        """
        flags = [f.network_exposed for f in self.deployment_findings if f.network_exposed is not None]
        if not flags:
            return None
        return False if False in flags else True


# ─────────────────────────────────────────────────────────────────────────────
# 5. Plan and Verdict — the decisions
# ─────────────────────────────────────────────────────────────────────────────


class AssessmentPlan(BaseModel):
    """How this CVE will be assessed. Produced once, in core.policy."""

    activation_basis: ActivationBasis = ActivationBasis.UNKNOWN
    probes: list[ProbeId] = Field(default_factory=list)
    sink_gate: bool = False
    presence_check: bool = False
    notes: str = ""

    @property
    def skip_rescoring(self) -> bool:
        """Unknown basis means we cannot justify a rescore; flag for an analyst."""
        return self.activation_basis == ActivationBasis.UNKNOWN


class RiskVerdict(BaseModel):
    """The single risk decision. Nothing else in the codebase decides this."""

    activation_basis: ActivationBasis
    activation_state: ActivationState
    exploitable: bool
    fully_mitigated: bool = False
    unmitigated_path_count: int = 0
    sinks_hit: list[str] = Field(default_factory=list)
    rationale: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# 6. Report — the output
# ─────────────────────────────────────────────────────────────────────────────


class MetricAnswer(BaseModel):
    metric: str = Field(description="CVSS environmental metric id, e.g. MAV, CR")
    question: str = ""
    answer: str
    reason: str = ""
    source: AnswerSource = AnswerSource.BASE


class RiskAssessmentResult(BaseModel):
    """Top-level output for one CVE against one codebase."""

    cve_id: str
    component_purl: str
    original_base_vector: str
    original_base_score: float
    environmental_vector: str
    score: float
    severity: Severity
    rescored: bool = True
    skipped: bool = False
    skip_reason: str = ""
    exploitable: bool
    reason: str
    verdict: RiskVerdict
    plan: AssessmentPlan
    metric_answers: list[MetricAnswer] = Field(default_factory=list)
    evidence: EvidenceSet = Field(default_factory=EvidenceSet)
    scan_id: Optional[str] = None
    scan_dir: Optional[str] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def score_delta(self) -> float:
        return round(self.score - self.original_base_score, 1)
