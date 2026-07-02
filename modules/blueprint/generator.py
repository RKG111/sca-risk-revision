"""
Module 2 — Attack Blueprint Generator

Uses Claude Sonnet (via LLMaS OpenAI-compatible API) and the `instructor`
library to generate a structured AttackBlueprint from:
  - Raw CVE data from NVD
  - SBOM vulnerability and component context

`instructor` enforces that the LLM response validates against the
AttackBlueprint Pydantic schema before it is returned.
"""

import logging
from typing import Any, Optional

import instructor
from openai import OpenAI

from api.config import settings
from schemas.sbom import SBOMVulnerability, SBOMComponent
from schemas.blueprint import AttackBlueprint

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert security researcher specialising in vulnerability analysis and CVSS rescoring.

Your task is to analyse a CVE and generate a precise, machine-readable Attack Blueprint.
This blueprint will drive automated code analysis tools — it must be technically accurate and concrete.

Guidelines:
- `vulnerable_symbol` must be the exact function/method name that is dangerous (e.g. "yaml.load", "Constructor")
- `indicators_of_reachability` must be literal strings or AST patterns a static tool can search for
- `assessment_strategy` should be DETERMINISTIC when the vulnerability can be proven via taint analysis or AST matching;
  use AGENT when it requires semantic understanding of business logic or deployment context
- CVSS override values must use the official v3.1 single-letter codes (N/A/L/P for AV, L/H for AC, etc.)
- Be conservative: if unsure whether a path is reachable, prefer not to downgrade
"""


def _build_user_prompt(
    cve_id: str,
    nvd_data: dict[str, Any],
    vuln: SBOMVulnerability,
    component: Optional[SBOMComponent],
) -> str:
    rating = vuln.primary_rating
    component_str = (
        f"{component.name} {component.version} ({component.purl})"
        if component
        else "unknown component"
    )
    return f"""
Analyse the following vulnerability and generate an Attack Blueprint.

## CVE Information
CVE ID: {cve_id}
Component: {component_str}
NVD Description: {nvd_data.get('description', 'N/A')}
CWEs: {', '.join(nvd_data.get('weaknesses', [])) or 'Not specified'}
NVD CVSS v3.1 Vector: {nvd_data.get('cvss_v31', {}).get('vectorString', 'N/A')}
NVD CVSS Score: {rating.score if rating else 'N/A'}

## CVSS Base Metrics (from NVD)
{_format_cvss(nvd_data.get('cvss_v31', {}))}

## References
{chr(10).join(nvd_data.get('references', [])[:3])}

Generate a complete AttackBlueprint for this CVE. Be specific about:
1. The exact vulnerable symbol and package context
2. Whether deterministic static analysis can resolve this, or if agent reasoning is required
3. The precise code-level indicators of reachability
4. How the deployment environment affects exploitability
5. The true impact vectors considering a real-world exploitation scenario
""".strip()


def _format_cvss(cvss: dict) -> str:
    if not cvss:
        return "Not available"
    keys = ["attackVector", "attackComplexity", "privilegesRequired",
            "userInteraction", "scope", "confidentialityImpact",
            "integrityImpact", "availabilityImpact"]
    return "\n".join(f"  {k}: {cvss.get(k, 'N/A')}" for k in keys)


class BlueprintGenerator:
    """
    Calls Claude Sonnet via LLMaS and uses instructor to enforce
    structured output conforming to AttackBlueprint.
    """

    def __init__(self):
        raw_client = OpenAI(
            base_url=settings.llmas_base_url,
            api_key=settings.llmas_api_key,
        )
        self._client = instructor.from_openai(raw_client)

    async def generate(
        self,
        vuln: SBOMVulnerability,
        nvd_data: dict[str, Any],
        component: Optional[SBOMComponent] = None,
    ) -> AttackBlueprint:
        cve_id = vuln.cve_id
        logger.info("Generating blueprint for %s using %s", cve_id, settings.llmas_model)

        user_prompt = _build_user_prompt(cve_id, nvd_data, vuln, component)

        blueprint: AttackBlueprint = self._client.chat.completions.create(
            model=settings.llmas_model,
            response_model=AttackBlueprint,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_retries=3,
        )

        logger.info(
            "Blueprint generated: strategy=%s, feasibility=%s",
            blueprint.assessment_strategy,
            blueprint.deterministic_verification_feasibility,
        )
        return blueprint
