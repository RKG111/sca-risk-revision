"""
CycloneDX SBOM input schema.
Models the subset of CycloneDX 1.5 that the platform consumes:
components (with PURLs) and their associated vulnerability ratings.
"""

from typing import Optional
from pydantic import BaseModel, Field


class CVSSRating(BaseModel):
    source_name: str = Field(alias="source_name", default="NVD")
    score: float
    severity: str
    method: str = "CVSSv31"
    vector: str

    model_config = {"populate_by_name": True}


class SBOMVulnerability(BaseModel):
    bom_ref: str = Field(alias="bom-ref")
    cve_id: str = Field(alias="id")
    source_url: Optional[str] = None
    ratings: list[CVSSRating] = []
    affected_purls: list[str] = []

    model_config = {"populate_by_name": True}

    @property
    def primary_rating(self) -> Optional[CVSSRating]:
        """Returns the NVD rating if present, otherwise the first available rating."""
        nvd = next((r for r in self.ratings if r.source_name.upper() == "NVD"), None)
        return nvd or (self.ratings[0] if self.ratings else None)


class SBOMComponent(BaseModel):
    bom_ref: str = Field(alias="bom-ref")
    name: str
    version: str
    purl: str
    group: Optional[str] = None
    publisher: Optional[str] = None

    model_config = {"populate_by_name": True}


class SBOMMetadata(BaseModel):
    product_name: str
    product_version: str


class CycloneDXSBOM(BaseModel):
    """Top-level CycloneDX SBOM. Parsed from the Black Duck / NVD output."""

    bom_format: str = Field(alias="bomFormat", default="CycloneDX")
    spec_version: str = Field(alias="specVersion", default="1.5")
    metadata: Optional[SBOMMetadata] = None
    components: list[SBOMComponent] = []
    vulnerabilities: list[SBOMVulnerability] = []

    model_config = {"populate_by_name": True}

    def get_component_by_purl(self, purl: str) -> Optional[SBOMComponent]:
        return next((c for c in self.components if c.purl == purl), None)

    def get_vulnerability(self, cve_id: str) -> Optional[SBOMVulnerability]:
        return next((v for v in self.vulnerabilities if v.cve_id == cve_id), None)
