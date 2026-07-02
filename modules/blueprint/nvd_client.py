"""
Module 2 — NVD API v2 Client

Fetches CVE details from the National Vulnerability Database.
Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  Without API key: 5 requests per 30 seconds
  With API key:    50 requests per 30 seconds
Set NVD_API_KEY in .env to get the higher limit.
"""

import logging
from typing import Any, Optional

import httpx

from api.config import settings

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClientError(Exception):
    pass


class NVDClient:
    """Async client for the NVD REST API v2."""

    def __init__(self):
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        self._client = httpx.AsyncClient(headers=headers, timeout=30.0)

    async def fetch(self, cve_id: str) -> dict[str, Any]:
        """
        Fetches full CVE details including description, CWE, CVSS vectors,
        and CPE applicability from NVD.

        Returns a flat dict with the most useful fields extracted.
        """
        params = {"cveId": cve_id}
        try:
            resp = await self._client.get(NVD_BASE_URL, params=params)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise NVDClientError(f"NVD returned {exc.response.status_code} for {cve_id}") from exc

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            raise NVDClientError(f"CVE {cve_id} not found in NVD")

        raw_cve = vulnerabilities[0]["cve"]
        return self._extract(cve_id, raw_cve)

    def _extract(self, cve_id: str, raw: dict) -> dict[str, Any]:
        """Extracts a clean, flat dict from the raw NVD CVE response."""
        description = next(
            (d["value"] for d in raw.get("descriptions", []) if d.get("lang") == "en"),
            "No description available.",
        )

        weaknesses = []
        for w in raw.get("weaknesses", []):
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc["value"])

        cvss_v31: Optional[dict] = None
        for metric in raw.get("metrics", {}).get("cvssMetricV31", []):
            if metric.get("type") == "Primary":
                cvss_v31 = metric.get("cvssData", {})
                break

        references = [r["url"] for r in raw.get("references", [])[:5]]

        return {
            "cve_id": cve_id,
            "description": description,
            "published": raw.get("published"),
            "last_modified": raw.get("lastModified"),
            "weaknesses": weaknesses,
            "cvss_v31": cvss_v31,
            "references": references,
        }

    async def close(self):
        await self._client.aclose()
