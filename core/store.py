"""
Blueprint lookup.

Blueprints are trusted research artefacts on disk, keyed by CVE id plus a
*versioned* PURL. Matching is exact by design: a blueprint researched against
pyyaml 5.3.1 says nothing about 6.0, so near-misses are treated as absent.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from core.models import Blueprint

logger = logging.getLogger(__name__)

_PURL_PATTERN = re.compile(r"^(pkg:[^/]+/)(.+?)(@.+)?$", re.IGNORECASE)


def normalise_purl(purl: str) -> str:
    """Lowercase the type and name, keep the version, drop qualifiers."""
    purl = purl.strip().split("?")[0].split("#")[0]
    match = _PURL_PATTERN.match(purl)
    if not match:
        return purl.lower()
    prefix, name, version = match.group(1).lower(), match.group(2).lower(), (match.group(3) or "")
    return f"{prefix}{name}{version}"


def package_tokens(purl: str, component_name: str | None = None) -> list[str]:
    """Import-name candidates for a package, for presence checks.

    pkg:pypi/pyyaml@5.3.1                          -> pyyaml
    pkg:npm/ua-parser-js@0.7.29                    -> ua-parser-js, ua_parser_js, uaparserjs
    pkg:maven/org.apache.logging.log4j/log4j-core  -> log4j-core, log4j_core, log4j
    """
    name = ""
    raw = (purl or "").strip().split("?")[0].split("#")[0]
    candidates: list[str] = []

    if raw.lower().startswith("pkg:"):
        _, _, remainder = raw.partition(":")
        _, _, path = remainder.partition("/")
        segments = path.split("@")[0].split("/")
        name = segments[-1]
        if len(segments) > 1 and segments[-2]:
            # Maven-style namespace: org.apache.logging.log4j -> log4j
            candidates.append(segments[-2].split(".")[-1])

    name = name or (component_name or "")
    for value in (name, component_name or ""):
        if not value:
            continue
        candidates.append(value)
        candidates.append(value.replace("-", "_"))
        candidates.append(value.replace("-", ""))
        candidates.append(value.replace("_", "-"))
        for suffix in ("-core", "-api", "-client", "-server"):
            if value.endswith(suffix) and len(value) > len(suffix) + 2:
                candidates.append(value[: -len(suffix)])

    seen: set[str] = set()
    tokens: list[str] = []
    for token in candidates:
        token = token.strip()
        if len(token) < 2 or token.lower() in seen:
            continue
        seen.add(token.lower())
        tokens.append(token)
    return tokens


class BlueprintStore:
    """Directory of blueprint JSON files, indexed on first use."""

    def __init__(self, store_path: str | Path):
        self.store_path = Path(store_path)
        self._by_key: dict[tuple[str, str], Blueprint] = {}
        self._loaded = False

    def load(self) -> int:
        """Index every *.json under the store path. Returns the file count."""
        self._by_key.clear()
        self._loaded = True

        if not self.store_path.exists():
            logger.warning("Blueprint store not found: %s", self.store_path)
            return 0

        count = 0
        for path in sorted(self.store_path.rglob("*.json")):
            try:
                blueprint = Blueprint.model_validate(json.loads(path.read_text(encoding="utf-8")))
            except Exception as exc:
                logger.warning("Skipping invalid blueprint %s: %s", path, exc)
                continue
            for component in blueprint.affected_components:
                self._by_key[(blueprint.cve_id.upper(), normalise_purl(component.purl))] = blueprint
            count += 1

        logger.info("Loaded %d blueprint(s), %d key(s), from %s", count, len(self._by_key), self.store_path)
        return count

    def get(self, cve_id: str, purl: str) -> Optional[Blueprint]:
        if not self._loaded:
            self.load()
        return self._by_key.get((cve_id.upper(), normalise_purl(purl)))

    def cve_ids(self) -> list[str]:
        if not self._loaded:
            self.load()
        return sorted({cve for cve, _ in self._by_key})
