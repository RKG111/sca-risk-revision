"""
Typed failure modes.

The system is agent-only: there is no deterministic fallback to quietly take
over when something is unavailable. So every unavailability is an explicit,
typed failure that ends up visible in the report as an evidence gap. Silence
would be indistinguishable from "we checked and found nothing".
"""

from __future__ import annotations


class CoreError(Exception):
    """Base class for every failure this package raises."""


class ConfigError(CoreError):
    """Configuration is missing or inconsistent."""


class BlueprintNotFound(CoreError):
    """No trusted blueprint for this (CVE, component) pair."""


class JoernUnavailable(CoreError):
    """Joern is not reachable, or a CPG query failed."""


class LLMUnavailable(CoreError):
    """The model endpoint could not be reached or refused the request."""


class EvidenceUnavailable(CoreError):
    """A probe could not produce evidence.

    Raised rather than returning empty evidence, because "no findings" and
    "could not look" must never collapse into the same value.
    """

    def __init__(self, probe: str, reason: str):
        self.probe = probe
        self.reason = reason
        super().__init__(f"{probe}: {reason}")
