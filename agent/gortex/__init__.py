"""Gortex-backed code intelligence: HTTP client and interprocedural taint."""

from agent.gortex.client import GortexClient, GortexError
from agent.gortex.taint import (
    LATENT_PARAMETER,
    REQUEST_REACHABLE,
    TEXT_ONLY,
    TaintFinding,
    TaintStep,
    find_taint_paths,
)

__all__ = [
    "GortexClient",
    "GortexError",
    "LATENT_PARAMETER",
    "REQUEST_REACHABLE",
    "TEXT_ONLY",
    "TaintFinding",
    "TaintStep",
    "find_taint_paths",
]
