"""Interprocedural taint analysis composed from gortex CFG facts.

Gortex ships ``taint_paths`` and ``flow_between``, but both walk the
``value_flow`` / ``arg_of`` / ``returns_to`` edge layer, which is not populated
for every language — on our Python fixtures they return nothing. What *is*
reliable is ``get_cfg``, which returns per-statement ``defs`` / ``uses`` plus
parameter declarations, for every bespoke-tier language.

This module walks those CFG facts to build the source-to-sink paths the risk
assessment needs. Propagation is intra-procedural per function; calls are
followed by mapping a tainted argument onto the callee's parameter, which is
what makes a path interprocedural.

Callees are resolved by *name*, from the calling statement's own text, rather
than from graph ``calls`` edges. That is deliberate: gortex frequently fails to
emit a ``calls`` edge for a call through an imported module, so relying on the
edge layer would lose exactly the paths we care about.

Limitations, stated so callers can gate on them:

- Propagation walks statements in flattened block order, so it approximates
  reaching definitions rather than solving them per branch.
- Field and container element taint is tracked at whole-variable granularity.
- Aliasing through data structures is not modelled.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from agent.gortex.client import GortexClient

logger = logging.getLogger(__name__)

MAX_DEPTH = 5

# Statement shapes that read request-controlled data. Matched against the whole
# statement text, because the identifier alone is often uninformative — Go's
# `r.Body` and Python's `request.data` both hang off a bare receiver name.
DEFAULT_SOURCE_PATTERNS = (
    "request.",
    "request,",
    "req.",
    ".Body",
    ".Header",
    ".Query(",
    ".FormValue(",
    ".PostForm",
    ".URL",
    ".get_data(",
    ".getParameter(",
    ".getInputStream(",
    ".getReader(",
    "os.Getenv",
    "os.environ",
    "process.env",
    "sys.argv",
    "input(",
)


@dataclass
class TaintStep:
    """One statement on a taint path, citable as file/line evidence."""

    symbol_id: str
    file: str
    line: Optional[int]
    statement: str
    variable: str
    kind: str  # source | propagate | call | sink

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "file": self.file,
            "line": self.line,
            "statement": self.statement,
            "variable": self.variable,
            "kind": self.kind,
        }


# How much weight a finding carries. Downstream scoring must not treat these
# alike: only REQUEST_REACHABLE is evidence that untrusted input reaches a sink.
REQUEST_REACHABLE = "request_reachable"
LATENT_PARAMETER = "latent_parameter"
TEXT_ONLY = "text_only"

EVIDENCE_NOTES = {
    REQUEST_REACHABLE: "def/use path from a request-controlled read to the sink",
    LATENT_PARAMETER: "sink reachable from a parameter, but no indexed caller supplies it",
    TEXT_ONLY: "sink present in source but absent from every CFG — no dataflow proof",
}


@dataclass
class TaintFinding:
    """A source-to-sink path with the statements that justify it."""

    source: str
    sink: str
    entry_symbol: str
    sink_symbol: str
    steps: list[TaintStep] = field(default_factory=list)
    crossed_functions: int = 0
    evidence: str = REQUEST_REACHABLE

    @property
    def interprocedural(self) -> bool:
        return self.crossed_functions > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "sink": self.sink,
            "entry_symbol": self.entry_symbol,
            "sink_symbol": self.sink_symbol,
            "evidence": self.evidence,
            "evidence_note": EVIDENCE_NOTES.get(self.evidence, ""),
            "interprocedural": self.interprocedural,
            "functions_crossed": self.crossed_functions,
            "steps": [s.to_dict() for s in self.steps],
        }


# ── CFG access ───────────────────────────────────────────────────────────────


@dataclass
class _Statement:
    line: Optional[int]
    text: str
    defs: tuple[str, ...]
    uses: tuple[str, ...]
    kind: str


def _flatten_cfg(cfg: dict[str, Any]) -> list[_Statement]:
    """Statements in a walkable order: parameters first, then block order."""
    params: list[_Statement] = []
    body: list[_Statement] = []

    for block in cfg.get("blocks") or []:
        for raw in block.get("statements") or []:
            statement = _Statement(
                line=raw.get("start_line"),
                text=str(raw.get("text") or ""),
                defs=tuple(raw.get("defs") or ()),
                uses=tuple(raw.get("uses") or ()),
                kind=str(raw.get("kind") or "stmt"),
            )
            if statement.kind == "param":
                params.append(statement)
            else:
                body.append(statement)

    body.sort(key=lambda s: (s.line if s.line is not None else 0))
    return params + body


# ── matching helpers ─────────────────────────────────────────────────────────


def _leaf(name: str) -> str:
    """Last dotted segment: ``yaml.full_load`` → ``full_load``."""
    return name.rsplit(".", 1)[-1].strip()


def _matches_sink(text: str, patterns: Iterable[str]) -> Optional[str]:
    """Blueprint sinks are dotted names; match the final segment as a whole word.

    Whole-word matching is load-bearing rather than cosmetic. A substring test
    for the sink ``yaml.load`` also fires on ``yaml.safe_load`` (the mitigation)
    and on any unrelated identifier containing the letters, such as
    ``handle_upload`` — turning both into false exploit paths.
    """
    lowered = text.lower()
    for pattern in patterns:
        leaf = _leaf(pattern).lower()
        if leaf and re.search(rf"\b{re.escape(leaf)}\b", lowered):
            return pattern
    return None


def _matches_source(text: str, patterns: Iterable[str]) -> Optional[str]:
    """Source patterns are statement shapes; match them literally."""
    lowered = text.lower()
    for pattern in patterns:
        if pattern.lower() in lowered:
            return pattern
    return None


def _param_name(statement: "_Statement") -> str:
    """Parameter identifier — ``defs`` is more reliable than the raw text."""
    if statement.defs:
        return statement.defs[0]
    return statement.text.strip()


_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _split_args(text: str, open_paren: int) -> list[str]:
    """Split a call's argument list on top-level commas."""
    depth = 0
    current: list[str] = []
    args: list[str] = []
    for char in text[open_paren:]:
        if char in "([{":
            depth += 1
            if depth == 1:
                continue
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return [a.strip() for a in args]
        if depth == 1 and char == ",":
            args.append("".join(current))
            current = []
            continue
        current.append(char)
    args.append("".join(current))
    return [a.strip() for a in args]


def _tainted_arg_positions(text: str, callee: str, tainted: set[str]) -> list[int]:
    """Which argument positions of ``callee(...)`` hold a tainted variable."""
    positions: list[int] = []
    for match in _CALL_RE.finditer(text):
        if match.group(1) != callee:
            continue
        args = _split_args(text, match.end() - 1)
        for index, arg in enumerate(args):
            names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", arg))
            if names & tainted:
                positions.append(index)
    return positions


# ── the walk ─────────────────────────────────────────────────────────────────


class _Analyzer:
    def __init__(
        self,
        client: GortexClient,
        *,
        source_tokens: tuple[str, ...],
        sink_patterns: tuple[str, ...],
        max_depth: int,
        repo: Optional[str] = None,
    ) -> None:
        self._client = client
        self._sources = source_tokens
        self._sinks = sink_patterns
        self._max_depth = max_depth
        self._repo = repo
        self._cfg_cache: dict[str, list[_Statement]] = {}
        self._by_name: dict[str, list[dict[str, Any]]] = {}
        self._by_id: dict[str, dict[str, Any]] = {}
        self.findings: list[TaintFinding] = []

    def load_symbols(self) -> int:
        for node in self._client.functions(repo=self._repo):
            node_id = node.get("id")
            if not node_id:
                continue
            self._by_id[node_id] = node
            self._by_name.setdefault(_leaf(str(node.get("name") or "")), []).append(node)
        return len(self._by_id)

    def symbol_ids(self) -> list[str]:
        return list(self._by_id)

    def cfg(self, symbol_id: str) -> list[_Statement]:
        if symbol_id not in self._cfg_cache:
            try:
                self._cfg_cache[symbol_id] = _flatten_cfg(self._client.get_cfg(symbol_id))
            except Exception as exc:  # a CFG-less symbol must not abort the sweep
                logger.debug("no CFG for %s: %s", symbol_id, exc)
                self._cfg_cache[symbol_id] = []
        return self._cfg_cache[symbol_id]

    def analyze_all(self) -> None:
        for symbol_id in self.symbol_ids():
            self.analyze(symbol_id, tainted=set(), seed_params=False)

    def analyze_entry(self, symbol_id: str) -> None:
        """Treat every parameter of ``symbol_id`` as request-controlled."""
        self.analyze(symbol_id, tainted=set(), seed_params=True)

    def analyze(
        self,
        symbol_id: str,
        *,
        tainted: set[str],
        seed_params: bool,
        prefix: Optional[list[TaintStep]] = None,
        depth: int = 0,
        entry_symbol: Optional[str] = None,
        origin: str = "",
        visited: Optional[frozenset[str]] = None,
    ) -> None:
        if depth > self._max_depth:
            return
        visited = (visited or frozenset()) | {symbol_id}

        node = self._by_id.get(symbol_id) or {}
        file_path = str(node.get("file_path") or "")
        statements = self.cfg(symbol_id)
        if not statements:
            return

        local = set(tainted)
        steps = list(prefix or [])
        entry = entry_symbol or symbol_id
        source_label = origin

        # Seeded parameters are recorded but not emitted yet. A handler takes
        # several — Go's (w, r), Express's (req, res) — and only the one that
        # actually carries taint to the sink belongs in the citation list.
        param_steps: dict[str, TaintStep] = {}

        for statement in statements:
            if statement.kind == "param":
                if seed_params:
                    name = _param_name(statement)
                    local.add(name)
                    param_steps[name] = TaintStep(
                        symbol_id=symbol_id,
                        file=file_path,
                        line=statement.line,
                        statement=f"parameter {name}",
                        variable=name,
                        kind="source",
                    )
                continue

            # A statement reading request-controlled data introduces taint.
            introduced = _matches_source(statement.text, self._sources)
            if introduced and not (set(statement.uses) & local):
                local.update(statement.defs)
                source_label = source_label or introduced
                steps.append(
                    TaintStep(
                        symbol_id=symbol_id,
                        file=file_path,
                        line=statement.line,
                        statement=statement.text,
                        variable=", ".join(statement.defs) or introduced,
                        kind="source",
                    )
                )
                continue

            carried = set(statement.uses) & local
            if not carried:
                continue

            # Now that a parameter is known to carry taint, cite it.
            for name in sorted(carried):
                step = param_steps.pop(name, None)
                if step is not None:
                    steps.append(step)
                    source_label = source_label or f"parameter {name}"

            variable = ", ".join(sorted(carried))

            # Does this statement hand a tainted value to a blueprint sink?
            sink = _matches_sink(statement.text, self._sinks)
            if sink:
                self.findings.append(
                    TaintFinding(
                        source=source_label or "untrusted input",
                        sink=sink,
                        entry_symbol=entry,
                        sink_symbol=symbol_id,
                        steps=steps
                        + [
                            TaintStep(
                                symbol_id=symbol_id,
                                file=file_path,
                                line=statement.line,
                                statement=statement.text,
                                variable=variable,
                                kind="sink",
                            )
                        ],
                        crossed_functions=depth,
                    )
                )
                continue

            # Otherwise propagate, and follow any call that receives the taint.
            self._follow_calls(
                statement=statement,
                local=local,
                steps=steps,
                symbol_id=symbol_id,
                file_path=file_path,
                depth=depth,
                entry=entry,
                source_label=source_label,
                visited=visited,
                variable=variable,
            )

            if statement.defs:
                local.update(statement.defs)
                steps.append(
                    TaintStep(
                        symbol_id=symbol_id,
                        file=file_path,
                        line=statement.line,
                        statement=statement.text,
                        variable=variable,
                        kind="propagate",
                    )
                )

    def _follow_calls(
        self,
        *,
        statement: _Statement,
        local: set[str],
        steps: list[TaintStep],
        symbol_id: str,
        file_path: str,
        depth: int,
        entry: str,
        source_label: str,
        visited: frozenset[str],
        variable: str,
    ) -> None:
        for match in _CALL_RE.finditer(statement.text):
            callee_name = match.group(1)
            candidates = self._by_name.get(callee_name) or []
            for candidate in candidates:
                callee_id = str(candidate.get("id") or "")
                if not callee_id or callee_id in visited:
                    continue

                positions = _tainted_arg_positions(statement.text, callee_name, local)
                if not positions:
                    continue

                callee_params = [
                    _param_name(s) for s in self.cfg(callee_id) if s.kind == "param"
                ]
                promoted = {
                    callee_params[p] for p in positions if p < len(callee_params)
                }
                if not promoted:
                    continue

                call_step = TaintStep(
                    symbol_id=symbol_id,
                    file=file_path,
                    line=statement.line,
                    statement=statement.text,
                    variable=variable,
                    kind="call",
                )
                self.analyze(
                    callee_id,
                    tainted=promoted,
                    seed_params=False,
                    prefix=steps + [call_step],
                    depth=depth + 1,
                    entry_symbol=entry,
                    origin=source_label,
                    visited=visited,
                )


def find_taint_paths(
    client: GortexClient,
    *,
    sinks: Iterable[str],
    repo: Optional[str] = None,
    sources: Iterable[str] = (),
    entry_points: Iterable[str] = (),
    max_depth: int = MAX_DEPTH,
    include_latent: bool = False,
) -> list[TaintFinding]:
    """Find source-to-sink paths for the blueprint's sinks.

    ``sinks`` are blueprint sink names (``yaml.full_load``, ``FullLoader``).
    ``repo`` confines the sweep to one tracked repository. ``sources``
    overrides the default request-shaped statement patterns. ``entry_points``
    are symbol ids — typically route handlers from ``contracts`` — whose
    parameters are treated as request-controlled.

    ``include_latent`` additionally seeds every function's parameters, which
    surfaces a sink reachable from a parameter that no indexed caller supplies.
    Those are real latent exposure for a library, but they are not proof that a
    request reaches the sink, so they arrive flagged rather than mixed in.
    """
    sink_patterns = tuple(s for s in sinks if s)
    if not sink_patterns:
        return []

    analyzer = _Analyzer(
        client,
        source_tokens=tuple(sources) or DEFAULT_SOURCE_PATTERNS,
        sink_patterns=sink_patterns,
        max_depth=max_depth,
        repo=repo,
    )
    count = analyzer.load_symbols()
    logger.info("taint sweep over %d symbols for sinks %s", count, list(sink_patterns))

    for entry in entry_points:
        analyzer.analyze_entry(entry)
    analyzer.analyze_all()
    confirmed = _dedupe(analyzer.findings)

    if not include_latent:
        return confirmed

    latent = _Analyzer(
        client,
        source_tokens=tuple(sources) or DEFAULT_SOURCE_PATTERNS,
        sink_patterns=sink_patterns,
        max_depth=max_depth,
        repo=repo,
    )
    latent.load_symbols()
    for symbol_id in latent.symbol_ids():
        latent.analyze_entry(symbol_id)

    seen = {(f.sink_symbol, f.steps[-1].line if f.steps else None) for f in confirmed}
    extra = [
        f
        for f in _dedupe(latent.findings)
        if (f.sink_symbol, f.steps[-1].line if f.steps else None) not in seen
    ]
    for finding in extra:
        finding.evidence = LATENT_PARAMETER

    results = confirmed + extra
    return results + _text_only_findings(
        client, sink_patterns, repo=repo, covered=results
    )


def _text_only_findings(
    client: GortexClient,
    sink_patterns: tuple[str, ...],
    *,
    repo: Optional[str],
    covered: list[TaintFinding],
) -> list[TaintFinding]:
    """Sinks that appear in source but in no CFG.

    Gortex elides closure bodies from the enclosing function's CFG and refuses
    ``get_cfg`` on a closure outright, so a sink inside an inline route handler
    — ``r.GET("/x", func(c *gin.Context) {...})`` — has no def/use facts to walk.
    Reporting nothing there would read downstream as "not exploitable", which is
    a different claim from "not analysable". These come back explicitly weak.
    """
    covered_lines = {
        (step.file, step.line) for finding in covered for step in finding.steps
    }
    source_paths = {
        f"{f.get('repo')}/{f.get('path')}" for f in client.source_files(repo=repo)
    }

    findings: list[TaintFinding] = []
    emitted: set[tuple[str, Any]] = set()
    for pattern in sink_patterns:
        leaf = _leaf(pattern)
        try:
            matches = client.search_text(leaf)
        except Exception as exc:
            logger.debug("text fallback failed for %s: %s", pattern, exc)
            continue

        # search_text matches substrings, so it also returns docstrings,
        # imports and near-miss identifiers — "load" hits "payload",
        # "handle_upload" and "safe_load". Keep only whole-word call sites.
        call_site = re.compile(rf"\b{re.escape(leaf)}\s*\(")

        for match in matches:
            path = str(match.get("path") or "")
            line = match.get("line")
            text = str(match.get("text") or "").strip()
            if path not in source_paths or (path, line) in covered_lines:
                continue
            if (path, line) in emitted or not call_site.search(text):
                continue
            emitted.add((path, line))
            symbol = str(match.get("symbol_id") or path)
            findings.append(
                TaintFinding(
                    source="unknown — no dataflow facts for this location",
                    sink=pattern,
                    entry_symbol=symbol,
                    sink_symbol=symbol,
                    steps=[
                        TaintStep(
                            symbol_id=symbol,
                            file=path,
                            line=line,
                            statement=text,
                            variable="",
                            kind="sink",
                        )
                    ],
                    evidence=TEXT_ONLY,
                )
            )
    return findings


def _dedupe(findings: list[TaintFinding]) -> list[TaintFinding]:
    """Collapse paths that end at the same sink statement, keeping the longest."""
    best: dict[tuple[str, Optional[int]], TaintFinding] = {}
    for finding in findings:
        sink_step = finding.steps[-1] if finding.steps else None
        key = (sink_step.symbol_id if sink_step else "", sink_step.line if sink_step else None)
        incumbent = best.get(key)
        if incumbent is None or len(finding.steps) > len(incumbent.steps):
            best[key] = finding
    return sorted(best.values(), key=lambda f: (f.sink_symbol, f.steps[-1].line or 0))
