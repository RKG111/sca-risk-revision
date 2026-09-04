"""Experiment: can gortex CFG facts reproduce the taint evidence S1 needs?

Runs the composed taint analysis against each sample CVE and prints the
source-to-sink paths with their citations, so the output can be compared
against what Joern's reachableByFlows would have returned.

    python scripts/gortex_taint_experiment.py samples/python/CVE-2020-14343-pyyaml
    python scripts/gortex_taint_experiment.py --all
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.gortex import GortexClient, find_taint_paths  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def blueprint_sinks(sample: Path) -> list[str]:
    blueprint = json.loads((sample / "blueprint.json").read_text(encoding="utf-8"))
    upstream = blueprint.get("upstream_artifacts") or {}
    return list(upstream.get("functions") or [])


def route_entry_points(client: GortexClient, repo: str) -> list[str]:
    """Route handlers, from the contracts layer, as request-controlled entries."""
    contracts = client.contracts(all_repos=True)
    entries: list[str] = []
    for repo_name, bucket in (contracts.get("by_repo") or {}).items():
        if repo_name != repo:
            continue
        for rows in (bucket.get("contracts") or {}).values():
            for row in rows:
                symbol = row.get("symbol_id")
                if symbol:
                    entries.append(symbol)
    return entries


def run(client: GortexClient, sample: Path) -> int:
    repo = sample.name
    sinks = blueprint_sinks(sample)

    started = time.perf_counter()
    entries = route_entry_points(client, repo)
    findings = find_taint_paths(
        client, sinks=sinks, repo=repo, entry_points=entries, include_latent=True
    )
    elapsed = time.perf_counter() - started

    print(f"\n{'=' * 78}\n{repo}")
    print(f"  blueprint sinks : {sinks}")
    print(f"  route entries   : {entries or '(none linked)'}")
    print(f"  findings        : {len(findings)}  in {elapsed:.2f}s")

    for finding in findings:
        hops = finding.crossed_functions
        span = f"{hops + 1} functions" if hops else "1 function"
        print(f"\n  [{finding.evidence} | {span}] {finding.source} -> {finding.sink}")
        for step in finding.steps:
            location = f"{step.file}:{step.line}"
            print(f"    {step.kind:<10} {location:<58} {step.statement}")

    return len(findings)


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--all":
        samples = sorted(
            p.parent
            for p in ROOT.glob("samples/**/blueprint.json")
        )
    else:
        samples = [Path(argv[0] if argv else "samples/python/CVE-2020-14343-pyyaml")]

    with GortexClient() as client:
        if not client.is_up():
            print("daemon not reachable on 127.0.0.1:7411")
            return 1
        total = sum(run(client, ROOT / s if not s.is_absolute() else s) for s in samples)

    print(f"\n{'=' * 78}\ntotal findings across {len(samples)} sample(s): {total}")
    return 0 if total else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
