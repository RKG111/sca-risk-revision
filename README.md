# SCA Risk Rescoring Platform — POC

Most CVEs reported against a codebase do not matter to it. This service works out
which ones do, and rescores them for *your* product rather than for the world.

It takes a CycloneDX SBOM, a CVE id and a codebase; it returns an environmental
CVSS score plus the evidence behind it.

## How it works

Four LLM agents ("probes") gather evidence from the code. One policy module turns
that evidence into a single verdict. One scoring module turns the verdict into a
CVSS score.

```
CycloneDX SBOM + CVE id + codebase
          │
          ▼
  1. resolve   which component the CVE affects
  2. lookup    the trusted blueprint for that (CVE, versioned PURL)
  3. plan      how activation will be judged, and which probes can show it
          │
          ▼
  4. gather    S1 exploit paths    ┐
               S2 misconfiguration ├─ agents, with Joern CPG + file tools
               S3 deployment       │
               S4 mitigations      ┘  (S4 waits for S1)
          │
          ▼
  5. decide    one RiskVerdict: activated? exploitable?
  6. score     environmental CVSS, with policy clamps applied last
```

Two properties are worth knowing up front, because they shape everything else:

**Evidence comes only from agents.** There is no parallel deterministic
implementation to fall back on. When a probe cannot run, that is recorded as an
evidence gap and the verdict becomes *inconclusive* — never "safe". A silent
fallback would make "we checked and found nothing" indistinguishable from
"we could not check", which is the difference between a real result and a guess.

**Only `core/policy.py` decides anything.** Scoring consumes the verdict; it
never re-derives exploitability. Agents report findings; they never conclude.

## Layout

One flat package, one concept per file. Read it in this order:

```
core/models.py     every data shape: blueprint, SBOM, evidence, verdict, report
core/config.py     the single settings source, and the generator for derived files
core/errors.py     typed failures
core/store.py      blueprint lookup
core/joern.py      the only code that talks to Joern
core/llm.py        the only code that talks to the model
core/tools.py      the toolbelt handed to agents
core/agent.py      the one agent loop
core/probes.py     the four evidence questions, side by side
core/policy.py     the only code that decides activation and exploitability
core/scoring.py    CVSS vector, metric adjudication, arithmetic
core/pipeline.py   wiring — the only entry point you need
core/prompts/      S1–S4 agent instructions

api/main.py        HTTP transport, nothing else
blueprints/        trusted component–CVE research
third_party/       vendored Joern MCP server
```

## Quick start

```bash
cp .env.example .env
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Joern must be installed on the host (not Docker), e.g.:
#   https://github.com/joernio/joern/releases  →  joern on PATH (/usr/local/bin/joern)

./scripts/stack.sh start     # Ollama + native Joern + mcp-joern + API
./scripts/stack.sh status
```

```python
from core.models import CycloneDXSBOM
from core.pipeline import assess

report = await assess(sbom=sbom, cve_id="CVE-2020-14343", codebase_path=Path("./target"))
print(report.score, report.exploitable, report.verdict.rationale)
```

### API

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/sample_request.json
# → {"job_id": "...", "status": "queued"}

curl http://localhost:8000/api/v1/reports/{job_id}
```

## Services

| Service | Role |
|---|---|
| Ollama | The model behind the probes and CVSS adjudication |
| Joern | Native CPG server on `:16162` (`joern` on PATH via `joern-run.sh`) |
| mcp-joern | FastMCP SSE on `:8001/sse`, exposing CPG tools to agents |
| FastAPI | `/api/v1/analyze`, `/api/v1/analyze/blueprint`, `/api/v1/reports/{id}` |

`core/joern.py` and mcp-joern are two transports to the same Joern server: the
service uses HTTP for its own lookups, agents use MCP tools. Neither is a
fallback for the other.

## Tests

The suite is offline and deterministic. Agent replies are scripted (see
`tests/fake_llm.py`), so policy and scoring — which *are* deterministic given
fixed evidence — can be asserted exactly.

```bash
PYTHONPATH=. pytest              # everything, offline
PYTHONPATH=. pytest -m live      # the subset needing a running stack
```

`tests/golden/baseline_verdict.json` pins the decision for the sample fixture,
and is what proves the rebuild preserved behaviour. Change it deliberately:

```bash
REWRITE_GOLDEN=1 PYTHONPATH=. pytest tests/test_baseline.py
```

## Configuration

`core/config.py` is the only source of configuration. Every value comes from
`.env` (see `.env.example`), and files that would otherwise duplicate those
values are generated:

```bash
python -m core.config    # writes mcp_servers.json + third_party/.../mcp_settings.json
```

Do not hand-edit those two files; they carry a `_generated_by` marker.

## Extending

**Add a probe.** Write `core/prompts/S5.md`, add its output contract to
`core/models.py`, add a context builder plus one `PROBES` entry in
`core/probes.py`, and handle it in `absorb`. No runner or registry to touch.

**Add a risk rule.** It goes in `core/policy.py`. If you are tempted to put a
rule anywhere else, that is the bug.

**Add an MCP server.** Add a connection in `_mcp_connections` in `core/tools.py`.

## Phasing

| Phase | Scope | Status |
|---|---|---|
| 1 | Agentic core, policy, environmental CVSS | Current |
| 2 | Blueprint generation from advisories | Planned |
| 2 | Product criticality driving CR/IR/AR (currently defaulted to High) | Planned |
