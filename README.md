# Risk Assessment Agent (v2)

Asynchronous vulnerability risk assessment: gather evidence with static-analysis
tools, run skill agents, then produce an environmental CVSS score.

> The previous agent (`api/`, `core/`) lives under [`deprecated/`](deprecated/) for reference.

## Architecture

```
POST /api/v1/scans  →  workspace/{scan_id}/  →  8-step background pipeline
```

| Step | What |
|------|------|
| 1 Discover skills | Load `skills/*.md` (YAML frontmatter) |
| 2 Plan | LLM selects skills → `plan.json` |
| 3 Prepare tools | Mock Joern MCP + Graphify CLI |
| 4 Run skills | Per-skill OpenAI tool-calling loops → `sN_output.json` |
| 5 Aggregate | Deterministic evidence compile → `aggregated_evidence.json`, `mde_input.json` |
| 6 MDE | LLM chooses CVSS metrics / exploitability |
| 7 Scoring | Deterministic CVSS environmental score → `scoring.json` |
| 8 Final report | `final_assessment.json`, status → `completed` |

State is **file-based only** under `workspace/{scan_id}/` (no relational DB).

## Layout

```
app/               FastAPI app, scan routes, workspace I/O
agent/             Pipeline, LLM client, skills loader, tools, MDE, scoring
skills/            Skill definitions (Markdown + YAML frontmatter)
workspace/         Per-scan state directories
deprecated/        v1 agent (do not import)
blueprints/        Trusted CVE blueprints (optional input)
```

## Quick start

```bash
cp .env.example .env
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Ollama with qwen2.5-coder:14b on http://localhost:11434
uvicorn app.main:app --reload --port 8000
```

### API

```bash
# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2020-14343",
    "codebase_path": "samples/python/CVE-2020-14343-pyyaml",
    "blueprint_path": "blueprints/CVE-2020-14343_pkg-pypi-pyyaml@5.3.1.json",
    "target_name": "pyyaml-sample"
  }'
# → {"scan_id": "...", "status": "running"}

# Poll snapshot
curl http://localhost:8000/api/v1/scans/{scan_id}

# List completed
curl http://localhost:8000/api/v1/scans/completed
```

## LLM

Uses the official `openai` Python SDK against Ollama's OpenAI-compatible endpoint:

```python
OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
```

Default model: `qwen2.5-coder:14b` (override with `LLM_MODEL` in `.env`).
