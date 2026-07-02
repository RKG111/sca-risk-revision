# SCA Risk Rescoring Platform — POC

Context-aware vulnerability rescoring that replaces generic NVD CVSS scores with
evidence-backed assessments derived from your actual codebase and deployment context.

## The Problem

Standard SCA tools flag vulnerabilities based purely on version strings matched against NVD.
A CRITICAL 9.8 CVE in a library you import but **never call the vulnerable function** is treated
identically to one you call with raw user input. This is alert fatigue.

## The Solution

This platform evaluates **how your code actually uses** a vulnerable package, then reconstructs
the CVSS Base Score from code-proven facts rather than abstract assumptions.

---

## Architecture

```
SBOM + Codebase + Deployment Docs
          │
          ▼
┌─────────────────────┐
│  Module 1: Indexer  │  Tree-sitter AST + Joern CPG + ChromaDB
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Module 2: Blueprint│  NVD API → Claude Sonnet (LLMaS) → AttackBlueprint JSON
└──────────┬──────────┘
           │
      ┌────┴────┐
      │         │
      ▼         ▼
┌──────────┐ ┌──────────┐
│Module 3  │ │Module 4  │
│Determin. │ │AI Agent  │  (routed by blueprint.assessment_strategy)
│Joern+    │ │LangGraph │
│Semgrep   │ │+ Claude  │
└────┬─────┘ └────┬─────┘
     └─────┬──────┘
           │
           ▼
┌─────────────────────┐
│  Module 5: Rescore  │  Evidence → CVSS Engine → Signed Report
└─────────────────────┘
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker + Docker Compose
- Access to LLMaS endpoint (Claude Sonnet)
- Ollama running on GPU VM (optional, for embeddings)

### Setup

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your LLMaS URL, API key, and Ollama VM IP

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start Joern (required for CPG analysis)
cd docker && docker compose up joern -d

# 4. Start the API
uvicorn api.main:app --reload
```

### Submit a Rescoring Job

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/sample_request.json
```

### Check the Result

```bash
curl http://localhost:8000/api/v1/reports/{job_id}
```

---

## Project Structure

```
sca-risk-revision/
├── api/                        # FastAPI application
│   ├── main.py                 # App entrypoint
│   ├── config.py               # Settings (pydantic-settings)
│   └── routers/
│       ├── analysis.py         # POST /api/v1/analyze
│       └── reports.py          # GET /api/v1/reports/{id}
│
├── schemas/                    # Shared Pydantic models
│   ├── sbom.py                 # CycloneDX SBOM input
│   ├── blueprint.py            # Attack Blueprint (Module 2 output)
│   └── report.py               # Rescored Report (final output)
│
├── modules/
│   ├── ingestion/              # Module 1: Code Indexer
│   │   ├── tree_sitter_parser.py
│   │   ├── joern_client.py
│   │   └── indexer.py
│   ├── blueprint/              # Module 2: Blueprint Generator
│   │   ├── nvd_client.py
│   │   └── generator.py
│   ├── deterministic/          # Module 3: Static Analysis
│   │   ├── semgrep_runner.py
│   │   ├── joern_queries.py
│   │   └── resolver.py
│   ├── agent/                  # Module 4: LangGraph Agent
│   │   ├── graph.py
│   │   └── tools/
│   │       ├── file_search.py
│   │       ├── ast_slicer.py
│   │       └── cross_ref.py
│   └── rescoring/              # Module 5: CVSS Engine
│       ├── cvss_engine.py
│       └── report_builder.py
│
├── tests/
│   └── fixtures/
│       ├── sample.sbom.json    # Sample CycloneDX SBOM (PyYAML CVE)
│       └── sample_project/     # Placeholder for test codebase
│
├── docker/
│   ├── docker-compose.yml      # Joern + API
│   └── Dockerfile
│
├── requirements.txt
├── .env.example
└── plan.md                     # Original architecture document
```

---

## LLM Configuration

The platform uses two LLM surfaces:

| Role | Model | Config Key |
|---|---|---|
| Blueprint generation | Claude Sonnet (LLMaS) | `LLMAS_*` |
| Agent reasoning loop | Claude Sonnet (LLMaS) | `LLMAS_*` |
| Embeddings (optional) | Qwen2.5-Coder 32B (Ollama) | `OLLAMA_*` |

Both use the OpenAI-compatible API format. Point `LLMAS_BASE_URL` at your LLMaS endpoint.

---

## POC Phasing

| Phase | Scope | Status |
|---|---|---|
| 1 | Schemas + NVD client + Blueprint generator | Scaffolded |
| 2 | Tree-sitter indexer + Semgrep deterministic checks | Scaffolded |
| 3 | CVSS rescoring + FastAPI end-to-end | Scaffolded |
| 4 | LangGraph agentic loop | Scaffolded |
| 5 | Joern CPG integration | Scaffolded |
