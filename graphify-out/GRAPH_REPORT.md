# Graph Report - sca-risk-revision  (2026-07-27)

## Corpus Check
- 57 files · ~22,053 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 695 nodes · 1589 edges · 40 communities (36 shown, 4 thin omitted)
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 237 edges (avg confidence: 0.55)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `7421c79f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- ComponentCveBlueprint
- joern_remote
- runner.py
- JoernClient
- evidence.py
- mcp/registry.py
- tools.py
- stack.sh
- CycloneDXSBOM
- blueprint.py
- test_mcp_client.py
- joern_tools.py
- main.py
- .run
- Settings
- app.py
- joern-run.sh
- routers/__init__.py
- ingestion/__init__.py
- modules/__init__.py
- Path
- joern-mcp
- file_tools
- SCA Risk Rescoring Platform — POC
- conftest.py
- Joern MCP Server
- Joern MCP Server
- S1 — Exploit Path Verification
- S2 — Security Misconfiguration Verification
- S3 — Deployment Context Verification
- S4 — Mitigation Verification
- Plan — SCA Risk Revision (Phase 1)
- prompts_cn.md
- prompts_en.md
- TestWaves
- mcp-joern (sfncat)
- core/__init__.py

## God Nodes (most connected - your core abstractions)
1. `EvidenceSet` - 75 edges
2. `Blueprint` - 38 edges
3. `plan()` - 31 edges
4. `RiskVerdict` - 29 edges
5. `TestDecide` - 26 edges
6. `ActivationState` - 25 edges
7. `blueprint()` - 25 edges
8. `ProbeId` - 24 edges
9. `joern_remote()` - 24 edges
10. `TestPlan` - 23 edges

## Surprising Connections (you probably didn't know these)
- `AnalyzeRequest` --uses--> `CoreError`  [INFERRED]
  api/main.py → core/errors.py
- `AnalyzeRequest` --uses--> `CycloneDXSBOM`  [INFERRED]
  api/main.py → core/models.py
- `AnalyzeResponse` --uses--> `CoreError`  [INFERRED]
  api/main.py → core/errors.py
- `AnalyzeResponse` --uses--> `CycloneDXSBOM`  [INFERRED]
  api/main.py → core/models.py
- `JobStatus` --uses--> `CoreError`  [INFERRED]
  api/main.py → core/errors.py

## Import Cycles
- None detected.

## Communities (40 total, 4 thin omitted)

### Community 0 - "ComponentCveBlueprint"
Cohesion: 0.14
Nodes (17): _parse_evidence(), Any, T, The one agent loop.  Every probe runs through `run_agent`. A probe supplies inst, Run one probe to completion and return its typed evidence.      Raises EvidenceU, Pull the last valid instance of the output contract out of the transcript., run_agent(), _State (+9 more)

### Community 1 - "joern_remote"
Cohesion: 0.05
Nodes (70): extract_code_between_triple_quotes(), extract_list(), extract_long_value(), extract_quoted_string(), extract_value(), Extract value from a string based on its pattern.          This function automat, Extract content between triple quotes from a string.          Args:         inpu, Extract a list of elements from a string representation of a Scala List. (+62 more)

### Community 2 - "runner.py"
Cohesion: 0.06
Nodes (52): LLMUnavailable, The model endpoint could not be reached or refused the request., T, Ask the model for one instance of `output_model`.      Schema-constrained via in, structured(), ActivationBasis, AnswerSource, Blueprint (+44 more)

### Community 3 - "JoernClient"
Cohesion: 0.25
Nodes (8): Path, Interpret a request path relative to CODEBASE_ROOT, or absolutely., _resolve(), ConfigError, CoreError, Base class for every failure this package raises., Configuration is missing or inconsistent., Exception

### Community 4 - "evidence.py"
Cohesion: 0.08
Nodes (40): ActivationState, AssessmentPlan, BlueprintCondition, ConditionType, DeploymentFinding, EvidenceSet, Everything the probes established, flattened into one place.      `ran` and `gap, Kinds of precondition a CVE can carry. (+32 more)

### Community 5 - "mcp/registry.py"
Cohesion: 0.06
Nodes (58): AffectedComponent, BlueprintMitigation, BlueprintReferences, DeploymentEvidence, EvidenceGap, ExploitPathEvidence, ExploitPathStep, MisconfigEvidence (+50 more)

### Community 6 - "tools.py"
Cohesion: 0.07
Nodes (22): ExploitPath, MitigationStrength, PathMitigationResult, Paths with no high-strength mitigation covering them., How much a mitigation actually blocks exploitation.      One scale for both blue, BlueprintStore, normalise_purl(), package_tokens() (+14 more)

### Community 7 - "stack.sh"
Cohesion: 0.25
Nodes (22): api_running(), bad(), cmd_logs(), cmd_start(), cmd_status(), cmd_stop(), ensure_api(), ensure_joern() (+14 more)

### Community 8 - "CycloneDXSBOM"
Cohesion: 0.21
Nodes (6): CycloneDXSBOM, Only the parts we need: which components exist and which CVEs affect them., Resolve each vulnerability's `affects[].ref` to a versioned PURL., The PURL this CVE applies to, or None if the SBOM does not say., model_validator, TestAssess

### Community 9 - "blueprint.py"
Cohesion: 0.12
Nodes (21): JoernUnavailable, Joern is not reachable, or a CPG query failed., any_sink_called(), _as_records(), component_presence(), index_codebase(), Joern, Any (+13 more)

### Community 10 - "test_mcp_client.py"
Cohesion: 0.18
Nodes (15): main(), Test call-related queries, Test method name-related queries, Test ping functionality, Test loading CPG file, Test method-related queries, Test server connection, Test class-related queries (+7 more)

### Community 11 - "joern_tools.py"
Cohesion: 0.14
Nodes (12): BaseChatModel, BaseMessage, CallbackManagerForLLMRun, ChatResult, final_answer(), Any, Scripted chat model for offline agent tests.  An agent-only architecture has no, Script that answers immediately with a JSON payload. (+4 more)

### Community 12 - "main.py"
Cohesion: 0.20
Nodes (15): analyze(), AnalyzeRequest, AnalyzeResponse, health(), JobStatus, BaseModel, post, HTTP transport over core.pipeline. Deliberately thin: no logic lives here. (+7 more)

### Community 13 - ".run"
Cohesion: 0.20
Nodes (12): load_recorded_evidence(), Build an EvidenceSet from a recorded cassette., Any, Stable snapshot of a risk assessment, for golden-file comparison.  Deliberately, Reduce a RiskAssessmentResult to its reproducible decision surface., stable_snapshot(), _assert_matches_golden(), Golden baseline — pins the decision the pipeline reaches for the sample project. (+4 more)

### Community 14 - "Settings"
Cohesion: 0.15
Nodes (8): BaseSettings, mcp_servers_document(), Path, The single source of configuration truth.  Everything that used to be duplicated, Regenerate every file that mirrors Settings. Returns what changed., The MCP registry, derived from Settings rather than hand-maintained., Settings, write_generated_config()

### Community 15 - "app.py"
Cohesion: 0.40
Nodes (3): load_config(), post, Sample vulnerable usage of PyYAML FullLoader for end-to-end fixtures.

### Community 19 - "routers/__init__.py"
Cohesion: 0.20
Nodes (7): ProbeScriptedChatModel, Answers according to which probe's instructions it was handed.      Probes in a, offline(), fixture, Pipeline tests: probe orchestration, evidence gaps, and end-to-end assessment., Stub the Joern CPG and the MCP toolbelt so gather() runs offline., TestGather

### Community 20 - "ingestion/__init__.py"
Cohesion: 0.24
Nodes (4): We looked and found nothing" is legitimate evidence, unlike a failure., A stuck agent must not look like a clean 'nothing found' result., _run(), TestRunAgent

### Community 21 - "modules/__init__.py"
Cohesion: 0.18
Nodes (7): BlueprintNotFound, No trusted blueprint for this (CVE, component) pair., client(), payload(), fixture, API tests. The API is pure transport, so these only check request handling, job, test_a_failed_assessment_is_reported_as_failed()

### Community 22 - "Path"
Cohesion: 0.24
Nodes (11): joern_mcp_tools(), _mcp_connections(), _patch_mcp_compat(), Any, The toolbelt handed to probe agents.  Two families:    * filesystem tools — read, Run the vendored MCP server as a subprocess, preferring uv., One entry per MCP server. SSE when it is up, otherwise a subprocess., mcp >= 1.23 renamed streamablehttp_client; adapters still want the old name. (+3 more)

### Community 25 - "file_tools"
Cohesion: 0.24
Nodes (6): _docs_text(), file_tools(), Path, Filesystem tools scoped to one codebase (and optional product docs)., Concatenate readable documentation files up to a character budget., TestFileTools

### Community 26 - "SCA Risk Rescoring Platform — POC"
Cohesion: 0.18
Nodes (10): API, Configuration, Extending, How it works, Layout, Phasing, Quick start, SCA Risk Rescoring Platform — POC (+2 more)

### Community 27 - "conftest.py"
Cohesion: 0.29
Nodes (10): baseline_cve(), blueprint_dir(), fixture, Path, pytest_collection_modifyitems(), Shared test fixtures.  The suite runs fully offline. Anything needing Ollama / J, Deselect `live` tests unless -m live was passed explicitly., repo_root() (+2 more)

### Community 28 - "Joern MCP Server"
Cohesion: 0.20
Nodes (9): Contribution Guidelines, Development Notes, Environment Requirements, Installation Steps, Joern MCP Server, Project Introduction, Project Structure, References (+1 more)

### Community 29 - "Joern MCP Server"
Cohesion: 0.20
Nodes (9): Joern MCP Server, 使用方法, 参考, 安装步骤, 开发说明, 环境要求, 贡献指南, 项目简介 (+1 more)

### Community 30 - "S1 — Exploit Path Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S1 — Exploit Path Verification, Tools

### Community 31 - "S2 — Security Misconfiguration Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S2 — Security Misconfiguration Verification, Tools

### Community 32 - "S3 — Deployment Context Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S3 — Deployment Context Verification, Tools

### Community 33 - "S4 — Mitigation Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S4 — Mitigation Verification, Tools

### Community 34 - "Plan — SCA Risk Revision (Phase 1)"
Cohesion: 0.33
Nodes (5): Goal, Locked decisions, Out of scope (Phase 1), Pipeline, Plan — SCA Risk Revision (Phase 1)

### Community 35 - "prompts_cn.md"
Cohesion: 0.33
Nodes (5): 信息, 净化规则, 处理要求, 注意事项, 输出规则

### Community 36 - "prompts_en.md"
Cohesion: 0.33
Nodes (5): Information, Notes, Output Rules, Processing Requirements, Sanitization Rules

### Community 38 - "mcp-joern (sfncat)"
Cohesion: 0.40
Nodes (4): Fallback: stdio, mcp-joern (sfncat), Preferred: FastMCP SSE (stack-managed), Vendored / cloned third-party tools

## Knowledge Gaps
- **62 isolated node(s):** `joern-run.sh script`, `joern-mcp`, `How it works`, `Layout`, `API` (+57 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `EvidenceSet` connect `evidence.py` to `runner.py`, `.run`, `mcp/registry.py`, `tools.py`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Why does `CycloneDXSBOM` connect `CycloneDXSBOM` to `mcp/registry.py`, `tools.py`, `TestWaves`, `main.py`, `.run`, `routers/__init__.py`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Why does `Blueprint` connect `runner.py` to `evidence.py`, `mcp/registry.py`, `tools.py`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `EvidenceSet` (e.g. with `Clamp` and `Probe`) actually correct?**
  _`EvidenceSet` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 13 inferred relationships involving `Blueprint` (e.g. with `Clamp` and `Probe`) actually correct?**
  _`Blueprint` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `RiskVerdict` (e.g. with `Clamp` and `MetricJudgement`) actually correct?**
  _`RiskVerdict` has 10 INFERRED edges - model-reasoned connections that need verification._
- **What connects `joern-run.sh script`, `joern-mcp`, `How it works` to the rest of the system?**
  _62 weakly-connected nodes found - possible documentation gaps or missing edges._