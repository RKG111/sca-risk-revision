# Graph Report - /home/dagger/PROJECTS/sca-risk-revision  (2026-07-27)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 694 nodes · 1589 edges · 39 communities (34 shown, 5 thin omitted)
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 237 edges (avg confidence: 0.55)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a9b1034a`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- EvidenceSet
- joern_remote
- BlueprintStore
- test_agent.py
- BaseModel
- joern.py
- plan
- ProbeScriptedChatModel
- pipeline.py
- stack.sh
- CycloneDXSBOM
- EvidenceUnavailable
- test_api.py
- test_mcp_client.py
- CoreError
- test_baseline.py
- SCA Risk Rescoring Platform — POC
- conftest.py
- test_pipeline.py
- Joern MCP Server
- Joern MCP Server
- Settings
- config.py
- S1 — Exploit Path Verification
- S2 — Security Misconfiguration Verification
- S3 — Deployment Context Verification
- S4 — Mitigation Verification
- Plan — SCA Risk Revision (Phase 1)
- prompts_cn.md
- prompts_en.md
- app.py
- mcp-joern (sfncat)
- core/__init__.py
- joern-run.sh
- post
- joern-mcp

## God Nodes (most connected - your core abstractions)
1. `EvidenceSet` - 75 edges
2. `Blueprint` - 38 edges
3. `plan()` - 31 edges
4. `RiskVerdict` - 29 edges
5. `TestDecide` - 26 edges
6. `ActivationState` - 25 edges
7. `blueprint()` - 25 edges
8. `joern_remote()` - 24 edges
9. `ProbeId` - 24 edges
10. `TestPlan` - 23 edges

## Surprising Connections (you probably didn't know these)
- `AnalyzeRequest` --uses--> `CoreError`  [INFERRED]
  api/main.py → core/errors.py
- `AnalyzeRequest` --uses--> `RiskAssessmentResult`  [INFERRED]
  api/main.py → core/models.py
- `AnalyzeResponse` --uses--> `CoreError`  [INFERRED]
  api/main.py → core/errors.py
- `AnalyzeResponse` --uses--> `RiskAssessmentResult`  [INFERRED]
  api/main.py → core/models.py
- `JobStatus` --uses--> `CoreError`  [INFERRED]
  api/main.py → core/errors.py

## Import Cycles
- None detected.

## Communities (39 total, 5 thin omitted)

### Community 0 - "EvidenceSet"
Cohesion: 0.05
Nodes (76): ActivationBasis, ActivationState, AnswerSource, Blueprint, BlueprintCVSS, ConditionType, Confidence, DeploymentFinding (+68 more)

### Community 1 - "joern_remote"
Cohesion: 0.05
Nodes (68): extract_code_between_triple_quotes(), extract_list(), extract_long_value(), extract_quoted_string(), extract_value(), Extract value from a string based on its pattern.          This function automat, Extract content between triple quotes from a string.          Args:         inpu, Extract a list of elements from a string representation of a Scala List. (+60 more)

### Community 2 - "BlueprintStore"
Cohesion: 0.07
Nodes (19): ExploitPath, PathMitigationResult, Paths with no high-strength mitigation covering them., BlueprintStore, normalise_purl(), package_tokens(), Path, Lowercase the type and name, keep the version, drop qualifiers. (+11 more)

### Community 3 - "test_agent.py"
Cohesion: 0.07
Nodes (25): BaseChatModel, _docs_text(), file_tools(), joern_mcp_tools(), _mcp_connections(), _patch_mcp_compat(), Any, Path (+17 more)

### Community 4 - "BaseModel"
Cohesion: 0.10
Nodes (33): AffectedComponent, BlueprintMitigation, BlueprintReferences, DeploymentEvidence, ExploitPathEvidence, ExploitPathStep, MisconfigEvidence, MitigationEvidence (+25 more)

### Community 5 - "joern.py"
Cohesion: 0.11
Nodes (23): JoernUnavailable, Joern is not reachable, or a CPG query failed., any_sink_called(), _as_records(), component_presence(), index_codebase(), Joern, Any (+15 more)

### Community 6 - "plan"
Cohesion: 0.18
Nodes (12): BlueprintCondition, MisconfigurationFinding, decide(), plan(), Turn evidence into the one risk decision the report carries., Choose the activation basis and the probes that can establish it., blueprint(), path() (+4 more)

### Community 7 - "ProbeScriptedChatModel"
Cohesion: 0.11
Nodes (13): BaseMessage, CallbackManagerForLLMRun, ChatResult, final_answer(), ProbeScriptedChatModel, Any, Scripted chat model for offline agent tests.  An agent-only architecture has no, Script that answers immediately with a JSON payload. (+5 more)

### Community 8 - "pipeline.py"
Cohesion: 0.11
Nodes (26): BlueprintNotFound, No trusted blueprint for this (CVE, component) pair., EvidenceGap, A probe that could not run. Never silently treated as a negative result., Top-level output for one CVE against one codebase., RiskAssessmentResult, assess(), build_report() (+18 more)

### Community 9 - "stack.sh"
Cohesion: 0.25
Nodes (22): api_running(), bad(), cmd_logs(), cmd_start(), cmd_status(), cmd_stop(), ensure_api(), ensure_joern() (+14 more)

### Community 10 - "CycloneDXSBOM"
Cohesion: 0.13
Nodes (20): analyze(), AnalyzeRequest, AnalyzeResponse, health(), JobStatus, BaseModel, Path, HTTP transport over core.pipeline. Deliberately thin: no logic lives here. (+12 more)

### Community 11 - "EvidenceUnavailable"
Cohesion: 0.17
Nodes (14): _parse_evidence(), Any, T, The one agent loop.  Every probe runs through `run_agent`. A probe supplies inst, Run one probe to completion and return its typed evidence.      Raises EvidenceU, Pull the last valid instance of the output contract out of the transcript., run_agent(), _State (+6 more)

### Community 12 - "test_api.py"
Cohesion: 0.14
Nodes (9): AssessmentPlan, How this CVE will be assessed. Produced once, in core.policy., Unknown basis means we cannot justify a rescore; flag for an analyst., a_report(), client(), payload(), fixture, API tests. The API is pure transport, so these only check request handling, job (+1 more)

### Community 13 - "test_mcp_client.py"
Cohesion: 0.18
Nodes (15): main(), Test call-related queries, Test method name-related queries, Test ping functionality, Test loading CPG file, Test method-related queries, Test server connection, Test class-related queries (+7 more)

### Community 14 - "CoreError"
Cohesion: 0.19
Nodes (12): ConfigError, CoreError, LLMUnavailable, Typed failure modes.  The system is agent-only: there is no deterministic fallba, Base class for every failure this package raises., Configuration is missing or inconsistent., The model endpoint could not be reached or refused the request., T (+4 more)

### Community 15 - "test_baseline.py"
Cohesion: 0.20
Nodes (12): load_recorded_evidence(), Build an EvidenceSet from a recorded cassette., Any, Stable snapshot of a risk assessment, for golden-file comparison.  Deliberately, Reduce a RiskAssessmentResult to its reproducible decision surface., stable_snapshot(), _assert_matches_golden(), Golden baseline — pins the decision the pipeline reaches for the sample project. (+4 more)

### Community 16 - "SCA Risk Rescoring Platform — POC"
Cohesion: 0.18
Nodes (10): API, Configuration, Extending, How it works, Layout, Phasing, Quick start, SCA Risk Rescoring Platform — POC (+2 more)

### Community 17 - "conftest.py"
Cohesion: 0.29
Nodes (10): baseline_cve(), blueprint_dir(), fixture, Path, pytest_collection_modifyitems(), Shared test fixtures.  The suite runs fully offline. Anything needing Ollama / J, Deselect `live` tests unless -m live was passed explicitly., repo_root() (+2 more)

### Community 18 - "test_pipeline.py"
Cohesion: 0.20
Nodes (5): offline(), fixture, Pipeline tests: probe orchestration, evidence gaps, and end-to-end assessment., Stub the Joern CPG and the MCP toolbelt so gather() runs offline., TestWaves

### Community 19 - "Joern MCP Server"
Cohesion: 0.20
Nodes (9): Contribution Guidelines, Development Notes, Environment Requirements, Installation Steps, Joern MCP Server, Project Introduction, Project Structure, References (+1 more)

### Community 20 - "Joern MCP Server"
Cohesion: 0.20
Nodes (9): Joern MCP Server, 使用方法, 参考, 安装步骤, 开发说明, 环境要求, 贡献指南, 项目简介 (+1 more)

### Community 22 - "config.py"
Cohesion: 0.33
Nodes (6): mcp_servers_document(), Path, The single source of configuration truth.  Everything that used to be duplicated, Regenerate every file that mirrors Settings. Returns what changed., The MCP registry, derived from Settings rather than hand-maintained., write_generated_config()

### Community 23 - "S1 — Exploit Path Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S1 — Exploit Path Verification, Tools

### Community 24 - "S2 — Security Misconfiguration Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S2 — Security Misconfiguration Verification, Tools

### Community 25 - "S3 — Deployment Context Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S3 — Deployment Context Verification, Tools

### Community 26 - "S4 — Mitigation Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, Objectives, Output format, S4 — Mitigation Verification, Tools

### Community 27 - "Plan — SCA Risk Revision (Phase 1)"
Cohesion: 0.33
Nodes (5): Goal, Locked decisions, Out of scope (Phase 1), Pipeline, Plan — SCA Risk Revision (Phase 1)

### Community 28 - "prompts_cn.md"
Cohesion: 0.33
Nodes (5): 信息, 净化规则, 处理要求, 注意事项, 输出规则

### Community 29 - "prompts_en.md"
Cohesion: 0.33
Nodes (5): Information, Notes, Output Rules, Processing Requirements, Sanitization Rules

### Community 30 - "app.py"
Cohesion: 0.40
Nodes (3): load_config(), post, Sample vulnerable usage of PyYAML FullLoader for end-to-end fixtures.

### Community 31 - "mcp-joern (sfncat)"
Cohesion: 0.40
Nodes (4): Fallback: stdio, mcp-joern (sfncat), Preferred: FastMCP SSE (stack-managed), Vendored / cloned third-party tools

## Knowledge Gaps
- **62 isolated node(s):** `joern-run.sh script`, `joern-mcp`, `How it works`, `Layout`, `API` (+57 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `EvidenceSet` connect `EvidenceSet` to `BlueprintStore`, `BaseModel`, `plan`, `pipeline.py`, `test_baseline.py`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Why does `CycloneDXSBOM` connect `CycloneDXSBOM` to `EvidenceSet`, `BlueprintStore`, `BaseModel`, `ProbeScriptedChatModel`, `pipeline.py`, `test_baseline.py`, `test_pipeline.py`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Why does `Blueprint` connect `EvidenceSet` to `pipeline.py`, `BlueprintStore`, `BaseModel`, `plan`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `EvidenceSet` (e.g. with `Clamp` and `Probe`) actually correct?**
  _`EvidenceSet` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 13 inferred relationships involving `Blueprint` (e.g. with `Clamp` and `Probe`) actually correct?**
  _`Blueprint` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `RiskVerdict` (e.g. with `Clamp` and `MetricJudgement`) actually correct?**
  _`RiskVerdict` has 10 INFERRED edges - model-reasoned connections that need verification._
- **What connects `joern-run.sh script`, `joern-mcp`, `How it works` to the rest of the system?**
  _62 weakly-connected nodes found - possible documentation gaps or missing edges._