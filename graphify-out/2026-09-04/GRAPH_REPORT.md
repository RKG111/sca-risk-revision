# Graph Report - sca-risk-revision  (2026-07-30)

## Corpus Check
- 140 files · ~38,272 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1099 nodes · 2233 edges · 101 communities (69 shown, 32 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 103 edges (avg confidence: 0.63)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8ee23219`
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
- api/__init__.py
- post
- joern-mcp
- tests/__init__.py
- tools.py
- _generate.py
- conftest.py
- workspace.py
- test_baseline.py
- test_agent.py
- file_tools
- assess
- CVE-2021-23337-lodash/app/package.json
- CVE-2021-23358-underscore/app/package.json
- S1 — Exploit Path Verification
- compute_score
- UserController.java
- Settings
- S2 — Security Misconfiguration Verification
- S3 — Deployment Context Verification
- S4 — Mitigation Verification
- Plan — SCA Risk Revision
- CVE-2022-23812-node-ipc/app/package.json
- Sample CVE assessment dataset
- aggregate_evidence
- write_generated_config
- sample_project/app.py
- no_joern
- TestWaves
- App
- JsonApi
- handler
- handler
- CVE-2020-14343-pyyaml/app/app.py
- CVE-2021-23337-lodash/app/index.js
- CVE-2021-23358-underscore/app/index.js
- CVE-2022-29217-pyjwt/app/app.py
- CVE-2023-50447-pillow/app/app.py
- S1 — Exploit Path Verification
- S2 — Security Misconfiguration Verification
- S3 — Deployment Context Verification
- S4 — Mitigation Verification
- agent/__init__.py
- app/__init__.py
- deprecated/README.md
- CVE-2020-28483-gin/README.md
- CVE-2021-38561-xtext/README.md
- CVE-2022-28948-yaml/README.md
- CVE-2019-12384-jackson/README.md
- CVE-2021-44228-log4j/README.md
- CVE-2022-22965-spring/README.md
- CVE-2021-23337-lodash/README.md
- CVE-2021-23358-underscore/README.md
- CVE-2022-23812-node-ipc/app/index.js
- CVE-2022-23812-node-ipc/README.md
- CVE-2020-14343-pyyaml/README.md
- CVE-2022-29217-pyjwt/README.md
- CVE-2023-50447-pillow/README.md
- samples/gin-demo
- samples:jackson-demo
- samples:log4shell-demo
- samples:spring4shell-demo
- samples/xtext-demo
- samples/yaml-demo

## God Nodes (most connected - your core abstractions)
1. `EvidenceSet` - 71 edges
2. `plan()` - 48 edges
3. `blueprint()` - 37 edges
4. `ScanSession` - 30 edges
5. `Blueprint` - 29 edges
6. `decide()` - 29 edges
7. `assess()` - 26 edges
8. `joern_remote()` - 24 edges
9. `ProbeScriptedChatModel` - 23 edges
10. `CoreError` - 21 edges

## Surprising Connections (you probably didn't know these)
- `chat_json()` --calls--> `write_conversation()`  [EXTRACTED]
  agent/llm.py → app/workspace.py
- `run_pipeline()` --calls--> `read_json()`  [EXTRACTED]
  agent/pipeline.py → app/workspace.py
- `create_scan()` --indirect_call--> `run_pipeline()`  [INFERRED]
  app/api/scans.py → agent/pipeline.py
- `prepare_tool_bundle()` --calls--> `write_json()`  [EXTRACTED]
  agent/pipeline.py → app/workspace.py
- `run_skills()` --calls--> `update_status()`  [EXTRACTED]
  agent/pipeline.py → app/workspace.py

## Import Cycles
- None detected.

## Communities (101 total, 32 thin omitted)

### Community 0 - "EvidenceSet"
Cohesion: 0.12
Nodes (16): ActivationBasis, AnswerSource, Blueprint, ConditionType, Confidence, CVSS 3.1 severity bands — the only place this mapping exists., Component-specific CVE research. Never mentions probes or CVSS policy., Kinds of precondition a CVE can carry. (+8 more)

### Community 1 - "joern_remote"
Cohesion: 0.05
Nodes (70): extract_code_between_triple_quotes(), extract_list(), extract_long_value(), extract_quoted_string(), extract_value(), Extract value from a string based on its pattern.          This function automat, Extract content between triple quotes from a string.          Args:         inpu, Extract a list of elements from a string representation of a Scala List. (+62 more)

### Community 2 - "BlueprintStore"
Cohesion: 0.07
Nodes (35): DeploymentFinding, EvidenceSet, ExploitPath, MisconfigurationFinding, PathMitigationResult, Everything the probes established, flattened into one place.      `ran` and `gap, Paths with no high-strength mitigation covering them., Tri-state network exposure from deployment findings.          False wins over Tr (+27 more)

### Community 3 - "test_agent.py"
Cohesion: 0.29
Nodes (4): BaseChatModel, Replays a fixed list of turns, one per invocation.      A turn is `{"content": ", ScriptedChatModel, TestAgentConversationLog

### Community 4 - "BaseModel"
Cohesion: 0.08
Nodes (15): BlueprintStore, normalise_purl(), package_tokens(), Path, Lowercase the type and name, keep the version, drop qualifiers., Import-name candidates for a package, for presence checks.      pkg:pypi/pyyaml@, Directory of blueprint JSON files, indexed on first use., Index every *.json under the store path. Returns the file count. (+7 more)

### Community 5 - "joern.py"
Cohesion: 0.09
Nodes (32): The single source of configuration truth.  Everything that used to be duplicated, JoernUnavailable, Joern is not reachable, or a CPG query failed., SCA risk assessment core.  One flat package, one concept per module:      config, component_presence(), The only code in the system that talks to Joern.  Joern is reached over its `/qu, Whether the vulnerable component is imported anywhere in the CPG.      Import-gr, EvidenceGap (+24 more)

### Community 6 - "plan"
Cohesion: 0.11
Nodes (26): AffectedComponent, BlueprintCondition, BlueprintCVSS, BlueprintMitigation, BlueprintReferences, CycloneDXSBOM, DeploymentEvidence, ExploitPathEvidence (+18 more)

### Community 7 - "ProbeScriptedChatModel"
Cohesion: 0.08
Nodes (18): CallbackManagerForLLMRun, ChatResult, _default_tool_args(), final_answer(), ProbeScriptedChatModel, Any, BaseMessage, Scripted chat model for offline agent tests.  An agent-only architecture has no (+10 more)

### Community 8 - "pipeline.py"
Cohesion: 0.12
Nodes (19): any_sink_called(), _as_int(), _as_records(), _as_string_list(), index_codebase(), Joern, Any, Path (+11 more)

### Community 9 - "stack.sh"
Cohesion: 0.26
Nodes (21): api_running(), bad(), cmd_logs(), cmd_start(), cmd_status(), cmd_stop(), ensure_api(), ensure_joern() (+13 more)

### Community 11 - "EvidenceUnavailable"
Cohesion: 0.13
Nodes (20): _parse_evidence(), AIMessage, Any, T, The one agent loop.  Every probe runs through `run_agent`. A probe supplies inst, Pull the last valid instance of the output contract out of the transcript., Synthetic tool results that tell the model to change strategy., Run one probe to completion and return its typed evidence.      Raises EvidenceU (+12 more)

### Community 12 - "test_api.py"
Cohesion: 0.10
Nodes (19): Skill discovery package., load_skills(), order_by_dependencies(), _parse_frontmatter(), Any, Path, Skill discovery from Markdown files with YAML frontmatter., Topological order of selected skills honoring depends_on. (+11 more)

### Community 13 - "test_mcp_client.py"
Cohesion: 0.18
Nodes (15): main(), Test call-related queries, Test method name-related queries, Test ping functionality, Test loading CPG file, Test method-related queries, Test server connection, Test class-related queries (+7 more)

### Community 14 - "CoreError"
Cohesion: 0.17
Nodes (23): analyze(), analyze_blueprint(), AnalyzeRequest, AnalyzeResponse, BlueprintAnalyzeRequest, health(), JobStatus, BackgroundTasks (+15 more)

### Community 15 - "test_baseline.py"
Cohesion: 0.10
Nodes (15): BlueprintNotFound, ConfigError, Typed failure modes.  The system is agent-only: there is no deterministic fallba, Configuration is missing or inconsistent., No trusted blueprint for this (CVE, component) pair., load_blueprint(), Blueprint lookup.  Blueprints are trusted research artefacts on disk, keyed by C, Load and validate one blueprint JSON file. (+7 more)

### Community 16 - "SCA Risk Rescoring Platform — POC"
Cohesion: 0.29
Nodes (6): API, Architecture, Layout, LLM, Quick start, Risk Assessment Agent (v2)

### Community 17 - "conftest.py"
Cohesion: 0.15
Nodes (13): ExploitPathStep, AIMessage, BaseMessage, Serialize one LangChain message for the conversation log., Replace the transcript with the full agent message list and sum usage., Record a non-tool structured LLM call (e.g. CVSS adjudication)., Pull token counts from a LangChain AIMessage (provider-agnostic)., serialize_message() (+5 more)

### Community 18 - "test_pipeline.py"
Cohesion: 0.12
Nodes (9): Base metrics, then requirements, then modified metrics.          Base segments a, Environmental score for a full vector. The only arithmetic in the system., A CVSS 3.1 vector, immutable, that can emit an environmental variant., score(), Vector, parametrize, The published base vector is a fact; findings go in the M* metrics., TestScore (+1 more)

### Community 19 - "Joern MCP Server"
Cohesion: 0.20
Nodes (9): Contribution Guidelines, Development Notes, Environment Requirements, Installation Steps, Joern MCP Server, Project Introduction, Project Structure, References (+1 more)

### Community 20 - "Joern MCP Server"
Cohesion: 0.20
Nodes (9): Joern MCP Server, 使用方法, 参考, 安装步骤, 开发说明, 环境要求, 贡献指南, 项目简介 (+1 more)

### Community 21 - "Settings"
Cohesion: 0.16
Nodes (20): LLMUnavailable, The model endpoint could not be reached or refused the request., T, The only code that talks to the language model.  Two call shapes are needed and, Ask the model for one instance of `output_model`.      Schema-constrained via in, structured(), llm_adjudicator(), make_llm_adjudicator() (+12 more)

### Community 22 - "config.py"
Cohesion: 0.16
Nodes (18): _elapsed_seconds(), get_scan(), list_completed_scans(), Any, get, Scan lifecycle REST endpoints., Comprehensive snapshot of a scan from its workspace files., Return metadata for scans whose status is completed. (+10 more)

### Community 23 - "S1 — Exploit Path Verification"
Cohesion: 0.17
Nodes (12): datetime, _iso(), Any, Path, Per-scan telemetry: full agent↔LLM transcripts, token usage, and metadata.json., Accumulates one skill/probe's conversation and usage, then writes it., Create a session.          Artefacts land in `output_root` when set; otherwise u, Pull token counts from an OpenAI-style completion object. (+4 more)

### Community 24 - "S2 — Security Misconfiguration Verification"
Cohesion: 0.16
Nodes (19): discover_skills(), plan_assessment(), Step 1 — load skill definitions from skills/., Step 2 — LLM selects skills from the catalog., Execute the full 8-step pipeline for ``scan_id``., run_pipeline(), build_final_assessment(), Any (+11 more)

### Community 25 - "S3 — Deployment Context Verification"
Cohesion: 0.18
Nodes (17): _dependencies_met(), A dependent probe needs its prerequisite to have run *and* produced input., absorb(), _deployment_context(), _exploit_path_context(), _json_block(), _misconfig_context(), _mitigation_context() (+9 more)

### Community 26 - "S4 — Mitigation Verification"
Cohesion: 0.18
Nodes (9): GraphifyCLI, JoernMCP, prepare_tools(), Any, Mock / real tool adapters used by skills (Joern MCP, Graphify CLI)., Stub for the Joern MCP server (CPG analysis)., Initialize mock Joern MCP and Graphify CLI connections., OpenAI function-calling schemas for mocked Joern tools. (+1 more)

### Community 27 - "Plan — SCA Risk Revision (Phase 1)"
Cohesion: 0.18
Nodes (6): We looked and found nothing" is legitimate evidence, unlike a failure., Models sometimes write {"name":"check_connection"} as content instead of tool_ca, Same tool+args more than twice gets a refusal; agent can still finish., A stuck agent must not look like a clean 'nothing found' result., _run(), TestRunAgent

### Community 28 - "prompts_cn.md"
Cohesion: 0.33
Nodes (5): 信息, 净化规则, 处理要求, 注意事项, 输出规则

### Community 29 - "prompts_en.md"
Cohesion: 0.33
Nodes (5): Information, Notes, Output Rules, Processing Requirements, Sanitization Rules

### Community 30 - "app.py"
Cohesion: 0.18
Nodes (15): chat(), chat_json(), _extract_json(), get_client(), Any, LLM client for Ollama via the OpenAI-compatible API., Official OpenAI SDK pointed at the local Ollama endpoint., Single chat completion call. Returns the OpenAI response object. (+7 more)

### Community 31 - "mcp-joern (sfncat)"
Cohesion: 0.40
Nodes (4): Fallback: stdio, mcp-joern (sfncat), Preferred: FastMCP SSE (stack-managed), Vendored / cloned third-party tools

### Community 32 - "core/__init__.py"
Cohesion: 0.28
Nodes (15): load_blueprint_if_needed(), _parse_skill_output(), prepare_tool_bundle(), Any, Core 8-step Risk Assessment pipeline (v2).  Runs as a FastAPI background task. A, Step 3 — initialize mock Joern MCP + Graphify CLI., Step 4 — execute selected skills in dependency order., Isolated LLM tool-calling loop for one skill. (+7 more)

### Community 33 - "joern-run.sh"
Cohesion: 0.50
Nodes (3): joern-run.sh script, SL_LOGGING_LEVEL, TERM

### Community 35 - "api/__init__.py"
Cohesion: 0.36
Nodes (7): adjudicate(), Answer every environmental metric, then enforce the policy clamps., answers_of(), blueprint(), Scoring tests: the vector value object, metric adjudication, and the arithmetic., TestAdjudicate, verdict()

### Community 36 - "post"
Cohesion: 0.22
Nodes (12): ActivationState, AssessmentPlan, How this CVE will be assessed. Produced once, in core.policy., Unknown basis means we cannot justify a rescore; flag for an analyst., The answer to "is the CVE live here?"., _activation_state(), _from_tristate(), _rationale() (+4 more)

### Community 39 - "tools.py"
Cohesion: 0.21
Nodes (13): joern_mcp_tools(), _joern_query_sync(), _mcp_connections(), _patch_mcp_compat(), Any, The toolbelt handed to probe agents.  Two families:    * filesystem tools — read, Synchronous Joern /query-sync for use inside LangChain tools., Run the vendored MCP server as a subprocess, preferring uv. (+5 more)

### Community 40 - "_generate.py"
Cohesion: 0.48
Nodes (13): blueprint(), cond(), go_samples(), java_samples(), main(), mit(), npm_samples(), Path (+5 more)

### Community 41 - "conftest.py"
Cohesion: 0.24
Nodes (12): baseline_cve(), blueprint_dir(), _isolate_scan_output(), fixture, Path, pytest_collection_modifyitems(), Shared test fixtures.  The suite runs fully offline. Anything needing Ollama / J, Keep per-scan artefacts out of the repo during tests. (+4 more)

### Community 42 - "workspace.py"
Cohesion: 0.30
Nodes (11): conversations_dir(), create_workspace(), Path, File-based workspace helpers for scan state under workspace/{scan_id}/., Create workspace/{scan_id}/ and conversations/ subfolder., Return parsed JSON, or None if the file is missing or unreadable., Persist a raw LLM conversation log under conversations/., read_json() (+3 more)

### Community 43 - "test_baseline.py"
Cohesion: 0.23
Nodes (10): Any, Stable snapshot of a risk assessment, for golden-file comparison.  Deliberately, Reduce a RiskAssessmentResult to its reproducible decision surface., stable_snapshot(), _assert_matches_golden(), Golden baseline — pins the decision the pipeline reaches for the sample project., The rebuilt core reaches the same decision as the pipeline it replaces., Replay the recorded probe evidence instead of calling live agents. (+2 more)

### Community 44 - "test_agent.py"
Cohesion: 0.24
Nodes (7): _docs_text(), Path, Concatenate readable documentation files up to a character budget., Force a pathlib-safe relative glob. Absolute patterns raise on Path.glob., _relative_glob(), Agent loop and toolbelt tests, driven by a scripted model rather than Ollama.  T, TestRelativeGlob

### Community 45 - "file_tools"
Cohesion: 0.31
Nodes (3): file_tools(), Filesystem tools scoped to one codebase (and optional product docs)., TestFileTools

### Community 46 - "assess"
Cohesion: 0.28
Nodes (8): Top-level output for one CVE against one codebase., RiskAssessmentResult, assess(), build_report(), Adjudicator, Score the verdict and assemble the report., Assess one CVE against one codebase.      Provide either:       - `sbom` + `cve_, a_report()

### Community 47 - "CVE-2021-23337-lodash/app/package.json"
Cohesion: 0.22
Nodes (8): lodash, dependencies, express, lodash, express, name, private, version

### Community 48 - "CVE-2021-23358-underscore/app/package.json"
Cohesion: 0.22
Nodes (8): dependencies, express, underscore, express, name, private, version, underscore

### Community 49 - "S1 — Exploit Path Verification"
Cohesion: 0.25
Nodes (7): Blueprint fields to use, Critical: wrong vs right Joern tools, Evidence rules, How to work, Objectives, Output format, S1 — Exploit Path Verification

### Community 50 - "compute_score"
Cohesion: 0.43
Nodes (6): compute_score(), Any, Step 7 — Deterministic CVSS environmental scoring., Calculate environmental score/severity from MDE vector + metrics., _score_with_cvss_lib(), severity_from_score()

### Community 51 - "UserController.java"
Cohesion: 0.48
Nodes (5): Controller, PostMapping, ResponseBody, UserController, UserForm

### Community 53 - "S2 — Security Misconfiguration Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, How to work, Objectives, Output format, S2 — Security Misconfiguration Verification

### Community 54 - "S3 — Deployment Context Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, How to work, Objectives, Output format, S3 — Deployment Context Verification

### Community 55 - "S4 — Mitigation Verification"
Cohesion: 0.29
Nodes (6): Blueprint fields to use, Evidence rules, How to work, Objectives, Output format, S4 — Mitigation Verification

### Community 56 - "Plan — SCA Risk Revision"
Cohesion: 0.29
Nodes (6): Goal, Locked decisions, Out of scope, Pipeline, Plan — SCA Risk Revision, Testing

### Community 57 - "CVE-2022-23812-node-ipc/app/package.json"
Cohesion: 0.29
Nodes (6): node-ipc, dependencies, node-ipc, name, private, version

### Community 58 - "Sample CVE assessment dataset"
Cohesion: 0.33
Nodes (5): Languages (3 CVEs each), Layout, Notes, Regenerate, Sample CVE assessment dataset

### Community 59 - "aggregate_evidence"
Cohesion: 0.40
Nodes (4): aggregate_evidence(), Any, Step 5 — Aggregate evidence from skill outputs into MDE input., Deterministically compile citations, path gates, and review flags.      Returns

### Community 60 - "write_generated_config"
Cohesion: 0.40
Nodes (5): mcp_servers_document(), Path, Regenerate every file that mirrors Settings. Returns what changed., The MCP registry, derived from Settings rather than hand-maintained., write_generated_config()

### Community 61 - "sample_project/app.py"
Cohesion: 0.40
Nodes (3): load_config(), post, Sample vulnerable usage of PyYAML FullLoader for end-to-end fixtures.

### Community 62 - "no_joern"
Cohesion: 0.40
Nodes (5): no_joern(), offline(), fixture, Stub Joern/MCP as fully unavailable., Stub Joern as available so CPG-backed plans can run offline with scripted agents

### Community 66 - "handler"
Cohesion: 0.40
Nodes (3): Request, ResponseWriter, handler()

### Community 67 - "handler"
Cohesion: 0.40
Nodes (3): Request, ResponseWriter, handler()

### Community 68 - "CVE-2020-14343-pyyaml/app/app.py"
Cohesion: 0.40
Nodes (3): load_config(), post, Vulnerable: untrusted YAML via yaml.full_load / FullLoader.

### Community 69 - "CVE-2021-23337-lodash/app/index.js"
Cohesion: 0.50
Nodes (3): _, app, express

### Community 70 - "CVE-2021-23358-underscore/app/index.js"
Cohesion: 0.50
Nodes (3): _, app, express

### Community 71 - "CVE-2022-29217-pyjwt/app/app.py"
Cohesion: 0.50
Nodes (3): profile(), get, Vulnerable: jwt.decode without algorithms allow-list.

### Community 72 - "CVE-2023-50447-pillow/app/app.py"
Cohesion: 0.50
Nodes (3): post, Vulnerable: Image.open on attacker-uploaded files., thumb()

### Community 73 - "S1 — Exploit Path Verification"
Cohesion: 0.50
Nodes (3): Objectives, Output, S1 — Exploit Path Verification

## Knowledge Gaps
- **110 isolated node(s):** `joern-run.sh script`, `TERM`, `SL_LOGGING_LEVEL`, `samples/gin-demo`, `samples/xtext-demo` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **32 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `EvidenceSet` connect `BlueprintStore` to `api/__init__.py`, `post`, `joern.py`, `plan`, `BaseModel`, `assess`, `conftest.py`, `Settings`, `S3 — Deployment Context Verification`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Why does `ScanSession` connect `Settings` to `test_agent.py`, `joern.py`, `EvidenceUnavailable`, `assess`, `test_baseline.py`, `conftest.py`, `test_pipeline.py`, `S1 — Exploit Path Verification`, `S3 — Deployment Context Verification`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Why does `assess()` connect `assess` to `EvidenceSet`, `BlueprintStore`, `BaseModel`, `joern.py`, `plan`, `test_baseline.py`, `CoreError`, `test_baseline.py`, `conftest.py`, `Settings`, `S1 — Exploit Path Verification`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **Are the 9 inferred relationships involving `ScanSession` (e.g. with `_State` and `Probe`) actually correct?**
  _`ScanSession` has 9 INFERRED edges - model-reasoned connections that need verification._
- **What connects `joern-run.sh script`, `TERM`, `SL_LOGGING_LEVEL` to the rest of the system?**
  _110 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `EvidenceSet` be split into smaller, more focused modules?**
  _Cohesion score 0.12380952380952381 - nodes in this community are weakly interconnected._
- **Should `joern_remote` be split into smaller, more focused modules?**
  _Cohesion score 0.05146242132543503 - nodes in this community are weakly interconnected._