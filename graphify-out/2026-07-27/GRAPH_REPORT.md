# Graph Report - /home/dagger/PROJECTS/sca-risk-revision  (2026-07-27)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 505 nodes · 1205 edges · 25 communities (21 shown, 4 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 140 edges (avg confidence: 0.59)
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
- Path
- joern-mcp

## God Nodes (most connected - your core abstractions)
1. `ComponentCveBlueprint` - 34 edges
2. `JoernClient` - 26 edges
3. `joern_remote()` - 24 edges
4. `MetricsDeterminationEngine` - 21 edges
5. `SkillResults` - 20 edges
6. `SkillRunner` - 19 edges
7. `SkillAgentRunner` - 18 edges
8. `S1ExploitPathSkill` - 18 edges
9. `S4MitigationSkill` - 18 edges
10. `ReportBuilder` - 18 edges

## Surprising Connections (you probably didn't know these)
- `AnalysisRequest` --uses--> `ReportBuilder`  [INFERRED]
  api/routers/analysis.py → modules/rescoring/report_builder.py
- `AnalysisRequest` --uses--> `RiskAssessmentResult`  [INFERRED]
  api/routers/analysis.py → schemas/report.py
- `AnalysisRequest` --uses--> `CycloneDXSBOM`  [INFERRED]
  api/routers/analysis.py → schemas/sbom.py
- `AnalysisResponse` --uses--> `ReportBuilder`  [INFERRED]
  api/routers/analysis.py → modules/rescoring/report_builder.py
- `AnalysisResponse` --uses--> `RiskAssessmentResult`  [INFERRED]
  api/routers/analysis.py → schemas/report.py

## Import Cycles
- None detected.

## Communities (25 total, 4 thin omitted)

### Community 0 - "ComponentCveBlueprint"
Cohesion: 0.08
Nodes (48): Central settings — loaded from environment / .env via pydantic-settings., Path, Map host filesystem paths to Joern container paths., Map a host path to Joern's container path (repo mounted at JOERN_WORKSPACE_PATH), to_joern_path(), AgentState, LangGraph skill agent runner.  Loads per-skill SKILL.md instructions, runs a t, SkillAgentRunner (+40 more)

### Community 1 - "joern_remote"
Cohesion: 0.05
Nodes (68): extract_code_between_triple_quotes(), extract_list(), extract_long_value(), extract_quoted_string(), extract_value(), Extract value from a string based on its pattern.          This function automat, Extract content between triple quotes from a string.          Args:         inpu, Extract a list of elements from a string representation of a Scala List. (+60 more)

### Community 2 - "runner.py"
Cohesion: 0.05
Nodes (42): ABC, JoernClient, BaseSkill, Any, Return a Pydantic evidence model for this skill., _candidate_import_keys(), check_component_presence(), package_tokens_from_purl() (+34 more)

### Community 3 - "JoernClient"
Cohesion: 0.07
Nodes (35): AnalysisRequest, AnalysisResponse, _ensure_joern_index(), BaseModel, Path, post, POST /api/v1/analyze  Accepts a CycloneDX SBOM + CVE ID + codebase path, loads a, Best-effort Joern CPG import. Returns True if indexed. (+27 more)

### Community 4 - "evidence.py"
Cohesion: 0.12
Nodes (30): computed_field, EvidenceAggregator, Evidence aggregator — builds a compact digest for the metrics determination engi, MetricsDeterminationEngine, ComponentCveBlueprint, Hybrid Metrics Determination Engine (MDE).  1. Keep original base CVSS vector 2., Attempt constrained LLM fill; fall back to base values on failure., CVSS 3.1 environmental vector includes base metrics plus environmental. (+22 more)

### Community 5 - "mcp/registry.py"
Cohesion: 0.16
Nodes (26): _builtin_joern_config(), default_config_path(), enabled_server_ids(), _expand_env(), _expand_obj(), load_server_configs(), mcp_tools_session(), McpServerConfig (+18 more)

### Community 6 - "tools.py"
Cohesion: 0.12
Nodes (22): tool, Filesystem tools shared by S2–S4 skill agents., Search files by glob pattern relative to codebase root (e.g. '*.yml', '*Dockerfi, Read a line range from a file (1-indexed, inclusive)., Search for a literal substring across files matching file_glob., Read snippets from product documentation path if configured., read_file_slice(), read_product_docs() (+14 more)

### Community 7 - "stack.sh"
Cohesion: 0.25
Nodes (22): api_running(), bad(), cmd_logs(), cmd_start(), cmd_status(), cmd_stop(), ensure_api(), ensure_joern() (+14 more)

### Community 8 - "CycloneDXSBOM"
Cohesion: 0.15
Nodes (13): model_validator, AffectsRef, CVSSRating, CycloneDXSBOM, MetadataComponent, BaseModel, RatingSource, CycloneDX SBOM input schema (1.5 subset).  Parses real CycloneDX vulnerability (+5 more)

### Community 9 - "blueprint.py"
Cohesion: 0.21
Nodes (14): AffectedComponent, BlueprintCondition, BlueprintCVSS, BlueprintMitigation, BlueprintReferences, ConditionConfidence, ConditionType, MitigationStrength (+6 more)

### Community 10 - "test_mcp_client.py"
Cohesion: 0.18
Nodes (15): main(), Test call-related queries, Test method name-related queries, Test ping functionality, Test loading CPG file, Test method-related queries, Test server connection, Test class-related queries (+7 more)

### Community 11 - "joern_tools.py"
Cohesion: 0.27
Nodes (13): _container_path(), _get_client(), get_joern_tools(), joern_get_calls(), joern_import_code(), joern_query(), joern_taint_to_sink(), tool (+5 more)

### Community 12 - "main.py"
Cohesion: 0.21
Nodes (10): health(), lifespan(), get, SCA Risk Rescoring Platform — FastAPI entry point.  Endpoints:   POST /api/v1/an, get_report(), JobStatus, BaseModel, get (+2 more)

### Community 13 - ".run"
Cohesion: 0.20
Nodes (6): ChatOpenAI, Any, load_skill_instructions(), Load per-skill agent instruction files.  Convention: modules/skills/instructio, Return markdown instructions for a skill id., T

### Community 15 - "app.py"
Cohesion: 0.40
Nodes (3): load_config(), post, Sample vulnerable usage of PyYAML FullLoader for end-to-end fixtures.

## Knowledge Gaps
- **2 isolated node(s):** `joern-run.sh script`, `joern-mcp`
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JoernClient` connect `JoernClient` to `ComponentCveBlueprint`, `joern_tools.py`, `tools.py`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **Why does `ComponentCveBlueprint` connect `ComponentCveBlueprint` to `blueprint.py`, `runner.py`, `JoernClient`, `evidence.py`?**
  _High betweenness centrality (0.057) - this node is a cross-community bridge._
- **Why does `SkillRunner` connect `JoernClient` to `ComponentCveBlueprint`, `runner.py`, `evidence.py`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `ComponentCveBlueprint` (e.g. with `BlueprintStore` and `BaseSkill`) actually correct?**
  _`ComponentCveBlueprint` has 8 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `JoernClient` (e.g. with `AnalysisRequest` and `AnalysisResponse`) actually correct?**
  _`JoernClient` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 20 inferred relationships involving `joern_remote()` (e.g. with `remove_ansi_escape_sequences()` and `find_flows_from_method_params_to_sink_method()`) actually correct?**
  _`joern_remote()` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 9 inferred relationships involving `MetricsDeterminationEngine` (e.g. with `ActivationBasis` and `ActivationState`) actually correct?**
  _`MetricsDeterminationEngine` has 9 INFERRED edges - model-reasoned connections that need verification._