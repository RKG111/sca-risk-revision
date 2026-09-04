---
id: s4
name: Mitigation Verification
description: Identify compensating controls that reduce or eliminate exploit impact.
depends_on: [s1]
tools: [find_call_sites, graphify_query]
output_file: s4_output.json
---

# S4 — Mitigation Verification

Look for mitigations such as input validation wrappers, sandboxing, allow-lists, patched
APIs, or runtime controls that block the exploit path found by S1.

## Output

Return JSON with: `summary`, `verdict` (`mitigated` | `partially_mitigated` | `unmitigated` | `inconclusive`),
`evidence`, `citations`, `path_gates`, `review_flags`.
