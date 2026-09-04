---
id: s2
name: Security Misconfiguration Verification
description: Check whether insecure configuration or loader choices enable the vulnerability.
depends_on: [s1]
tools: [check_connection, find_call_sites, graphify_query]
output_file: s2_output.json
---

# S2 — Security Misconfiguration Verification

Determine whether the product uses insecure configuration that activates the vulnerability
(for example unsafe YAML loaders, debug flags, or permissive defaults).

Use prior S1 findings when available. Prefer CPG/tool evidence over speculation.

## Output

Return JSON with: `summary`, `verdict` (`misconfig_present` | `misconfig_absent` | `inconclusive`),
`evidence`, `citations`, `path_gates`, `review_flags`.
