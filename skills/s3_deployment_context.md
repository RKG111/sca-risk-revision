---
id: s3
name: Deployment Context Verification
description: Assess network exposure, isolation, and deployment topology relevant to exploitability.
depends_on: []
tools: [graphify_query]
output_file: s3_output.json
---

# S3 — Deployment Context Verification

Gather deployment and exposure context: whether the vulnerable surface is network-reachable,
isolated, behind auth, or internal-only.

## Output

Return JSON with: `summary`, `verdict` (`exposed` | `isolated` | `inconclusive`),
`evidence`, `citations`, `path_gates`, `review_flags`.
