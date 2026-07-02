AI-Powered Vulnerability Rescoring Platform - Knowledge Transfer
This document serves as a comprehensive knowledge transfer (KT) guide for the architecture, methodology, and implementation phases of the AI-Powered Vulnerability Rescoring Platform. It outlines the core concept, execution plan, modular sub-problems, and specific vulnerability use cases.

1. The Core Idea & Problem Statement
The Problem: Alert Fatigue in Static Analysis
Standard Software Composition Analysis (SCA) and Vulnerability Management workflows suffer from severe alert fatigue. They flag security flaws based purely on raw version strings matched against the National Vulnerability Database (NVD). This approach completely ignores the actual runtime context, code structural layout, and environmental configuration of the product, resulting in a high volume of false positives and generic CVSS scores that do not reflect true risk.
The Solution: Context-Aware Rescoring
To achieve an optimal risk assessment, a system must move past generic scoring. It must evaluate how a target codebase uses a vulnerable package and how the system is deployed. This evidence must then be used to reconstruct and calculate all core Base Score Metrics from the ground up, discarding abstract assumptions in favor of code-proven facts.
Attack Vector (AV)
Attack Complexity (AC)
Privileges Required (PR)
User Interaction (UI)
Scope (S)
Confidentiality (C), Integrity (I), and Availability (A)

2. High-Level Architecture (The Plan)
The platform ingests a CycloneDX SBOM, the product's codebase, and its deployment architecture documentation to evaluate vulnerabilities in context. The workflow is executed in a structured pipeline:
Ingestion & Indexing: The system parses inputs and generates a token-optimized structural map of the codebase to prevent LLM context-window explosion.
Threat Modeling: A generic CVE is translated into a highly structured exploitability blueprint mapping out exact required conditions.
Triage & Assessment: The blueprint routes through a decoupled, two-tier evaluation framework: a deterministic code-graph engine handles straightforward code-path checks, while an agentic, tool-equipped LLM manages complex semantic conditions.
Evidence & Rescoring: Collected evidence (reachability, mitigation presence) is evaluated against standard CVSS definitions to compute a new score, outputting a contextualized compliance report.

3. Sub-Problem Statements (Modular Breakdown)
The platform is split into five distinct, independent modules to decouple research efforts and simplify development.
Module 1: Code Ingestion & Token-Optimized Indexer
Objective: Ingest the repository and create an index optimized for low token usage, allowing an AI agent to navigate it efficiently.
Implementation: Compile source code into a Code Property Graph (CPG) via Joern. Use Tree-sitter to extract function signatures and import maps. Expose a lightweight, searchable structural skeleton map to a vector database.
Module 2: Threat Modeling & Attack Blueprint Generator
Objective: Convert raw CVE data and architectural constraints into an actionable, machine-readable validation plan.
Implementation: Query NVD/MITRE/CISA. Use an LLM to generate a strict JSON blueprint detailing exact code targets (vulnerable symbols), deployment variables, and reachability requirements.
Module 3: Deterministic Triage & Analysis Engine
Objective: Validate explicit, mathematical code flows using rules-based tools to resolve straightforward vulnerabilities instantly.
Implementation: Translate JSON blueprint conditions into automated Joern CPGQL graph queries or Semgrep AST syntax rules. Provide definitive YES/NO answers on data flow paths.
Module 4: Agentic Reasoning Loop (LangGraph Agent)
Objective: Handle non-deterministic, semantic security conditions where static rules create excessive noise or fail outright.
Implementation: Initialize a cyclic LangGraph workflow equipped with local utility tools (e.g., file search, AST slice extraction, cross-reference tracing) to evaluate complex conditions like custom validation logic.
Module 5: Context-Aware CVSS Rescoring Engine
Objective: Map the collected evidence directly to CVSS metrics and output the updated risk score.
Implementation: Evaluate evidence against CVSS Base Score definitions. Programmatically compute the final score via the official FIRST cvss Python library and export a signed justification report.

4. Vulnerability Assessment Matrix (The Cases)
Vulnerabilities are classified by their technical structures to determine whether they can be resolved using deterministic tools or if they require an AI agent.
Vulnerability Type (CWE Group)
Assessment Strategy
Technical Justification
 
Known Vulnerable Dependency Calls (CWE-1104 / CWE-1395)
Deterministic
Joern can map the import tree and verify if the proprietary code actually references or invokes the vulnerable package symbols.
Classic Injection Flaws (CWE-89: SQLi, CWE-78: OS Command)
Deterministic
Proven through static taint analysis; data flow tracking can mathematically trace an untrusted source directly to an un-sanitized sink execution block.
Insecure Cryptographic / Hardcoded Secrets (CWE-327, CWE-798)
Deterministic
Easily checked via abstract syntax tree (AST) matching with Semgrep rules looking for weak algorithms or literal strings assigned to key variables.
Broken Object Level Authentication / IDOR (CWE-639, CWE-284)
AI Agent
Requires a semantic understanding of business logic. Static tools cannot verify if an application-level identifier check properly matches authorization records without context.
Deserialization Gadget Chains (CWE-502)
AI Agent
Validating if a multi-step sequence of object magic methods will successfully execute a payload requires an understanding of semantic type interactions.
Server-Side Request Forgery (SSRF) (CWE-918)
AI Agent
Needs combined evaluation of the code's URL parsing behavior and the deployment environment's network isolation layout to see if internal endpoints are actually exposed.
Race Conditions & Concurrency Issues (CWE-362)
AI Agent
Highly dynamic and notoriously noisy for traditional tools. Evaluating true impact requires reading the threading architecture alongside deployment configuration documents.


5. Reference: Target Blueprint JSON Schema
The following JSON schema represents the expected output from the Blueprint Generator (Module 2), which acts as the instruction set for Modules 3 and 4.
{
  "cve_id": "CVE-202X-XXXX",
  "mappings": {
    "cwe_id": "CWE-94",
    "capec_ids": ["CAPEC-242", "CAPEC-126"]
  },
  "exploit_blueprint": {
    "deterministic_verification_feasibility": "HIGH", 
    "required_conditions": {
      "code_level": {
        "vulnerable_symbol": "unsafe_deserialize",
        "package_context": "org.yaml.snakeyaml",
        "expected_data_flow": "User input passed directly into Constructor without validation"
      },
      "environment_level": {
        "runtime_version_constraints": "Java <= 17",
        "required_feature_flags": ["enable_custom_templates"],
        "network_exposure": "public_ingress"
      }
    },
    "exploitation_mechanism": {
      "step_by_step": "1. Attacker sends malicious YAML... 2. App invokes... 3. RCE triggered.",
      "indicators_of_reachability": [
        "yaml.load(",
        "YamlReader.read("
      ]
    },
    "true_impact_vectors": {
      "confidentiality": "HIGH",
      "integrity": "HIGH",
      "availability": "HIGH"
    }
  }
}



6. The Final Output (Rescored Vulnerability Report)
Once the evidence is collected and the CVSS score is recalculated, the platform outputs a final compliance and justification report. This output compares the original NVD score with the newly calculated contextual score, providing the mathematical delta and the specific evidence trail used to alter the metrics.
{
  "cve_id": "CVE-2022-1471",
  "component": "pkg:maven/org.yaml/snakeyaml@1.30",
  "original_assessment": {
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "score": 9.8,
    "severity": "CRITICAL"
  },
  "rescored_assessment": {
    "cvss_v3_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "score": 0.0,
    "severity": "NONE",
    "score_delta": -9.8
  },
  "evidence_justification": {
    "reachability_verified": false,
    "execution_trace": "Function Constructor() in snakeyaml is never invoked by proprietary codebase.",
    "environmental_mitigations": "Application runs in isolated VPC without external ingress.",
    "confidence_score": 1.0,
    "verification_method": "Deterministic (Joern CPG Analysis)"
  }
}



7. Sample Input: CycloneDX SBOM (Black Duck Style)
The system ingests a standard CycloneDX (cdx) SBOM to identify the target components and their associated vulnerabilities. Tools like Black Duck map vulnerabilities to components using the bom-ref identifier inside the affects array.
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "author": "Synopsys",
          "name": "Black Duck Hub",
          "version": "2023.4.2"
        }
      ]
    },
    "component": {
      "type": "application",
      "name": "acme-payment-gateway",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:maven/org.yaml/snakeyaml@1.30?type=jar",
      "publisher": "SnakeYAML",
      "group": "org.yaml",
      "name": "snakeyaml",
      "version": "1.30",
      "purl": "pkg:maven/org.yaml/snakeyaml@1.30?type=jar"
    }
  ],
  "vulnerabilities": [
    {
      "bom-ref": "vuln-CVE-2022-1471",
      "id": "CVE-2022-1471",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-1471"
      },
      "ratings": [
        {
          "source": { "name": "NVD" },
          "score": 9.8,
          "severity": "critical",
          "method": "CVSSv31",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      ],
      "affects": [
        {
          "ref": "pkg:maven/org.yaml/snakeyaml@1.30?type=jar"
        }
      ]
    }
  ]
}


