# Sample CVE assessment dataset

Multi-language fixtures for exercising the SCA risk-rescoring pipeline.

## Layout

```text
samples/
  <language>/
    <CVE-ID>-<package>/
      blueprint.json   # component–CVE research blueprint
      sbom.json        # minimal CycloneDX SBOM for that finding
      app/             # small product-like code that uses the vulnerable package
      README.md
```

## Languages (3 CVEs each)

| Language | CVE folders |
|----------|-------------|
| python | `CVE-2020-14343-pyyaml`, `CVE-2022-29217-pyjwt`, `CVE-2023-50447-pillow` |
| java | `CVE-2021-44228-log4j`, `CVE-2019-12384-jackson`, `CVE-2022-22965-spring` |
| npm | `CVE-2021-23337-lodash`, `CVE-2022-23812-node-ipc`, `CVE-2021-23358-underscore` |
| go | `CVE-2022-28948-yaml`, `CVE-2021-38561-xtext`, `CVE-2020-28483-gin` |

## Notes

- Apps are **fixtures for static / CPG assessment**, not exploit kits.
- Prefer copying a case's `blueprint.json` into `blueprints/` (or pointing
  `BLUEPRINT_STORE_PATH` at a case directory) when running the pipeline.
- For npm `CVE-2022-23812-node-ipc`, treat as an **inclusion** case (empty sinks);
  do not install/run known-malicious versions on shared hosts.
- Java/Go apps include manifests (`pom.xml` / `go.mod`) so Joern and SCA tools
  can resolve the vulnerable component; compile only if you need a live server.

## Regenerate

```bash
python samples/_generate.py
```
