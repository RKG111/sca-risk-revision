"""
Contract tests: SBOM parsing, blueprint lookup, and PURL handling.

These are the boundaries where malformed external input arrives, so they get
pinned explicitly.
"""

from __future__ import annotations

import json

import pytest

from core.models import CycloneDXSBOM, EvidenceSet, ExploitPath, MitigationStrength, PathMitigationResult
from core.store import BlueprintStore, normalise_purl, package_tokens


class TestSBOM:
    def test_links_a_vulnerability_to_its_component_purl(self):
        sbom = CycloneDXSBOM.model_validate(
            {
                "components": [
                    {"bom-ref": "ref-1", "name": "pyyaml", "version": "5.3.1", "purl": "pkg:pypi/pyyaml@5.3.1"}
                ],
                "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "ref-1"}]}],
            }
        )
        assert sbom.affected_purl("CVE-1") == "pkg:pypi/pyyaml@5.3.1"

    def test_accepts_a_purl_used_directly_as_the_affects_ref(self):
        sbom = CycloneDXSBOM.model_validate(
            {
                "components": [],
                "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "pkg:npm/left-pad@1.0.0"}]}],
            }
        )
        assert sbom.affected_purl("CVE-1") == "pkg:npm/left-pad@1.0.0"

    def test_synthesises_a_purl_from_name_and_version(self):
        sbom = CycloneDXSBOM.model_validate(
            {
                "components": [{"bom-ref": "ref-1", "name": "thing", "version": "2.0"}],
                "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "ref-1"}]}],
            }
        )
        assert sbom.affected_purl("CVE-1") == "pkg:generic/thing@2.0"

    def test_returns_none_for_an_unknown_cve(self):
        sbom = CycloneDXSBOM.model_validate({"components": [], "vulnerabilities": []})
        assert sbom.affected_purl("CVE-9") is None

    def test_ignores_unknown_cyclonedx_fields(self):
        """Real SBOMs carry far more than we read; extra keys must not break parsing."""
        sbom = CycloneDXSBOM.model_validate(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:x",
                "metadata": {"tools": [{"name": "trivy"}]},
                "components": [{"name": "a", "version": "1", "type": "library", "publisher": "x"}],
                "vulnerabilities": [],
            }
        )
        assert sbom.components[0].name == "a"

    def test_parses_the_real_fixture(self, sample_sbom_dict, baseline_cve):
        sbom = CycloneDXSBOM.model_validate(sample_sbom_dict)
        assert sbom.affected_purl(baseline_cve) == "pkg:pypi/pyyaml@5.3.1"


class TestPurl:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("pkg:PyPI/PyYAML@5.3.1", "pkg:pypi/pyyaml@5.3.1"),
            ("pkg:pypi/pyyaml@5.3.1?arch=x86", "pkg:pypi/pyyaml@5.3.1"),
            ("  pkg:npm/Left-Pad@1.0.0  ", "pkg:npm/left-pad@1.0.0"),
        ],
    )
    def test_normalisation(self, raw, expected):
        assert normalise_purl(raw) == expected

    def test_version_is_significant(self):
        """Research done against one version says nothing about another."""
        assert normalise_purl("pkg:pypi/x@1.0") != normalise_purl("pkg:pypi/x@2.0")

    @pytest.mark.parametrize(
        "purl,expected",
        [
            ("pkg:pypi/pyyaml@5.3.1", "pyyaml"),
            ("pkg:npm/ua-parser-js@0.7.29", "ua_parser_js"),
            ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j"),
        ],
    )
    def test_tokens_include_the_expected_import_name(self, purl, expected):
        assert expected in package_tokens(purl)

    def test_tokens_are_deduplicated_case_insensitively(self):
        tokens = package_tokens("pkg:pypi/thing@1.0", "Thing")
        assert len(tokens) == len({t.lower() for t in tokens})

    def test_single_character_tokens_are_dropped(self):
        assert all(len(t) >= 2 for t in package_tokens("pkg:pypi/a@1.0"))


class TestBlueprintStore:
    def test_finds_the_fixture_blueprint(self, blueprint_dir, baseline_cve):
        store = BlueprintStore(blueprint_dir)
        blueprint = store.get(baseline_cve, "pkg:pypi/pyyaml@5.3.1")
        assert blueprint is not None
        assert blueprint.cve_id == baseline_cve
        assert "yaml.full_load" in blueprint.sinks

    def test_lookup_is_case_insensitive(self, blueprint_dir):
        store = BlueprintStore(blueprint_dir)
        assert store.get("cve-2020-14343", "pkg:PyPI/PyYAML@5.3.1") is not None

    def test_a_different_version_does_not_match(self, blueprint_dir, baseline_cve):
        store = BlueprintStore(blueprint_dir)
        assert store.get(baseline_cve, "pkg:pypi/pyyaml@6.0") is None

    def test_a_missing_directory_yields_nothing(self, tmp_path):
        store = BlueprintStore(tmp_path / "does-not-exist")
        assert store.load() == 0
        assert store.get("CVE-1", "pkg:pypi/x@1") is None

    def test_invalid_files_are_skipped_not_fatal(self, tmp_path, blueprint_dir, baseline_cve):
        (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
        (tmp_path / "wrong-shape.json").write_text('{"hello": 1}', encoding="utf-8")
        source = next(blueprint_dir.glob("*.json"))
        (tmp_path / "good.json").write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

        store = BlueprintStore(tmp_path)
        assert store.load() == 1
        assert store.get(baseline_cve, "pkg:pypi/pyyaml@5.3.1") is not None

    def test_blueprint_json_round_trips(self, blueprint_dir, baseline_cve):
        store = BlueprintStore(blueprint_dir)
        blueprint = store.get(baseline_cve, "pkg:pypi/pyyaml@5.3.1")
        reparsed = type(blueprint).model_validate(json.loads(blueprint.model_dump_json()))
        assert reparsed == blueprint


class TestEvidenceSet:
    def _paths(self, *ids):
        return [ExploitPath(path_id=i, sink="s", summary="x") for i in ids]

    def test_unmitigated_paths_excludes_only_high_strength_blocks(self):
        evidence = EvidenceSet(
            exploit_paths=self._paths("p1", "p2", "p3"),
            mitigations=[
                PathMitigationResult(
                    path_id="p1", mitigation_description="m", present=True,
                    strength=MitigationStrength.HIGH,
                ),
                PathMitigationResult(
                    path_id="p2", mitigation_description="m", present=True,
                    strength=MitigationStrength.LOW,
                ),
                PathMitigationResult(
                    path_id="p3", mitigation_description="m", present=False,
                    strength=MitigationStrength.HIGH,
                ),
            ],
        )
        assert {p.path_id for p in evidence.unmitigated_paths} == {"p2", "p3"}

    def test_sinks_hit_is_sorted_and_deduplicated(self):
        evidence = EvidenceSet(
            exploit_paths=[
                ExploitPath(path_id="p1", sink="b", summary=""),
                ExploitPath(path_id="p2", sink="a", summary=""),
                ExploitPath(path_id="p3", sink="a", summary=""),
            ]
        )
        assert evidence.sinks_hit == ["a", "b"]

    def test_a_mitigation_for_an_unknown_path_is_ignored(self):
        evidence = EvidenceSet(
            exploit_paths=self._paths("p1"),
            mitigations=[
                PathMitigationResult(
                    path_id="hallucinated", mitigation_description="m", present=True,
                    strength=MitigationStrength.HIGH,
                )
            ],
        )
        assert len(evidence.unmitigated_paths) == 1
