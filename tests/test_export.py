from __future__ import annotations

import json

import pytest

from hwatlib import export
from hwatlib.findings import Finding
from hwatlib.report import HwatReport, new_report


def _findings():
    return [
        Finding("secrets", "Secret found", "high", {"max_risk": 9, "url": "http://t/x"}, "Rotate"),
        Finding("web", "Tech hints", "info", {"hints": ["nginx"]}),
        Finding("secrets", "Secret found", "high", {"max_risk": 9, "url": "http://t/x"}),  # dup rule
    ]


# --- JSONL ---

def test_to_jsonl_one_object_per_line():
    out = export.to_jsonl(_findings())
    lines = out.splitlines()
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first["category"] == "secrets"
    assert first["severity"] == "high"


def test_to_jsonl_empty():
    assert export.to_jsonl([]) == ""


def test_to_jsonl_accepts_dicts():
    out = export.to_jsonl([{"category": "c", "title": "t", "severity": "low"}])
    assert json.loads(out.strip())["title"] == "t"


def test_write_jsonl_roundtrip(tmp_path):
    p = tmp_path / "f.jsonl"
    export.write_jsonl(_findings(), str(p))
    lines = p.read_text().splitlines()
    assert len(lines) == 3
    assert all(json.loads(line) for line in lines)


# --- SARIF ---

def test_to_sarif_shape_and_version():
    log = export.to_sarif(_findings(), run_id="run-1")
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "hwatlib"
    assert run["automationDetails"]["id"] == "run-1"


def test_to_sarif_dedupes_rules():
    run = export.to_sarif(_findings())["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    # 3 findings, 2 distinct (category,title) -> 2 rules.
    assert len(rule_ids) == 2
    assert len(run["results"]) == 3


def test_to_sarif_severity_maps_to_level_and_security_severity():
    run = export.to_sarif([Finding("c", "crit", "critical", {})])["runs"][0]
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["security-severity"] == "9.3"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"


def test_to_sarif_low_and_info_are_notes():
    for sev in ("low", "info", "unknown"):
        run = export.to_sarif([Finding("c", "t", sev, {})])["runs"][0]
        assert run["results"][0]["level"] == "note"


def test_to_sarif_location_from_evidence():
    run = export.to_sarif([Finding("c", "t", "high", {"url": "http://h/a"})])["runs"][0]
    loc = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "http://h/a"


def test_to_sarif_no_location_when_not_locatable():
    run = export.to_sarif([Finding("c", "t", "high", {"max_risk": 9})])["runs"][0]
    assert "locations" not in run["results"][0]


def test_to_sarif_partial_fingerprints_present():
    run = export.to_sarif(_findings())["runs"][0]
    fp = run["results"][0]["partialFingerprints"]["hwatlibFindingHash/v1"]
    assert isinstance(fp, str) and len(fp) == 64  # sha256 hex


def test_to_sarif_empty_findings():
    run = export.to_sarif([])["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


# --- report source ---

def test_export_from_report_uses_metadata_findings_and_run_id():
    report = new_report(target="example.test")
    report.metadata["run_id"] = "report-xyz"
    report.metadata["findings"] = [
        {"category": "web", "title": "t", "severity": "medium", "evidence": {"target": "example.test"}}
    ]
    sarif = export.to_sarif(report)
    assert sarif["runs"][0]["automationDetails"]["id"] == "report-xyz"
    assert len(sarif["runs"][0]["results"]) == 1
    jsonl = export.to_jsonl(report)
    assert json.loads(jsonl.strip())["title"] == "t"


def test_export_from_report_without_findings():
    report = HwatReport()
    assert export.to_jsonl(report) == ""
    assert export.to_sarif(report)["runs"][0]["results"] == []


def test_write_sarif_is_valid_json(tmp_path):
    p = tmp_path / "out.sarif"
    export.write_sarif(_findings(), str(p), run_id="r")
    loaded = json.loads(p.read_text())
    assert loaded["version"] == "2.1.0"


def test_normalize_rejects_bad_type():
    with pytest.raises(TypeError):
        export.to_jsonl([42])
