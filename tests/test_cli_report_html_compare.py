from __future__ import annotations

import json

import pytest

from hwatlib.report import new_report


def _fake_report_factory(findings, risk):
    def fake_build_report(**kwargs):
        r = new_report(target=kwargs["target"])
        r.metadata["risk"] = risk
        r.metadata["findings"] = findings
        return r

    return fake_build_report


def test_cli_out_html(monkeypatch, tmp_path, capsys):
    import hwatlib.cli as cli

    monkeypatch.setattr(
        cli, "build_report",
        _fake_report_factory(
            [{"category": "secrets", "title": "Secret", "severity": "high"}],
            {"score": 55, "level": "medium"},
        ),
    )
    out_html = tmp_path / "report.html"
    code = cli.main(["report", "example.com", "--out-html", str(out_html)])
    assert code == 0
    html = out_html.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "Secret" in html
    # HTML output suppresses the default stdout JSON dump.
    assert capsys.readouterr().out.strip() == ""


def test_cli_compare_attaches_diff(monkeypatch, tmp_path, capsys):
    import hwatlib.cli as cli

    # Previous report on disk (lower risk, one finding).
    prev = {
        "metadata": {
            "risk": {"score": 20, "level": "low"},
            "findings": [{"category": "a", "title": "old", "severity": "low"}],
        },
        "web": {"tech": {"hints": ["nginx"]}},
        "recon": {"fingerprint": {"80": {}}},
    }
    prev_path = tmp_path / "prev.json"
    prev_path.write_text(json.dumps(prev))

    monkeypatch.setattr(
        cli, "build_report",
        _fake_report_factory(
            [{"category": "b", "title": "new", "severity": "high"}],
            {"score": 65, "level": "high"},
        ),
    )

    out_json = tmp_path / "cur.json"
    code = cli.main(["report", "example.com", "--compare", str(prev_path), "--out-json", str(out_json)])
    assert code == 0

    report = json.loads(out_json.read_text(encoding="utf-8"))
    diff = report["metadata"]["diff"]
    assert diff["risk"]["delta"] == 45
    assert len(diff["findings"]["added"]) == 1
    assert len(diff["findings"]["removed"]) == 1


def test_cli_compare_html_includes_diff_section(monkeypatch, tmp_path):
    import hwatlib.cli as cli

    prev = {"metadata": {"risk": {"score": 10, "level": "low"}, "findings": []}}
    prev_path = tmp_path / "prev.json"
    prev_path.write_text(json.dumps(prev))

    monkeypatch.setattr(
        cli, "build_report",
        _fake_report_factory([], {"score": 30, "level": "medium"}),
    )
    out_html = tmp_path / "r.html"
    cli.main(["report", "example.com", "--compare", str(prev_path), "--out-html", str(out_html)])
    html = out_html.read_text(encoding="utf-8")
    assert "Changes since previous scan" in html
    assert "delta 20" in html


def test_cli_compare_missing_file_errors(monkeypatch, tmp_path):
    import hwatlib.cli as cli

    monkeypatch.setattr(cli, "build_report", _fake_report_factory([], {"score": 0, "level": "info"}))
    with pytest.raises(SystemExit):
        cli.main(["report", "example.com", "--compare", str(tmp_path / "nope.json")])
