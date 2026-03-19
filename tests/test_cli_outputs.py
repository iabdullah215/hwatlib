from __future__ import annotations

import json

from hwatlib.models import CrawlResult, WebResult
from hwatlib.report import new_report


def test_cli_report_writes_json_md_and_sitemap_files(monkeypatch, tmp_path, capsys):
    import hwatlib.cli as cli

    def fake_build_report(**kwargs):
        r = new_report(target=kwargs["target"])
        r.web = WebResult(
            ok=True,
            sitemap=CrawlResult(
                base="https://example.test",
                count=2,
                links=["https://example.test/a", "https://example.test/b"],
            ),
        )
        return r

    monkeypatch.setattr(cli, "build_report", fake_build_report)

    out_json = tmp_path / "report.json"
    out_md = tmp_path / "report.md"
    sitemap_json = tmp_path / "sitemap.json"
    sitemap_csv = tmp_path / "sitemap.csv"

    code = cli.main(
        [
            "report",
            "example.com",
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
            "--sitemap-json",
            str(sitemap_json),
            "--sitemap-csv",
            str(sitemap_csv),
        ]
    )

    assert code == 0
    assert out_json.exists()
    assert out_md.exists()
    assert sitemap_json.exists()
    assert sitemap_csv.exists()

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["metadata"]["target"] == "example.com"

    md = out_md.read_text(encoding="utf-8")
    assert "# hwatlib report" in md

    out = capsys.readouterr().out.strip()
    assert out == ""


def test_cli_report_prints_json_when_no_output_files(monkeypatch, capsys):
    import hwatlib.cli as cli

    def fake_build_report(**kwargs):
        return new_report(target=kwargs["target"])

    monkeypatch.setattr(cli, "build_report", fake_build_report)

    code = cli.main(["report", "example.com"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["metadata"]["target"] == "example.com"
