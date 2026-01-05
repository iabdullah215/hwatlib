from __future__ import annotations

from hwatlib.report import new_report


def test_new_report_includes_metadata_and_target():
    r = new_report(target="example.com")
    d = r.to_dict()

    assert d["metadata"]["target"] == "example.com"
    assert "generated_at" in d["metadata"]

    md = r.to_markdown()
    assert "# hwatlib report" in md
    assert "## Metadata" in md
