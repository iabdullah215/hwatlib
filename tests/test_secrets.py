from __future__ import annotations

from pathlib import Path

from hwatlib.secrets import scan_paths, summarize


def test_secrets_scan_and_summarize(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nPASSWORD=supersecret\n", encoding="utf-8")

    findings = scan_paths([str(tmp_path)])
    s = summarize(findings)

    assert s.count >= 1
    assert s.max_risk >= 6
    assert any(f["preview"] for f in s.findings)
