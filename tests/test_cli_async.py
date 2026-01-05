from __future__ import annotations

import json

import pytest


def test_cli_report_async_uses_async_workflow(monkeypatch, capsys):
    import hwatlib.cli as cli
    import hwatlib.workflows_async as workflows_async
    from hwatlib.report import new_report

    # Pretend aiohttp is installed so --async path is enabled.
    def fake_find_spec(name: str):
        return object() if name == "aiohttp" else None

    monkeypatch.setattr(cli.importlib.util, "find_spec", fake_find_spec)

    async def fake_build_report_async(**kwargs):
        report = new_report(target=kwargs["target"])
        report.metadata["async"] = True
        report.metadata["url"] = kwargs.get("url")
        return report

    monkeypatch.setattr(workflows_async, "build_report_async", fake_build_report_async)

    exit_code = cli.main(["report", "example.com", "--async"])
    assert exit_code == 0

    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert payload["metadata"]["target"] == "example.com"
    assert payload["metadata"]["async"] is True


def test_cli_report_async_errors_without_aiohttp(monkeypatch):
    import hwatlib.cli as cli

    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)

    with pytest.raises(SystemExit) as e:
        cli.main(["report", "example.com", "--async"])

    assert "aiohttp" in str(e.value).lower()
