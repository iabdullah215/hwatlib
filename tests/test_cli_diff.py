from __future__ import annotations

import json


def test_cli_diff_outputs_json(tmp_path, capsys):
    import hwatlib.cli as cli

    old = {
        "metadata": {
            "risk": {"score": 1, "level": "low"},
            "findings": [
                {"category": "secrets", "title": "token", "severity": "high"},
            ],
        },
        "recon": {"fingerprint": {"22": {"banner": "OpenSSH"}}},
        "web": {"tech": {"hints": ["nginx"]}},
    }
    new = {
        "metadata": {
            "risk": {"score": 4, "level": "medium"},
            "findings": [
                {"category": "secrets", "title": "token", "severity": "high"},
                {"category": "web", "title": "admin panel", "severity": "medium"},
            ],
        },
        "recon": {"fingerprint": {"22": {"banner": "OpenSSH"}, "80": {"banner": "nginx"}}},
        "web": {"tech": {"hints": ["nginx", "php"]}},
    }

    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(old), encoding="utf-8")
    new_path.write_text(json.dumps(new), encoding="utf-8")

    exit_code = cli.main(["diff", str(old_path), str(new_path)])
    assert exit_code == 0

    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["risk"]["old_score"] == 1
    assert payload["risk"]["new_score"] == 4
    assert payload["risk"]["delta"] == 3

    assert payload["recon"]["ports_added"] == ["80"]
    assert payload["web"]["tech_hints_added"] == ["php"]

    added = payload["findings"]["added"]
    assert any(f.get("title") == "admin panel" for f in added)
