from __future__ import annotations

from pathlib import Path

import pytest

from hwatlib.config import load_config


def test_load_config_from_toml_profile(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        """
[profiles.default.http]
timeout = 9.5
verify = true
rate_limit_per_sec = 3.0

[profiles.default.http.proxies]
http = "http://127.0.0.1:8080"
""".lstrip(),
        encoding="utf-8",
    )

    cfg = load_config(profile="default", path=str(cfg_path))
    assert cfg.http.timeout == pytest.approx(9.5)
    assert cfg.http.verify is True
    assert cfg.http.rate_limit_per_sec == pytest.approx(3.0)
    assert cfg.http.proxies and cfg.http.proxies["http"].startswith("http://")


def test_env_overrides_toml(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        """
[profiles.default.http]
timeout = 1.0
verify = true
""".lstrip(),
        encoding="utf-8",
    )

    monkeypatch.setenv("HWAT_TIMEOUT", "4.0")
    monkeypatch.setenv("HWAT_VERIFY", "false")

    cfg = load_config(profile="default", path=str(cfg_path))
    assert cfg.http.timeout == pytest.approx(4.0)
    assert cfg.http.verify is False
