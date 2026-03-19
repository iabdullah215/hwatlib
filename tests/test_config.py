from __future__ import annotations

from pathlib import Path

import pytest

from hwatlib.config import load_config
from hwatlib.http import HttpOptions


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


def test_invalid_env_values_fall_back_to_defaults(monkeypatch):
    defaults = HttpOptions()

    monkeypatch.setenv("HWAT_TIMEOUT", "not-a-number")
    monkeypatch.setenv("HWAT_VERIFY", "maybe")
    monkeypatch.setenv("HWAT_MAX_CONCURRENCY", "many")

    cfg = load_config(profile="default", path=None)

    assert cfg.http.timeout == pytest.approx(defaults.timeout)
    assert cfg.http.verify is defaults.verify
    assert cfg.http.max_concurrency == defaults.max_concurrency


def test_out_of_range_toml_values_fall_back_to_defaults(tmp_path: Path):
    defaults = HttpOptions()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        """
[profiles.default.http]
timeout = -1
rate_limit_per_sec = 0
max_concurrency = 999999
retries = 999
backoff_factor = -5
""".lstrip(),
        encoding="utf-8",
    )

    cfg = load_config(profile="default", path=str(cfg_path))

    assert cfg.http.timeout == pytest.approx(defaults.timeout)
    assert cfg.http.rate_limit_per_sec == defaults.rate_limit_per_sec
    assert cfg.http.max_concurrency == defaults.max_concurrency
    assert cfg.http.retries == defaults.retries
    assert cfg.http.backoff_factor == pytest.approx(defaults.backoff_factor)


def test_invalid_env_values_emit_warnings(monkeypatch, caplog):
    monkeypatch.setenv("HWAT_TIMEOUT", "abc")
    monkeypatch.setenv("HWAT_VERIFY", "sometimes")
    monkeypatch.setenv("HWAT_HEADERS_JSON", "[1,2,3]")

    caplog.set_level("WARNING")
    load_config(profile="default", path=None)

    messages = "\n".join(r.message for r in caplog.records)
    assert "Ignoring invalid float env HWAT_TIMEOUT" in messages
    assert "Ignoring invalid boolean env HWAT_VERIFY" in messages
    assert "Ignoring invalid JSON object env HWAT_HEADERS_JSON" in messages


def test_out_of_range_values_emit_warnings(tmp_path: Path, caplog):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        """
[profiles.default.http]
timeout = 100000
max_concurrency = 0
""".lstrip(),
        encoding="utf-8",
    )

    caplog.set_level("WARNING")
    load_config(profile="default", path=str(cfg_path))

    messages = "\n".join(r.message for r in caplog.records)
    assert "Out-of-range timeout" in messages
    assert "Out-of-range max_concurrency" in messages


def test_strict_mode_raises_on_invalid_env(monkeypatch):
    monkeypatch.setenv("HWAT_TIMEOUT", "abc")

    with pytest.raises(ValueError) as e:
        load_config(profile="default", path=None, strict=True)

    assert "invalid float env HWAT_TIMEOUT" in str(e.value)


def test_strict_mode_env_flag_raises(monkeypatch):
    monkeypatch.setenv("HWAT_CONFIG_STRICT", "1")
    monkeypatch.setenv("HWAT_VERIFY", "sometimes")

    with pytest.raises(ValueError) as e:
        load_config(profile="default", path=None)

    assert "invalid boolean env HWAT_VERIFY" in str(e.value)


def test_strict_mode_raises_on_out_of_range_toml(tmp_path: Path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        """
[profiles.default.http]
timeout = 100000
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as e:
        load_config(profile="default", path=str(cfg_path), strict=True)

    assert "Out-of-range timeout" in str(e.value)
