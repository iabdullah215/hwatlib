from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .http import HttpOptions


@dataclass
class HwatConfig:
    http: HttpOptions = field(default_factory=HttpOptions)


def default_config_path() -> Path:
    return Path.home() / ".config" / "hwat" / "config.toml"


def load_config(
    *,
    profile: str = "default",
    path: Optional[str] = None,
) -> HwatConfig:
    """Load config from TOML (~/.config/hwat/config.toml) + env vars.

    TOML format (minimal):

      [profiles.default.http]
      timeout = 5.0
      verify = true
      rate_limit_per_sec = 2.0

      [profiles.default.http.proxies]
      http = "http://127.0.0.1:8080"
      https = "http://127.0.0.1:8080"

      [profiles.default.http.headers]
      User-Agent = "hwatlib"

    Env vars override file:
      HWAT_TIMEOUT, HWAT_VERIFY, HWAT_RATE_LIMIT_PER_SEC,
      HWAT_PROXY_HTTP, HWAT_PROXY_HTTPS,
      HWAT_HEADERS_JSON, HWAT_COOKIES_JSON
    """

    cfg = HwatConfig()

    toml_path = Path(path) if path else default_config_path()
    data: Dict[str, Any] = {}
    if toml_path.exists():
        try:
            import tomllib  # py3.11+

            data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    cfg.http = _apply_toml_http(cfg.http, data, profile=profile)
    cfg.http = _apply_env_http(cfg.http)
    return cfg


def _apply_toml_http(options: HttpOptions, data: Dict[str, Any], *, profile: str) -> HttpOptions:
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, dict):
        return options

    prof = profiles.get(profile)
    if not isinstance(prof, dict):
        return options

    http = prof.get("http")
    if not isinstance(http, dict):
        return options

    _set_if_present(options, http, "timeout")
    _set_if_present(options, http, "verify")
    _set_if_present(options, http, "rate_limit_per_sec")
    _set_if_present(options, http, "retries")
    _set_if_present(options, http, "backoff_factor")
    _set_if_present(options, http, "max_concurrency")

    proxies = http.get("proxies")
    if isinstance(proxies, dict):
        options.proxies = {str(k): str(v) for k, v in proxies.items()}

    headers = http.get("headers")
    if isinstance(headers, dict):
        options.headers.update({str(k): str(v) for k, v in headers.items()})

    cookies = http.get("cookies")
    if isinstance(cookies, dict):
        options.cookies.update({str(k): str(v) for k, v in cookies.items()})

    return options


def _apply_env_http(options: HttpOptions) -> HttpOptions:
    _apply_env_float(options, "timeout", "HWAT_TIMEOUT")
    _apply_env_bool(options, "verify", "HWAT_VERIFY")
    _apply_env_float(options, "rate_limit_per_sec", "HWAT_RATE_LIMIT_PER_SEC")
    _apply_env_float(options, "max_concurrency", "HWAT_MAX_CONCURRENCY")
    _apply_env_proxies(options)
    _apply_env_json_dict(options.headers, "HWAT_HEADERS_JSON")
    _apply_env_json_dict(options.cookies, "HWAT_COOKIES_JSON")
    return options


def _apply_env_float(options: HttpOptions, field_name: str, env_name: str) -> None:
    value = os.getenv(env_name)
    if value is None:
        return
    try:
        setattr(options, field_name, float(value))
    except Exception:
        return


def _apply_env_bool(options: HttpOptions, field_name: str, env_name: str) -> None:
    value = os.getenv(env_name)
    if value is None:
        return
    v = value.strip().lower()
    if v in {"1", "true", "yes", "on"}:
        setattr(options, field_name, True)
    elif v in {"0", "false", "no", "off"}:
        setattr(options, field_name, False)


def _apply_env_proxies(options: HttpOptions) -> None:
    proxy_http = os.getenv("HWAT_PROXY_HTTP")
    proxy_https = os.getenv("HWAT_PROXY_HTTPS")
    if not (proxy_http or proxy_https):
        return
    proxies = dict(options.proxies or {})
    if proxy_http:
        proxies["http"] = proxy_http
    if proxy_https:
        proxies["https"] = proxy_https
    options.proxies = proxies


def _apply_env_json_dict(dst: Dict[str, str], env_name: str) -> None:
    raw = os.getenv(env_name)
    if not raw:
        return
    dst.update(_load_json_dict(raw))


def _load_json_dict(value: str) -> Dict[str, str]:
    try:
        obj = json.loads(value)
        if isinstance(obj, dict):
            return {str(k): str(v) for k, v in obj.items()}
    except Exception:
        pass
    return {}


def _set_if_present(options: HttpOptions, src: Dict[str, Any], key: str) -> None:
    if key in src:
        setattr(options, key, src[key])
