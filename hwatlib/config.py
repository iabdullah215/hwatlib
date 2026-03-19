from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .http import HttpOptions
from .utils import setup_logger

logger = setup_logger()

_MAX_TIMEOUT = 300.0
_MAX_RATE_LIMIT = 10_000.0
_MAX_CONCURRENCY = 1_000
_MAX_RETRIES = 20
_MAX_BACKOFF = 60.0


def _load_toml_document(content: str) -> Dict[str, Any]:
    """Load TOML across Python versions.

    Uses stdlib tomllib on 3.11+ and falls back to tomli on 3.9/3.10.
    """

    try:
        import tomllib  # py3.11+

        return tomllib.loads(content)
    except ModuleNotFoundError:
        import tomli  # type: ignore[import-not-found]

        return tomli.loads(content)


@dataclass
class HwatConfig:
    http: HttpOptions = field(default_factory=HttpOptions)


def default_config_path() -> Path:
    return Path.home() / ".config" / "hwat" / "config.toml"


def load_config(
    *,
    profile: str = "default",
    path: Optional[str] = None,
    strict: Optional[bool] = None,
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

    strict_mode = _resolve_strict_mode(strict)
    cfg = HwatConfig()

    toml_path = Path(path) if path else default_config_path()
    data: Dict[str, Any] = {}
    if toml_path.exists():
        try:
            data = _load_toml_document(toml_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, ModuleNotFoundError) as e:
            msg = f"Failed to parse config file path={toml_path} error={e}"
            _config_issue(msg, strict=strict_mode)
            data = {}

    cfg.http = _apply_toml_http(cfg.http, data, profile=profile, strict=strict_mode)
    cfg.http = _apply_env_http(cfg.http, strict=strict_mode)
    return cfg


def _resolve_strict_mode(strict: Optional[bool]) -> bool:
    if strict is not None:
        return bool(strict)

    raw = os.getenv("HWAT_CONFIG_STRICT")
    if raw is None:
        return False

    v = raw.strip().lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False

    logger.warning("Ignoring invalid boolean env HWAT_CONFIG_STRICT=%r", raw)
    return False


def _apply_toml_http(options: HttpOptions, data: Dict[str, Any], *, profile: str, strict: bool) -> HttpOptions:
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

    return _validate_http_options(options, source=f"toml profile '{profile}'", strict=strict)


def _apply_env_http(options: HttpOptions, *, strict: bool) -> HttpOptions:
    _apply_env_float(options, "timeout", "HWAT_TIMEOUT", strict=strict)
    _apply_env_bool(options, "verify", "HWAT_VERIFY", strict=strict)
    _apply_env_float(options, "rate_limit_per_sec", "HWAT_RATE_LIMIT_PER_SEC", strict=strict)
    _apply_env_int(options, "max_concurrency", "HWAT_MAX_CONCURRENCY", strict=strict)
    _apply_env_int(options, "retries", "HWAT_RETRIES", strict=strict)
    _apply_env_float(options, "backoff_factor", "HWAT_BACKOFF_FACTOR", strict=strict)
    _apply_env_proxies(options)
    _apply_env_json_dict(options.headers, "HWAT_HEADERS_JSON", strict=strict)
    _apply_env_json_dict(options.cookies, "HWAT_COOKIES_JSON", strict=strict)
    return _validate_http_options(options, source="env", strict=strict)


def _apply_env_float(options: HttpOptions, field_name: str, env_name: str, *, strict: bool) -> None:
    value = os.getenv(env_name)
    if value is None:
        return
    try:
        setattr(options, field_name, float(value))
    except ValueError:
        _config_issue(f"Ignoring invalid float env {env_name}={value!r}", strict=strict)
        return


def _apply_env_int(options: HttpOptions, field_name: str, env_name: str, *, strict: bool) -> None:
    value = os.getenv(env_name)
    if value is None:
        return
    try:
        setattr(options, field_name, int(value))
    except ValueError:
        _config_issue(f"Ignoring invalid integer env {env_name}={value!r}", strict=strict)
        return


def _apply_env_bool(options: HttpOptions, field_name: str, env_name: str, *, strict: bool) -> None:
    value = os.getenv(env_name)
    if value is None:
        return
    v = value.strip().lower()
    if v in {"1", "true", "yes", "on"}:
        setattr(options, field_name, True)
    elif v in {"0", "false", "no", "off"}:
        setattr(options, field_name, False)
    else:
        _config_issue(f"Ignoring invalid boolean env {env_name}={value!r}", strict=strict)


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


def _apply_env_json_dict(dst: Dict[str, str], env_name: str, *, strict: bool) -> None:
    raw = os.getenv(env_name)
    if not raw:
        return
    parsed = _load_json_dict(raw, strict=strict)
    if parsed is None:
        _config_issue(f"Ignoring invalid JSON object env {env_name}", strict=strict)
        return
    dst.update(parsed)


def _load_json_dict(value: str, *, strict: bool) -> Optional[Dict[str, str]]:
    try:
        obj = json.loads(value)
        if isinstance(obj, dict):
            return {str(k): str(v) for k, v in obj.items()}
    except json.JSONDecodeError as err:
        if strict:
            raise ValueError("Invalid JSON object") from err
        return None
    if strict:
        raise ValueError("JSON value is not an object")
    return None


def _set_if_present(options: HttpOptions, src: Dict[str, Any], key: str) -> None:
    if key in src:
        setattr(options, key, src[key])


def _validate_http_options(options: HttpOptions, *, source: str, strict: bool) -> HttpOptions:
    defaults = HttpOptions()

    options.timeout = _validate_float(
        options.timeout,
        default=defaults.timeout,
        field="timeout",
        source=source,
        min_value=0.001,
        max_value=_MAX_TIMEOUT,
        strict=strict,
    )

    options.rate_limit_per_sec = _validate_optional_float(
        options.rate_limit_per_sec,
        default=defaults.rate_limit_per_sec,
        field="rate_limit_per_sec",
        source=source,
        min_value=0.001,
        max_value=_MAX_RATE_LIMIT,
        strict=strict,
    )

    options.max_concurrency = _validate_int(
        options.max_concurrency,
        default=defaults.max_concurrency,
        field="max_concurrency",
        source=source,
        min_value=1,
        max_value=_MAX_CONCURRENCY,
        strict=strict,
    )

    options.retries = _validate_int(
        options.retries,
        default=defaults.retries,
        field="retries",
        source=source,
        min_value=0,
        max_value=_MAX_RETRIES,
        strict=strict,
    )

    options.backoff_factor = _validate_float(
        options.backoff_factor,
        default=defaults.backoff_factor,
        field="backoff_factor",
        source=source,
        min_value=0.0,
        max_value=_MAX_BACKOFF,
        strict=strict,
    )

    options.verify = _validate_bool(
        options.verify,
        default=defaults.verify,
        field="verify",
        source=source,
        strict=strict,
    )

    return options


def _validate_bool(value: Any, *, default: bool, field: str, source: str, strict: bool) -> bool:
    if isinstance(value, bool):
        return value
    _config_issue(
        f"Invalid {field} value from {source}: {value!r} (expected bool). Using default={default!r}",
        strict=strict,
    )
    return default


def _validate_int(
    value: Any,
    *,
    default: int,
    field: str,
    source: str,
    min_value: int,
    max_value: int,
    strict: bool,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _config_issue(
            f"Invalid {field} value from {source}: {value!r} (expected int). Using default={default!r}",
            strict=strict,
        )
        return default
    if value < min_value or value > max_value:
        _config_issue(
            f"Out-of-range {field} from {source}: {value!r} (expected {min_value}..{max_value}). Using default={default!r}",
            strict=strict,
        )
        return default
    return value


def _validate_float(
    value: Any,
    *,
    default: float,
    field: str,
    source: str,
    min_value: float,
    max_value: float,
    strict: bool,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _config_issue(
            f"Invalid {field} value from {source}: {value!r} (expected number). Using default={default!r}",
            strict=strict,
        )
        return default
    f = float(value)
    if f < min_value or f > max_value:
        _config_issue(
            f"Out-of-range {field} from {source}: {value!r} (expected {min_value}..{max_value}). Using default={default!r}",
            strict=strict,
        )
        return default
    return f


def _validate_optional_float(
    value: Any,
    *,
    default: Optional[float],
    field: str,
    source: str,
    min_value: float,
    max_value: float,
    strict: bool,
) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _config_issue(
            f"Invalid {field} value from {source}: {value!r} (expected number or null). Using default={default!r}",
            strict=strict,
        )
        return default
    f = float(value)
    if f < min_value or f > max_value:
        _config_issue(
            f"Out-of-range {field} from {source}: {value!r} (expected {min_value}..{max_value}). Using default={default!r}",
            strict=strict,
        )
        return default
    return f


def _config_issue(message: str, *, strict: bool) -> None:
    if strict:
        raise ValueError(message)
    logger.warning(message)
