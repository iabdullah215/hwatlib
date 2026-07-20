from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .exceptions import PluginError
from .findings import Finding
from .session import HwatSession
from .utils import get_logger

logger = get_logger()

# A check may be a plain function or a coroutine function; both take a session.
CheckFn = Callable[[HwatSession], Any]

# setuptools entry-point group third-party packages use to register checks.
ENTRY_POINT_GROUP = "hwatlib.plugins"


@dataclass
class PluginMeta:
    name: str
    description: str = ""
    severity: str = "info"  # e.g. info/low/medium/high
    category: str = "plugin"
    tags: Sequence[str] = field(default_factory=tuple)
    default_enabled: bool = False
    output_schema: str = "raw"  # "raw" | "findings"


@dataclass
class Plugin:
    meta: PluginMeta
    fn: CheckFn


@dataclass
class PluginResult:
    name: str
    ok: bool
    result: Any = None
    error: Optional[str] = None
    description: str = ""
    severity: str = "info"
    category: str = "plugin"
    tags: Sequence[str] = field(default_factory=tuple)
    output_schema: str = "raw"
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "result": self.result,
            "error": self.error,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "tags": list(self.tags),
            "output_schema": self.output_schema,
            "findings": [f.to_dict() for f in self.findings],
        }


_registry: Dict[str, Plugin] = {}


def register_check(
    name: str,
    fn: CheckFn,
    *,
    description: str = "",
    severity: str = "info",
    category: str = "plugin",
    tags: Optional[Sequence[str]] = None,
    default_enabled: bool = False,
    output_schema: str = "raw",
) -> None:
    if not name or not callable(fn):
        raise PluginError("name and fn are required")
    _registry[name] = Plugin(
        meta=PluginMeta(
            name=name,
            description=description,
            severity=severity,
            category=category,
            tags=tuple(tags or ()),
            default_enabled=bool(default_enabled),
            output_schema=output_schema,
        ),
        fn=fn,
    )


def plugin_check(
    name: Optional[str] = None,
    *,
    description: str = "",
    severity: str = "info",
    category: str = "plugin",
    tags: Optional[Sequence[str]] = None,
    default_enabled: bool = False,
    output_schema: str = "raw",
) -> Callable[[CheckFn], CheckFn]:
    """Decorator attaching plugin metadata to a check function.

    Third-party packages expose the decorated function via a ``hwatlib.plugins``
    entry point; :func:`discover_plugins` reads this metadata on load. Works on
    both regular and ``async def`` checks.
    """

    def decorator(fn: CheckFn) -> CheckFn:
        fn._hwat_meta = {  # type: ignore[attr-defined]
            "name": name,
            "description": description,
            "severity": severity,
            "category": category,
            "tags": tuple(tags or ()),
            "default_enabled": bool(default_enabled),
            "output_schema": output_schema,
        }
        return fn

    return decorator


def _iter_entry_points(group: str):
    """Return entry points for a group across Python 3.9–3.12."""
    eps = metadata.entry_points()
    if hasattr(eps, "select"):  # Python 3.10+
        return list(eps.select(group=group))
    return list(eps.get(group, []))  # Python 3.9


def discover_plugins(*, group: str = ENTRY_POINT_GROUP) -> Dict[str, PluginMeta]:
    """Load and register checks advertised via setuptools entry points.

    Third-party packages register a check without the caller needing
    ``--plugin module:function``::

        [project.entry-points."hwatlib.plugins"]
        my_check = "mypkg.checks:my_check"

    Each entry point is loaded and registered under its metadata name (from the
    :func:`plugin_check` decorator) or the entry-point name. Failures in one
    plugin are logged and skipped. Returns the metadata of newly discovered
    plugins.
    """
    discovered: Dict[str, PluginMeta] = {}
    for ep in _iter_entry_points(group):
        try:
            fn = ep.load()
        except Exception as e:
            logger.warning("Failed to load plugin entry point name=%s error=%s", ep.name, e)
            continue
        if not callable(fn):
            logger.warning("Plugin entry point name=%s is not callable; skipping", ep.name)
            continue

        meta = getattr(fn, "_hwat_meta", None) or {}
        reg_name = meta.get("name") or ep.name
        register_check(
            reg_name,
            fn,
            description=meta.get("description", ""),
            severity=meta.get("severity", "info"),
            category=meta.get("category", "plugin"),
            tags=meta.get("tags"),
            default_enabled=meta.get("default_enabled", False),
            output_schema=meta.get("output_schema", "raw"),
        )
        discovered[reg_name] = _registry[reg_name].meta
    return discovered


def list_checks() -> Dict[str, PluginMeta]:
    return {name: plugin.meta for name, plugin in _registry.items()}


def load_check(spec: str) -> CheckFn:
    """Load a check function from a spec: module:function."""

    if ":" not in spec:
        raise PluginError("Plugin spec must be in the form module:function")
    mod_name, fn_name = spec.split(":", 1)
    module = __import__(mod_name, fromlist=[fn_name])
    fn = getattr(module, fn_name)
    if not callable(fn):
        raise PluginError(f"{spec} is not callable")
    return fn


def _select_plugins(names: Optional[Iterable[str]]) -> List[str]:
    if names is not None:
        return list(names)
    return [name for name, plugin in _registry.items() if bool(plugin.meta.default_enabled)]


def run_checks(session: HwatSession, names: Optional[Iterable[str]] = None) -> Dict[str, PluginResult]:
    selected = _select_plugins(names)
    results: Dict[str, PluginResult] = {}

    for name in selected:
        plugin, fn, err = _resolve_plugin(name)
        if err is not None or fn is None:
            results[name] = PluginResult(name=name, ok=False, error=str(err or "unknown error"))
            continue

        results[name] = _run_one(session, name, fn, plugin)

    return results


def _resolve_plugin(name: str) -> tuple[Optional[Plugin], Optional[CheckFn], Optional[Exception]]:
    plugin = _registry.get(name)
    if plugin is not None:
        return plugin, plugin.fn, None

    try:
        return None, load_check(name), None
    except Exception as e:
        return None, None, e


def _meta_fields(plugin: Optional[Plugin]) -> Dict[str, Any]:
    return {
        "description": plugin.meta.description if plugin else "",
        "severity": plugin.meta.severity if plugin else "info",
        "category": plugin.meta.category if plugin else "plugin",
        "tags": plugin.meta.tags if plugin else (),
        "output_schema": plugin.meta.output_schema if plugin else "raw",
    }


def _success(name: str, out: Any, fields: Dict[str, Any]) -> PluginResult:
    return PluginResult(name=name, ok=True, result=out, findings=_normalize_findings(out), **fields)


def _failure(name: str, error: str, fields: Dict[str, Any]) -> PluginResult:
    return PluginResult(name=name, ok=False, error=error, **fields)


def _run_one(session: HwatSession, name: str, fn: CheckFn, plugin: Optional[Plugin]) -> PluginResult:
    fields = _meta_fields(plugin)
    try:
        # Support async checks from the sync path (no loop is running here).
        if inspect.iscoroutinefunction(fn):
            out = asyncio.run(fn(session))
        else:
            out = fn(session)
        return _success(name, out, fields)
    except Exception as e:
        return _failure(name, str(e), fields)


async def _run_one_async(session: HwatSession, name: str, fn: CheckFn, plugin: Optional[Plugin]) -> PluginResult:
    fields = _meta_fields(plugin)
    try:
        if inspect.iscoroutinefunction(fn):
            out = await fn(session)
        else:
            # Run blocking checks off the event loop so they don't stall it.
            out = await asyncio.to_thread(fn, session)
        return _success(name, out, fields)
    except Exception as e:
        return _failure(name, str(e), fields)


async def run_checks_async(
    session: HwatSession,
    names: Optional[Iterable[str]] = None,
    *,
    max_concurrency: int = 10,
) -> Dict[str, PluginResult]:
    """Async, concurrent counterpart to :func:`run_checks`.

    Async checks are awaited; sync checks run in a worker thread. Concurrency is
    bounded by ``max_concurrency``.
    """
    selected = _select_plugins(names)
    sem = asyncio.Semaphore(max(1, int(max_concurrency or 1)))

    async def run(name: str) -> tuple[str, PluginResult]:
        async with sem:
            plugin, fn, err = _resolve_plugin(name)
            if err is not None or fn is None:
                return name, PluginResult(name=name, ok=False, error=str(err or "unknown error"))
            return name, await _run_one_async(session, name, fn, plugin)

    pairs = await asyncio.gather(*(run(name) for name in selected))
    return dict(pairs)


def _normalize_findings(out: Any) -> List[Finding]:
    if isinstance(out, Finding):
        return [out]
    if isinstance(out, dict) and _looks_like_finding(out):
        return [_dict_to_finding(out)]
    if isinstance(out, list):
        findings: List[Finding] = []
        for item in out:
            if isinstance(item, Finding):
                findings.append(item)
            elif isinstance(item, dict) and _looks_like_finding(item):
                findings.append(_dict_to_finding(item))
        return findings
    return []


def _looks_like_finding(obj: Dict[str, Any]) -> bool:
    return isinstance(obj.get("category"), str) and isinstance(obj.get("title"), str) and isinstance(obj.get("severity"), str)


def _dict_to_finding(obj: Dict[str, Any]) -> Finding:
    evidence = obj.get("evidence") if isinstance(obj.get("evidence"), dict) else None
    recommendation = obj.get("recommendation")
    return Finding(
        category=str(obj.get("category")),
        title=str(obj.get("title")),
        severity=str(obj.get("severity")),
        evidence=evidence,
        recommendation=str(recommendation) if isinstance(recommendation, str) else "",
    )
