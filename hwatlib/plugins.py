from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .session import HwatSession
from .findings import Finding


CheckFn = Callable[[HwatSession], Any]


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
        raise ValueError("name and fn are required")
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


def list_checks() -> Dict[str, PluginMeta]:
    return {name: plugin.meta for name, plugin in _registry.items()}


def load_check(spec: str) -> CheckFn:
    """Load a check function from a spec: module:function."""

    if ":" not in spec:
        raise ValueError("Plugin spec must be in the form module:function")
    mod_name, fn_name = spec.split(":", 1)
    module = __import__(mod_name, fromlist=[fn_name])
    fn = getattr(module, fn_name)
    if not callable(fn):
        raise ValueError(f"{spec} is not callable")
    return fn


def run_checks(session: HwatSession, names: Optional[Iterable[str]] = None) -> Dict[str, PluginResult]:
    if names is not None:
        selected = list(names)
    else:
        selected = [name for name, plugin in _registry.items() if bool(plugin.meta.default_enabled)]
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


def _run_one(session: HwatSession, name: str, fn: CheckFn, plugin: Optional[Plugin]) -> PluginResult:
    desc = plugin.meta.description if plugin else ""
    sev = plugin.meta.severity if plugin else "info"
    cat = plugin.meta.category if plugin else "plugin"
    tags = plugin.meta.tags if plugin else ()
    schema = plugin.meta.output_schema if plugin else "raw"
    try:
        out = fn(session)
        findings = _normalize_findings(out)
        return PluginResult(
            name=name,
            ok=True,
            result=out,
            description=desc,
            severity=sev,
            category=cat,
            tags=tags,
            output_schema=schema,
            findings=findings,
        )
    except Exception as e:
        return PluginResult(
            name=name,
            ok=False,
            error=str(e),
            description=desc,
            severity=sev,
            category=cat,
            tags=tags,
            output_schema=schema,
        )


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
