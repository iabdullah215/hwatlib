"""Machine-readable exports for hwatlib findings.

Two interchange formats are supported so hwatlib output composes into other
pipelines:

- **JSONL** — one finding per line, ideal for streaming into log processors,
  jq, or a data warehouse.
- **SARIF 2.1.0** — the Static Analysis Results Interchange Format, consumable
  by GitHub code scanning and many security dashboards.

Both accept either :class:`hwatlib.findings.Finding` objects or the plain dicts
that live in ``report.metadata["findings"]``, so callers can export from a
scored report or from findings they assembled themselves.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from .findings import Finding
from .report import HwatReport


def _tool_version() -> str:
    # Resolved lazily to avoid importing __version__ at module load time (it is
    # defined at the end of hwatlib/__init__.py, after this module is imported).
    from . import __version__

    return __version__

FindingLike = Union[Finding, Dict[str, Any]]

_INFORMATION_URI = "https://github.com/iabdullah215/hwatlib"

# SARIF result "level" per finding severity.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# GitHub code-scanning "security-severity" (0-10) per finding severity.
_SEVERITY_TO_SECURITY = {
    "critical": "9.3",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}
# Evidence keys that can act as a locatable pointer for a SARIF result.
_LOCATION_KEYS = ("url", "target", "host", "endpoint", "path")


def _normalize(finding: FindingLike) -> Dict[str, Any]:
    """Coerce a Finding or dict into a plain finding dict."""
    if isinstance(finding, Finding):
        return finding.to_dict()
    if isinstance(finding, dict):
        return dict(finding)
    raise TypeError(f"Unsupported finding type: {type(finding).__name__}")


def _iter_findings(source: Union[HwatReport, Iterable[FindingLike]]) -> List[Dict[str, Any]]:
    """Extract findings from a report's metadata, or normalize an iterable."""
    if isinstance(source, HwatReport):
        raw = source.metadata.get("findings")
        items = raw if isinstance(raw, list) else []
        return [_normalize(f) for f in items if isinstance(f, (Finding, dict))]
    return [_normalize(f) for f in source]


def _slug(text: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in (text or "").strip().lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-") or "finding"


def _rule_id(category: str, title: str) -> str:
    return f"{_slug(category) or 'general'}/{_slug(title)}"


def _fingerprint(finding: Dict[str, Any]) -> str:
    payload = json.dumps(
        {
            "category": finding.get("category"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "evidence": finding.get("evidence"),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _location_uri(evidence: Any) -> Optional[str]:
    if not isinstance(evidence, dict):
        return None
    for key in _LOCATION_KEYS:
        val = evidence.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, list) and val and isinstance(val[0], str):
            return val[0]
    return None


# ---------------------------------------------------------------------------
# JSONL
# ---------------------------------------------------------------------------

def to_jsonl(source: Union[HwatReport, Iterable[FindingLike]]) -> str:
    """Render findings as JSON Lines (one compact JSON object per line)."""
    lines = [
        json.dumps(f, sort_keys=True, default=str) for f in _iter_findings(source)
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def write_jsonl(source: Union[HwatReport, Iterable[FindingLike]], path: str) -> None:
    Path(path).write_text(to_jsonl(source), encoding="utf-8")


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

def to_sarif(
    source: Union[HwatReport, Iterable[FindingLike]],
    *,
    run_id: Optional[str] = None,
    tool_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Render findings as a SARIF 2.1.0 log (a JSON-serializable dict)."""
    if tool_version is None:
        tool_version = _tool_version()
    findings = _iter_findings(source)
    if run_id is None and isinstance(source, HwatReport):
        rid = source.metadata.get("run_id")
        run_id = rid if isinstance(rid, str) else None

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        category = str(f.get("category") or "general")
        title = str(f.get("title") or "Finding")
        severity = str(f.get("severity") or "info").lower()
        recommendation = str(f.get("recommendation") or "")
        evidence = f.get("evidence")
        rule_id = _rule_id(category, title)

        if rule_id not in rules:
            rule: Dict[str, Any] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(severity, "note")},
                "properties": {
                    "category": category,
                    "security-severity": _SEVERITY_TO_SECURITY.get(severity, "0.0"),
                    "tags": ["security", category],
                },
            }
            if recommendation:
                rule["help"] = {"text": recommendation}
            rules[rule_id] = rule

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(severity, "note"),
            "message": {"text": recommendation or title},
            "partialFingerprints": {"hwatlibFindingHash/v1": _fingerprint(f)},
            "properties": {
                "severity": severity,
                "category": category,
                "security-severity": _SEVERITY_TO_SECURITY.get(severity, "0.0"),
            },
        }
        if evidence is not None:
            result["properties"]["evidence"] = evidence

        uri = _location_uri(evidence)
        if uri is not None:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            ]

        results.append(result)

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "hwatlib",
                "version": tool_version,
                "informationUri": _INFORMATION_URI,
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    if run_id:
        run["automationDetails"] = {"id": run_id}

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif(
    source: Union[HwatReport, Iterable[FindingLike]],
    path: str,
    *,
    run_id: Optional[str] = None,
) -> None:
    log = to_sarif(source, run_id=run_id)
    Path(path).write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")


__all__ = ["to_jsonl", "write_jsonl", "to_sarif", "write_sarif"]
