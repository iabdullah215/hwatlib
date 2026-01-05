from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def load_report_json(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass
class DiffSummary:
    risk: Dict[str, Any]
    findings: Dict[str, Any]
    web: Dict[str, Any]
    recon: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": self.risk,
            "findings": self.findings,
            "web": self.web,
            "recon": self.recon,
        }


def diff_reports(old: Dict[str, Any], new: Dict[str, Any]) -> DiffSummary:
    old_meta = _get_dict(old, "metadata")
    new_meta = _get_dict(new, "metadata")

    risk = _diff_risk(old_meta.get("risk"), new_meta.get("risk"))

    old_findings = _normalize_findings(old_meta.get("findings"))
    new_findings = _normalize_findings(new_meta.get("findings"))
    findings = _diff_findings(old_findings, new_findings)

    web = _diff_web(_get_dict(old, "web"), _get_dict(new, "web"))
    recon = _diff_recon(_get_dict(old, "recon"), _get_dict(new, "recon"))

    return DiffSummary(risk=risk, findings=findings, web=web, recon=recon)


def to_markdown(diff: DiffSummary) -> str:
    d = diff.to_dict()
    lines: List[str] = ["# hwat report diff"]

    r = d.get("risk") or {}
    lines.append("## Risk")
    lines.append(f"- old: {r.get('old_level')} ({r.get('old_score')})")
    lines.append(f"- new: {r.get('new_level')} ({r.get('new_score')})")
    lines.append(f"- delta: {r.get('delta')}")

    f = d.get("findings") or {}
    lines.append("## Findings")
    lines.append(f"- added: {len(f.get('added', []))}")
    lines.append(f"- removed: {len(f.get('removed', []))}")

    w = d.get("web") or {}
    lines.append("## Web")
    lines.append(f"- tech_hints_added: {w.get('tech_hints_added', [])}")
    lines.append(f"- tech_hints_removed: {w.get('tech_hints_removed', [])}")

    rc = d.get("recon") or {}
    lines.append("## Recon")
    lines.append(f"- ports_added: {rc.get('ports_added', [])}")
    lines.append(f"- ports_removed: {rc.get('ports_removed', [])}")

    return "\n".join(lines) + "\n"


def _get_dict(obj: Any, key: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    v = obj.get(key)
    return v if isinstance(v, dict) else {}


def _diff_risk(old_risk: Any, new_risk: Any) -> Dict[str, Any]:
    old = old_risk if isinstance(old_risk, dict) else {}
    new = new_risk if isinstance(new_risk, dict) else {}

    old_score = int(old.get("score") or 0)
    new_score = int(new.get("score") or 0)

    return {
        "old_score": old_score,
        "new_score": new_score,
        "delta": new_score - old_score,
        "old_level": str(old.get("level") or "info"),
        "new_level": str(new.get("level") or "info"),
    }


def _normalize_findings(obj: Any) -> List[Dict[str, Any]]:
    if not isinstance(obj, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in obj:
        if isinstance(item, dict):
            out.append(item)
    return out


def _finding_key(f: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(f.get("category") or ""),
        str(f.get("title") or ""),
        str(f.get("severity") or ""),
    )


def _diff_findings(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> Dict[str, Any]:
    old_map = {_finding_key(f): f for f in old}
    new_map = {_finding_key(f): f for f in new}

    added_keys = sorted(k for k in new_map.keys() if k not in old_map)
    removed_keys = sorted(k for k in old_map.keys() if k not in new_map)

    return {
        "added": [new_map[k] for k in added_keys],
        "removed": [old_map[k] for k in removed_keys],
    }


def _diff_web(old_web: Dict[str, Any], new_web: Dict[str, Any]) -> Dict[str, Any]:
    old_tech = old_web.get("tech") if isinstance(old_web.get("tech"), dict) else {}
    new_tech = new_web.get("tech") if isinstance(new_web.get("tech"), dict) else {}

    old_hints = set(old_tech.get("hints") or []) if isinstance(old_tech.get("hints"), list) else set()
    new_hints = set(new_tech.get("hints") or []) if isinstance(new_tech.get("hints"), list) else set()

    return {
        "tech_hints_added": sorted(new_hints - old_hints),
        "tech_hints_removed": sorted(old_hints - new_hints),
    }


def _diff_recon(old_recon: Dict[str, Any], new_recon: Dict[str, Any]) -> Dict[str, Any]:
    old_fp = old_recon.get("fingerprint") if isinstance(old_recon.get("fingerprint"), dict) else {}
    new_fp = new_recon.get("fingerprint") if isinstance(new_recon.get("fingerprint"), dict) else {}

    old_ports = {str(k) for k in old_fp.keys()}
    new_ports = {str(k) for k in new_fp.keys()}

    return {
        "ports_added": sorted(new_ports - old_ports),
        "ports_removed": sorted(old_ports - new_ports),
    }
