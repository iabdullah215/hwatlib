from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import to_dict as _to_dict

# Severity ordering (most to least severe) for grouping/rendering.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLORS = {
    "critical": "#7b1fa2",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#f9a825",
    "info": "#1565c0",
}


@dataclass
class HwatReport:
    metadata: Dict[str, Any] = field(default_factory=dict)
    recon: Any = field(default_factory=dict)
    dns: Any = field(default_factory=dict)
    web: Any = field(default_factory=dict)
    privesc: Any = field(default_factory=dict)
    secrets: Any = field(default_factory=dict)
    plugins: Any = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": _to_dict(self.metadata),
            "recon": _to_dict(self.recon),
            "dns": _to_dict(self.dns),
            "web": _to_dict(self.web),
            "privesc": _to_dict(self.privesc),
            "secrets": _to_dict(self.secrets),
            "plugins": _to_dict(self.plugins),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        def section(title: str, obj: Any) -> str:
            obj_dict = _to_dict(obj)
            if not isinstance(obj_dict, dict):
                obj_dict = {"value": obj_dict}
            lines = [f"## {title}"]
            if not obj_dict:
                lines.append("- (none)")
                return "\n".join(lines)
            for k, v in obj_dict.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"- **{k}**:")
                    lines.append("```json")
                    lines.append(json.dumps(v, indent=2, default=str))
                    lines.append("```")
                else:
                    lines.append(f"- **{k}**: {v}")
            return "\n".join(lines)

        parts = ["# hwatlib report"]
        parts.append(section("Metadata", self.metadata))
        parts.append(section("Recon", self.recon))
        parts.append(section("DNS", self.dns))
        parts.append(section("Web", self.web))
        parts.append(section("Privesc", self.privesc))
        parts.append(section("Secrets", self.secrets))
        parts.append(section("Plugins", self.plugins))
        return "\n\n".join(parts) + "\n"

    def to_html(self) -> str:
        """Render a self-contained HTML report with findings grouped by severity.

        Includes a risk summary, findings grouped critical→info, and (when a
        ``--compare`` diff has been attached to ``metadata["diff"]``) a
        "Changes since previous scan" section.
        """
        meta = _to_dict(self.metadata) if isinstance(self.metadata, dict) else {}
        findings = meta.get("findings") if isinstance(meta.get("findings"), list) else []
        risk = meta.get("risk") if isinstance(meta.get("risk"), dict) else {}
        return _render_html(meta=meta, risk=risk, findings=findings, diff=meta.get("diff"))


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _group_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "info").lower()
        groups.setdefault(sev, []).append(f)
    return groups


def _render_finding(f: Dict[str, Any]) -> str:
    title = _esc(f.get("title") or "Finding")
    category = _esc(f.get("category") or "")
    recommendation = f.get("recommendation") or ""
    evidence = f.get("evidence")
    rows = [f'<div class="f-title">{title}</div>',
            f'<div class="f-cat">{category}</div>']
    if recommendation:
        rows.append(f'<div class="f-rec"><strong>Recommendation:</strong> {_esc(recommendation)}</div>')
    if evidence:
        rows.append(f'<pre class="f-ev">{_esc(json.dumps(evidence, indent=2, default=str))}</pre>')
    return '<div class="finding">' + "".join(rows) + "</div>"


def _render_diff_html(diff: Dict[str, Any]) -> str:
    risk = diff.get("risk") or {}
    fnd = diff.get("findings") or {}
    web = diff.get("web") or {}
    recon = diff.get("recon") or {}
    added = fnd.get("added") or []
    removed = fnd.get("removed") or []

    def _lst(items: List[Any]) -> str:
        items = [i for i in items if i not in (None, "")]
        return ", ".join(_esc(i) for i in items) if items else "<em>none</em>"

    return (
        '<section class="diff"><h2>Changes since previous scan</h2>'
        f'<p>Risk: {_esc(risk.get("old_level"))} ({_esc(risk.get("old_score"))}) '
        f'&rarr; {_esc(risk.get("new_level"))} ({_esc(risk.get("new_score"))}), '
        f'delta {_esc(risk.get("delta"))}</p>'
        f"<p><strong>Findings added:</strong> {len(added)} &middot; "
        f"<strong>removed:</strong> {len(removed)}</p>"
        f'<p><strong>Tech added:</strong> {_lst(web.get("tech_hints_added") or [])} &middot; '
        f'<strong>removed:</strong> {_lst(web.get("tech_hints_removed") or [])}</p>'
        f'<p><strong>Ports added:</strong> {_lst(recon.get("ports_added") or [])} &middot; '
        f'<strong>removed:</strong> {_lst(recon.get("ports_removed") or [])}</p>'
        "</section>"
    )


def _render_html(*, meta: Dict[str, Any], risk: Dict[str, Any], findings: List[Dict[str, Any]], diff: Any) -> str:
    target = _esc(meta.get("target") or "(unspecified target)")
    generated = _esc(meta.get("generated_at") or "")
    run_id = _esc(meta.get("run_id") or "")
    level = str(risk.get("level") or "info").lower()
    score = risk.get("score")
    badge_color = _SEVERITY_COLORS.get(level, "#607d8b")

    groups = _group_by_severity(findings)
    body_sections: List[str] = []
    for sev in _SEVERITY_ORDER:
        items = groups.get(sev) or []
        if not items:
            continue
        color = _SEVERITY_COLORS[sev]
        cards = "".join(_render_finding(f) for f in items)
        body_sections.append(
            f'<section class="sev"><h2 style="border-color:{color}">'
            f'<span class="dot" style="background:{color}"></span>'
            f"{sev.title()} <span class=\"count\">({len(items)})</span></h2>{cards}</section>"
        )

    findings_html = "".join(body_sections) or "<p><em>No findings.</em></p>"
    diff_html = _render_diff_html(diff) if isinstance(diff, dict) else ""
    score_txt = "" if score is None else f" &middot; score {_esc(score)}"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>hwatlib report — {target}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f5f6f8;color:#1a1a1a}}
.wrap{{max-width:900px;margin:0 auto;padding:24px}}
header{{background:#fff;border-radius:8px;padding:20px 24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
h1{{margin:0 0 4px;font-size:22px}}
.meta{{color:#666;font-size:13px}}
.badge{{display:inline-block;color:#fff;padding:4px 12px;border-radius:12px;font-weight:600;font-size:13px;background:{badge_color}}}
.sev h2,.diff h2{{font-size:16px;border-left:4px solid #ccc;padding-left:10px;margin:24px 0 12px}}
.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}}
.count{{color:#888;font-weight:400}}
.finding{{background:#fff;border-radius:6px;padding:12px 16px;margin:8px 0;box-shadow:0 1px 2px rgba(0,0,0,.08)}}
.f-title{{font-weight:600}}
.f-cat{{color:#888;font-size:12px;text-transform:uppercase;letter-spacing:.03em}}
.f-rec{{margin-top:6px;font-size:14px}}
.f-ev{{background:#f0f1f3;border-radius:4px;padding:8px;margin-top:8px;font-size:12px;overflow:auto}}
.diff{{background:#fff;border-radius:8px;padding:16px 24px;margin-top:24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
footer{{color:#999;font-size:12px;text-align:center;padding:24px}}
</style></head>
<body><div class="wrap">
<header>
<h1>hwatlib report</h1>
<div class="meta">Target: <strong>{target}</strong> &middot; {generated}{f' &middot; run {run_id}' if run_id else ''}</div>
<p><span class="badge">Risk: {_esc(level).upper()}{score_txt}</span></p>
</header>
{diff_html}
<h2 style="font-size:18px;margin-top:28px">Findings</h2>
{findings_html}
<footer>Generated by hwatlib — authorized use only.</footer>
</div></body></html>
"""


def new_report(*, target: Optional[str] = None) -> HwatReport:
    from .logging_ext import get_run_id

    meta = {"generated_at": datetime.now(timezone.utc).isoformat()}
    if target:
        meta["target"] = target
    # Stamp the current run id (if any) so a report can be correlated with the
    # log lines emitted during the same invocation.
    run_id = get_run_id()
    if run_id:
        meta["run_id"] = run_id
    return HwatReport(metadata=meta)
