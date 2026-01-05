from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .report import HwatReport
from .models import to_dict as _to_dict


Severity = str  # "info" | "low" | "medium" | "high" | "critical"


@dataclass
class Finding:
    category: str
    title: str
    severity: Severity
    evidence: Optional[Dict[str, Any]] = None
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskSummary:
    score: int
    level: Severity
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "findings": [f.to_dict() for f in self.findings],
        }


def score_report(report: HwatReport) -> RiskSummary:
    """Best-effort scoring across recon/web/secrets/privesc.

    Heuristics are intentionally conservative and read-only.
    """

    score = 0
    findings: List[Finding] = []

    s_score, s_findings = _score_secrets(_to_dict(report.secrets))
    score += s_score
    findings.extend(s_findings)

    p_score, p_findings = _score_privesc(_to_dict(report.privesc))
    score += p_score
    findings.extend(p_findings)

    r_score, r_findings = _score_recon_tls(_to_dict(report.recon))
    score += r_score
    findings.extend(r_findings)

    w_findings = _score_web_tech(_to_dict(report.web))
    findings.extend(w_findings)

    pl_score, pl_findings = _score_plugins(_to_dict(report.plugins))
    score += pl_score
    findings.extend(pl_findings)

    score = max(0, min(100, score))
    return RiskSummary(score=score, level=_score_level(score), findings=findings)


def _score_plugins(plugins_obj: Any) -> tuple[int, List[Finding]]:
    plugins = plugins_obj if isinstance(plugins_obj, dict) else {}

    extracted: List[Finding] = []
    for plugin_name, payload in plugins.items():
        if not isinstance(payload, dict):
            continue
        raw_findings = payload.get("findings")
        if not isinstance(raw_findings, list):
            continue

        for raw in raw_findings:
            if not isinstance(raw, dict):
                continue
            category = raw.get("category")
            title = raw.get("title")
            severity = raw.get("severity")
            if not (isinstance(category, str) and isinstance(title, str) and isinstance(severity, str)):
                continue
            evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else None
            if evidence is None:
                evidence = {}
            # Preserve evidence while also noting the plugin name.
            evidence = dict(evidence)
            evidence.setdefault("plugin", str(plugin_name))

            recommendation = raw.get("recommendation")
            extracted.append(
                Finding(
                    category=category,
                    title=title,
                    severity=severity,
                    evidence=evidence,
                    recommendation=recommendation if isinstance(recommendation, str) else "",
                )
            )

    extracted = _dedupe_finding_objs(extracted)

    points = 0
    for f in extracted:
        points += _plugin_severity_points(f.severity)

    # Conservative cap so plugins can't dominate the overall score.
    points = min(points, 30)
    return points, extracted


def _plugin_severity_points(severity: Severity) -> int:
    sev = str(severity).strip().lower()
    if sev == "critical":
        return 30
    if sev == "high":
        return 20
    if sev == "medium":
        return 10
    if sev == "low":
        return 5
    return 0


def _dedupe_finding_objs(findings: List[Finding]) -> List[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: List[Finding] = []
    for f in findings:
        key = (str(f.category or ""), str(f.title or ""), str(f.severity or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _score_level(score: int) -> Severity:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _score_secrets(secrets_obj: Any) -> tuple[int, List[Finding]]:
    secrets = secrets_obj if isinstance(secrets_obj, dict) else {}
    max_risk = int(secrets.get("max_risk") or 0)
    if max_risk >= 9:
        return (
            35,
            [
                Finding(
                    category="secrets",
                    title="High-confidence secret patterns found",
                    severity="high",
                    evidence={"max_risk": max_risk, "count": secrets.get("count")},
                    recommendation="Rotate exposed credentials and remove secrets from disk/history.",
                )
            ],
        )
    if max_risk >= 7:
        return (
            20,
            [
                Finding(
                    category="secrets",
                    title="Potential secrets found",
                    severity="medium",
                    evidence={"max_risk": max_risk, "count": secrets.get("count")},
                    recommendation="Review findings and rotate/lock down any real secrets.",
                )
            ],
        )
    return 0, []


def _score_privesc(privesc_obj: Any) -> tuple[int, List[Finding]]:
    pr = privesc_obj if isinstance(privesc_obj, dict) else {}
    score_dict = pr.get("score") if isinstance(pr, dict) else None
    if not isinstance(score_dict, dict):
        return 0, []

    pr_score = int(score_dict.get("score") or 0)
    pr_level: Severity = str(score_dict.get("level") or "info")
    reasons = score_dict.get("reasons")

    if pr_score >= 60:
        return (
            25,
            [
                Finding(
                    category="privesc",
                    title="High privesc opportunity indicators",
                    severity="high",
                    evidence={"score": pr_score, "level": pr_level, "reasons": reasons},
                    recommendation="Validate sudo/SUID vectors and harden system permissions.",
                )
            ],
        )
    if pr_score >= 30:
        return (
            15,
            [
                Finding(
                    category="privesc",
                    title="Some privesc opportunity indicators",
                    severity="medium",
                    evidence={"score": pr_score, "level": pr_level, "reasons": reasons},
                    recommendation="Investigate listed privesc hints and harden accordingly.",
                )
            ],
        )

    return 0, []


def _score_recon_tls(recon_obj: Any) -> tuple[int, List[Finding]]:
    recon = recon_obj if isinstance(recon_obj, dict) else {}
    fp = recon.get("fingerprint") if isinstance(recon, dict) else None
    if not isinstance(fp, dict):
        return 0, []

    failures: List[str] = []
    for port, info in fp.items():
        if not isinstance(info, dict):
            continue
        notes = info.get("notes") or []
        if "tls_cert_verification_failed" in notes:
            failures.append(str(port))

    if not failures:
        return 0, []

    return (
        10,
        [
            Finding(
                category="recon",
                title="TLS certificate verification failures observed",
                severity="low",
                evidence={"ports": failures},
                recommendation="Verify certificates/hostnames; misconfig may enable MITM in some contexts.",
            )
        ],
    )


def _score_web_tech(web_obj: Any) -> List[Finding]:
    web = web_obj if isinstance(web_obj, dict) else {}
    tech = web.get("tech") if isinstance(web, dict) else None
    if not (isinstance(tech, dict) and tech.get("ok") is True):
        return []

    hints = tech.get("hints")
    if not (isinstance(hints, list) and hints):
        return []

    return [
        Finding(
            category="web",
            title="Technology hints detected",
            severity="info",
            evidence={"hints": hints, "server": tech.get("server"), "x_powered_by": tech.get("x_powered_by")},
            recommendation="Use these hints to guide further targeted testing.",
        )
    ]
