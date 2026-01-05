from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .models import SecretsSummary


DEFAULT_EXTS = {".env", ".ini", ".conf", ".yaml", ".yml", ".json", ".txt"}
DEFAULT_NAMES = {".env", "config", "settings", "secrets", "credentials"}


SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], int]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 9),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 8),
    ("generic_api_key", re.compile(r"(?i)\b(api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([a-z0-9_-]{12,})"), 6),
    ("password_assignment", re.compile(r"(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*['\"]?([^'\"\s]{6,})"), 7),
]


@dataclass
class SecretFinding:
    path: str
    line: int
    kind: str
    risk: int
    preview: str


def _redact(value: str) -> str:
    if value is None:
        return ""
    v = str(value)
    if len(v) <= 6:
        return "***"
    return v[:3] + "..." + v[-2:]


def _candidate_file(path: str, *, exts=DEFAULT_EXTS) -> bool:
    base = os.path.basename(path).lower()
    _root, ext = os.path.splitext(base)
    if base in DEFAULT_NAMES:
        return True
    if ext in exts:
        return True
    return False


def _iter_dir_files(dir_path: str) -> Iterable[str]:
    for root, _dirs, files in os.walk(dir_path):
        for name in files:
            yield os.path.join(root, name)


def _iter_candidate_files(paths: Iterable[str], *, max_files: int) -> Iterable[str]:
    scanned = 0
    for p in paths:
        if scanned >= max_files:
            return

        file_iter = _iter_dir_files(p) if os.path.isdir(p) else [p]
        for file_path in file_iter:
            if scanned >= max_files:
                return
            if not (os.path.isfile(file_path) and _candidate_file(file_path)):
                continue
            yield file_path
            scanned += 1


def scan_paths(
    paths: Iterable[str],
    *,
    max_files: int = 500,
    max_file_size_bytes: int = 2_000_000,
) -> List[SecretFinding]:
    findings: List[SecretFinding] = []

    for file_path in _iter_candidate_files(paths, max_files=max_files):
        _scan_file(file_path, findings, max_file_size_bytes=max_file_size_bytes)

    return findings


def _scan_file(path: str, findings: List[SecretFinding], *, max_file_size_bytes: int) -> None:
    try:
        if os.path.getsize(path) > max_file_size_bytes:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                for kind, pat, risk in SECRET_PATTERNS:
                    m = pat.search(line)
                    if not m:
                        continue

                    # Pick last capturing group as the likely secret value.
                    value = m.group(m.lastindex) if m.lastindex else m.group(0)
                    findings.append(
                        SecretFinding(
                            path=path,
                            line=idx,
                            kind=kind,
                            risk=risk,
                            preview=_redact(value),
                        )
                    )
    except Exception:
        return


def summarize(findings: List[SecretFinding]) -> SecretsSummary:
    by_kind: Dict[str, int] = {}
    max_risk = 0
    for f in findings:
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        max_risk = max(max_risk, f.risk)

    return SecretsSummary(
        count=len(findings),
        by_kind=by_kind,
        max_risk=max_risk,
        findings=[
            {"path": f.path, "line": f.line, "kind": f.kind, "risk": f.risk, "preview": f.preview}
            for f in findings[:200]
        ],
    )


def summarize_dict(findings: List[SecretFinding]) -> Dict[str, object]:
    return summarize(findings).to_dict()
