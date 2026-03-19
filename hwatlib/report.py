from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .models import to_dict as _to_dict


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


def new_report(*, target: Optional[str] = None) -> HwatReport:
    meta = {"generated_at": datetime.now(timezone.utc).isoformat()}
    if target:
        meta["target"] = target
    return HwatReport(metadata=meta)
