from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests

from .http import HttpClient, HttpOptions
from .utils import resolve_host, setup_logger


@dataclass
class HwatSession:
    """Shared context for recon/web/post-exploitation workflows."""

    target: str
    ip: Optional[str] = None
    base_url: Optional[str] = None
    http: Optional[HttpClient] = None
    http_options: HttpOptions = field(default_factory=HttpOptions)
    logger_name: str = "hwatlib"
    results: Dict[str, Any] = field(default_factory=dict)

    @property
    def logger(self):
        return setup_logger(self.logger_name)

    def ensure_ip(self) -> Optional[str]:
        if self.ip:
            return self.ip
        self.ip = resolve_host(self.target)
        return self.ip

    def ensure_http(self) -> HttpClient:
        if self.http is None:
            self.http = HttpClient(options=self.http_options)
        return self.http

    def ensure_base_url(self) -> Optional[str]:
        if self.base_url:
            return self.base_url
        # Heuristic: if target looks like URL keep it; else default to http://
        if self.target.startswith("http://") or self.target.startswith("https://"):
            self.base_url = self.target
        else:
            self.base_url = "http://" + self.target
        return self.base_url


def new_session(
    target: str,
    *,
    base_url: Optional[str] = None,
    http_options: Optional[HttpOptions] = None,
) -> HwatSession:
    session = HwatSession(target=target)
    if base_url is not None:
        session.base_url = base_url
    if http_options is not None:
        session.http_options = http_options
    session.ensure_http()
    return session
