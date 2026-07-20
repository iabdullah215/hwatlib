from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional

from .http import HttpClient, HttpOptions
from .utils import get_logger, resolve_host


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
        return get_logger(self.logger_name)

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

    # ---------------- Authentication ----------------
    # These build cookie/token flows on top of the shared HttpClient so that a
    # subsequent web.scan(client=session.ensure_http()) runs authenticated.

    def set_headers(self, headers: Mapping[str, str]) -> "HwatSession":
        """Add/override default request headers (e.g. an API key header)."""
        norm = {str(k): str(v) for k, v in headers.items()}
        self.http_options.headers.update(norm)
        if self.http is not None:
            self.http.session.headers.update(norm)
        return self

    def set_cookies(self, cookies: Mapping[str, str]) -> "HwatSession":
        """Seed session cookies (e.g. a captured auth cookie)."""
        norm = {str(k): str(v) for k, v in cookies.items()}
        self.http_options.cookies.update(norm)
        if self.http is not None:
            self.http.session.cookies.update(norm)
        return self

    def set_bearer_token(self, token: str) -> "HwatSession":
        """Send ``Authorization: Bearer <token>`` on every request."""
        return self.set_headers({"Authorization": f"Bearer {token}"})

    def set_basic_auth(self, username: str, password: str) -> "HwatSession":
        """Use HTTP Basic auth on every request."""
        self.http_options.auth = (username, password)
        self.ensure_http()  # client shares http_options, so auth propagates
        return self

    def login_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        method: str = "POST",
        success_check: Optional[Callable[[Any], bool]] = None,
        **kwargs: Any,
    ) -> bool:
        """Perform a form-based login; captured cookies persist on the client.

        Returns True on success. By default success is any non-error status
        (<400); pass ``success_check(response) -> bool`` for custom logic.
        """
        client = self.ensure_http()
        resp = client.request(method, url, data=dict(data), **kwargs)
        if success_check is not None:
            return bool(success_check(resp))
        return resp.status_code < 400

    def current_cookies(self) -> Dict[str, str]:
        """Snapshot of the cookies currently held by the HTTP client."""
        if self.http is None:
            return dict(self.http_options.cookies)
        return {c.name: (c.value or "") for c in self.http.session.cookies}


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
