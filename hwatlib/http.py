from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Union

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None  # type: ignore


@dataclass
class HttpOptions:
    timeout: float = 5.0
    verify: bool = True
    suppress_insecure_warning: bool = False
    proxies: Optional[Dict[str, str]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Tuple[str, str]] = None

    retries: int = 2
    backoff_factor: float = 0.3
    status_forcelist: Tuple[int, ...] = (429, 500, 502, 503, 504)

    rate_limit_per_sec: Optional[float] = None

    # Concurrency control for async paths (and any future threaded usage)
    max_concurrency: int = 20


class HttpClient:
    """Small wrapper around requests.Session with consistent options."""

    def __init__(self, *, options: Optional[HttpOptions] = None, session: Optional[requests.Session] = None):
        self.options = options or HttpOptions()
        self.session = session or requests.Session()
        self._last_request_at: Optional[float] = None

        # Apply defaults
        if self.options.headers:
            self.session.headers.update(self.options.headers)
        if self.options.cookies:
            self.session.cookies.update(self.options.cookies)
        if self.options.proxies:
            self.session.proxies.update(self.options.proxies)

        if Retry is not None:
            retry = Retry(
                total=self.options.retries,
                connect=self.options.retries,
                read=self.options.retries,
                status=self.options.retries,
                status_forcelist=self.options.status_forcelist,
                backoff_factor=self.options.backoff_factor,
                allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    def _rate_limit(self) -> None:
        rps = self.options.rate_limit_per_sec
        if not rps or rps <= 0:
            return
        min_interval = 1.0 / rps
        now = time.time()
        if self._last_request_at is not None:
            delta = now - self._last_request_at
            if delta < min_interval:
                time.sleep(min_interval - delta)
        self._last_request_at = time.time()

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self._rate_limit()

        timeout = kwargs.pop("timeout", self.options.timeout)
        verify = kwargs.pop("verify", self.options.verify)
        auth = kwargs.pop("auth", self.options.auth)

        if verify is False and self.options.suppress_insecure_warning:
            try:
                import warnings
                import urllib3

                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

        return self.session.request(method, url, timeout=timeout, verify=verify, auth=auth, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)
