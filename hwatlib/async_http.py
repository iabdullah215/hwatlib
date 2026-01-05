from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .http import HttpOptions


@dataclass
class AsyncResponse:
    status: int
    headers: Dict[str, str]
    text: str
    url: str


class AsyncHttpClient:
    """Optional aiohttp-based HTTP client.

    This module is only usable when aiohttp is installed:
      pip install hwatlib[async]

    Safety defaults:
    - TLS verification remains controlled by HttpOptions.verify.
    """

    def __init__(self, *, options: Optional[HttpOptions] = None):
        self.options = options or HttpOptions()
        self._last_request_at: Optional[float] = None
        self._sem = asyncio.Semaphore(max(1, int(self.options.max_concurrency or 1)))

        try:
            import aiohttp  # type: ignore

            self._aiohttp = aiohttp
        except Exception as e:  # pragma: no cover
            raise RuntimeError("aiohttp is required (install extras: pip install hwatlib[async])") from e

        self._session: Optional[Any] = None

    async def __aenter__(self) -> "AsyncHttpClient":
        self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    def _ensure_session(self) -> None:
        if self._session is not None:
            return

        timeout = self._aiohttp.ClientTimeout(total=self.options.timeout)
        connector = self._aiohttp.TCPConnector(ssl=self.options.verify)

        self._session = self._aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=self.options.headers or None,
            cookies=self.options.cookies or None,
        )

    async def _rate_limit(self) -> None:
        rps = self.options.rate_limit_per_sec
        if not rps or rps <= 0:
            return
        min_interval = 1.0 / rps
        now = time.time()
        if self._last_request_at is not None:
            delta = now - self._last_request_at
            if delta < min_interval:
                await asyncio.sleep(min_interval - delta)
        self._last_request_at = time.time()

    async def request(self, method: str, url: str, **kwargs) -> AsyncResponse:
        self._ensure_session()
        await self._rate_limit()

        proxy = self._resolve_proxy(url, kwargs)
        auth = self._resolve_auth(kwargs)

        retries = max(0, int(self.options.retries or 0))
        backoff = float(self.options.backoff_factor or 0.0)
        status_forcelist = set(self.options.status_forcelist or ())

        return await self._request_with_retries(
            method,
            url,
            kwargs,
            proxy=proxy,
            auth=auth,
            retries=retries,
            backoff=backoff,
            status_forcelist=status_forcelist,
        )

    def _resolve_proxy(self, url: str, kwargs: Dict[str, Any]) -> Optional[str]:
        # Proxies: aiohttp expects a single proxy URL per request.
        proxy = kwargs.pop("proxy", None)
        if proxy is not None:
            return proxy
        if not self.options.proxies:
            return None
        scheme = url.split(":", 1)[0]
        return self.options.proxies.get(scheme)

    def _resolve_auth(self, kwargs: Dict[str, Any]) -> Any:
        auth = kwargs.pop("auth", None)
        if auth is not None:
            return auth
        if not self.options.auth:
            return None
        return self._aiohttp.BasicAuth(self.options.auth[0], self.options.auth[1])

    async def _request_with_retries(
        self,
        method: str,
        url: str,
        kwargs: Dict[str, Any],
        *,
        proxy: Optional[str],
        auth: Any,
        retries: int,
        backoff: float,
        status_forcelist: set[int],
    ) -> AsyncResponse:
        last_exc: Optional[BaseException] = None
        for attempt in range(retries + 1):
            try:
                out = await self._request_once(method, url, kwargs, proxy=proxy, auth=auth)
                if out.status in status_forcelist and attempt < retries:
                    await _backoff_sleep(attempt, backoff)
                    continue
                return out
            except Exception as e:
                last_exc = e
                if attempt >= retries:
                    break
                await _backoff_sleep(attempt, backoff)

        raise RuntimeError(f"Async request failed after retries: {last_exc}")

    async def _request_once(
        self,
        method: str,
        url: str,
        kwargs: Dict[str, Any],
        *,
        proxy: Optional[str],
        auth: Any,
    ) -> AsyncResponse:
        assert self._session is not None
        async with self._sem:
            async with self._session.request(method, url, proxy=proxy, auth=auth, **kwargs) as resp:
                text = await resp.text(errors="ignore")
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return AsyncResponse(status=resp.status, headers=headers, text=text, url=str(resp.url))

    async def get(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("HEAD", url, **kwargs)


async def _backoff_sleep(attempt: int, backoff_factor: float) -> None:
    if backoff_factor <= 0:
        await asyncio.sleep(0)
        return
    delay = backoff_factor * (2 ** attempt)
    # keep it bounded; we don't expose a separate max delay yet
    await asyncio.sleep(min(delay, 10.0))
