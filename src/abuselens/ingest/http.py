from __future__ import annotations

import time

import requests

from .. import config


def get(url: str, *, headers: dict | None = None, retries: int = 3, timeout: int = 60, **kw):
    """GET with a polite user agent and exponential backoff."""
    h = {"User-Agent": config.USER_AGENT, **(headers or {})}
    last = None
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=h, timeout=timeout, **kw)
            if r.status_code == 429 or r.status_code >= 500:
                raise requests.HTTPError(f"{r.status_code} from {url}")
            r.raise_for_status()
            return r
        except requests.RequestException as e:  # noqa: PERF203
            last = e
            time.sleep(2**attempt)
    raise RuntimeError(f"GET failed after {retries} tries: {url}: {last}")
