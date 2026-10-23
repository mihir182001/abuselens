"""Fallback source of safe URLs with realistic paths: real internal links from each sampled
Tranco site's own homepage (one polite GET per site).

Used when the Common Crawl index is unavailable. Pages are only parsed as text (never executed).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FutTimeout
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

import pandas as pd
import requests

from .. import config

SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".pdf", ".zip",
            ".mp4", ".mp3", ".woff", ".woff2", ".xml", ".json")


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)


def _site(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def extract_links(html: str, base_url: str, limit: int) -> list[str]:
    """Same-site http(s) links that have a real path, de-duplicated, in page order."""
    p = _Links()
    try:
        p.feed(html[:500_000])
    except Exception:  # malformed HTML must never break the pipeline
        pass
    base_host = _site(urlsplit(base_url).hostname or "")
    out, seen = [], set()
    for h in p.hrefs:
        u, _ = urldefrag(urljoin(base_url, h.strip()))
        sp = urlsplit(u)
        if sp.scheme not in ("http", "https") or _site(sp.hostname or "") != base_host:
            continue
        if sp.path in ("", "/") and not sp.query:
            continue
        if sp.path.lower().endswith(SKIP_EXT) or u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out


def _one(rank, dom: str, per_domain: int) -> list[dict]:
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{dom}/", headers={"User-Agent": config.USER_AGENT},
                             timeout=8, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code == 200 and "html" in r.headers.get("content-type", "").lower():
            return [{"url": u, "domain": dom, "tranco_rank": int(rank), "source": "sitelinks"}
                    for u in extract_links(r.text, r.url, per_domain)]
        return []
    return []


def fetch_for_domains(domains: pd.DataFrame, per_domain: int | None = None,
                      budget_s: float | None = None, workers: int = 16) -> pd.DataFrame:
    per_domain = per_domain or config.CC_URLS_PER_DOMAIN
    budget_s = budget_s or config.CC_TIME_BUDGET_S
    start, rows, done = time.monotonic(), [], 0
    pairs = list(zip(domains["rank"], domains["domain"], strict=True))
    ex = ThreadPoolExecutor(max_workers=workers)
    futs = [ex.submit(_one, rk, dm, per_domain) for rk, dm in pairs]
    try:
        for f in as_completed(futs, timeout=budget_s):
            rows.extend(f.result())
            done += 1
            if done % 50 == 0:
                print(f"  sitelinks: {done}/{len(pairs)} sites, {len(rows)} urls "
                      f"({time.monotonic() - start:.0f}s)", flush=True)
    except FutTimeout:
        print(f"  sitelinks: time budget {budget_s}s reached; keeping {len(rows)} urls", flush=True)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return pd.DataFrame(rows, columns=["url", "domain", "tranco_rank", "source"])
