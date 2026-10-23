"""Common Crawl URL index: real paths for sampled legitimate domains.

Bare domains make trivially easy negatives. Pulling real crawled URLs for each sampled
Tranco domain gives the model negatives with realistic paths and query strings.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as TimeoutError  # noqa: PLC0414

import pandas as pd

from .. import config
from . import http


def latest_index_api() -> str:
    return http.get(config.COMMONCRAWL_COLLINFO).json()[0]["cdx-api"]


def parse_cdx(text: str, limit: int) -> list[str]:
    urls = []
    for ln in text.splitlines():
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if str(rec.get("status")) == "200" and rec.get("url", "").startswith("http"):
            urls.append(rec["url"])
        if len(urls) >= limit:
            break
    return urls


def available() -> bool:
    """One quick probe so a down index costs seconds, not the whole time budget."""
    try:
        api = latest_index_api()
        r = http.get(api, params={"url": "example.com/*", "output": "json", "limit": 1},
                     retries=1, timeout=15)
        return r.status_code == 200
    except Exception:
        return False


def _one(api: str, rank, dom: str, per_domain: int) -> list[dict]:
    try:
        r = http.get(api, params={"url": f"{dom}/*", "output": "json", "limit": per_domain * 4,
                                  "filter": "=status:200"}, retries=1, timeout=15)
    except RuntimeError:
        return []
    return [{"url": u, "domain": dom, "tranco_rank": int(rank), "source": "commoncrawl"}
            for u in parse_cdx(r.text, per_domain)]


def fetch_for_domains(domains: pd.DataFrame, per_domain: int | None = None,
                      budget_s: float | None = None, workers: int = 8) -> pd.DataFrame:
    """Parallel, time-bounded lookups. Returns whatever was collected when the budget runs out."""
    per_domain = per_domain or config.CC_URLS_PER_DOMAIN
    budget_s = budget_s or config.CC_TIME_BUDGET_S
    api = latest_index_api()
    start, rows, done = time.monotonic(), [], 0
    pairs = list(zip(domains["rank"], domains["domain"], strict=True))
    ex = ThreadPoolExecutor(max_workers=workers)
    futs = [ex.submit(_one, api, rk, dm, per_domain) for rk, dm in pairs]
    try:
        for f in as_completed(futs, timeout=budget_s):
            rows.extend(f.result())
            done += 1
            if done % 25 == 0:
                print(f"  commoncrawl: {done}/{len(pairs)} domains, {len(rows)} urls "
                      f"({time.monotonic() - start:.0f}s)", flush=True)
    except TimeoutError:
        print(f"  commoncrawl: time budget {budget_s}s reached; keeping {len(rows)} urls "
              f"from {done}/{len(pairs)} domains", flush=True)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return pd.DataFrame(rows, columns=["url", "domain", "tranco_rank", "source"])
