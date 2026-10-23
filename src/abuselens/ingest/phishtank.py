"""PhishTank verified phishing URLs, with the impersonated brand in the `target` column."""
from __future__ import annotations

import io

import pandas as pd

from .. import config
from . import http


def parse(text: str) -> pd.DataFrame:
    df = pd.read_csv(io.StringIO(text), dtype=str)
    out = pd.DataFrame({
        "url": df["url"].str.strip(),
        "phish_id": df["phish_id"],
        "submission_time": pd.to_datetime(df["submission_time"], errors="coerce", utc=True)
        .dt.tz_localize(None),
        "verified": df.get("verified"),
        "online": df.get("online"),
        "target": df.get("target"),
    })
    return out.dropna(subset=["url"])


def fetch() -> pd.DataFrame:
    if not config.PHISHTANK_API_KEY:
        raise RuntimeError("PHISHTANK_API_KEY not set (free key from phishtank.org/developer_info)")
    url = config.PHISHTANK_URL.format(key=config.PHISHTANK_API_KEY)
    return parse(http.get(url).text)
