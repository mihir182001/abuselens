"""OpenPhish community feed: one live phishing URL per line."""
from __future__ import annotations

import pandas as pd

from .. import config
from . import http


def parse(text: str) -> pd.DataFrame:
    urls = [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith("http")]
    return pd.DataFrame({"url": urls})


def fetch() -> pd.DataFrame:
    return parse(http.get(config.OPENPHISH_FEED).text)
