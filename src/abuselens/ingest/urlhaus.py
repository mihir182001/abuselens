"""abuse.ch URLhaus: malware-distribution URLs with added-date, online status, threat, tags.

abuse.ch now requires a free Auth-Key (https://auth.abuse.ch/) placed in the download URL.
"""
from __future__ import annotations

import io

import pandas as pd

from .. import config
from . import http

DEFAULT_COLUMNS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags",
                   "urlhaus_link", "reporter"]


def _split_header(text: str) -> tuple[list[str], str]:
    """Find column names whether they are a '# id,dateadded,...' comment or a plain header row."""
    cols, body = None, []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            cand = [c.strip().strip('"') for c in s.lstrip("#").strip().split(",")]
            if "dateadded" in cand and "url" in cand:
                cols = cand
            continue
        if cols is None and "dateadded" in s and "url" in s and not s.lower().startswith(('"http', "http")):
            cols = [c.strip().strip('"') for c in s.split(",")]
            continue
        body.append(ln)
    return cols or DEFAULT_COLUMNS, "\n".join(body)


def parse(text: str) -> pd.DataFrame:
    cols, body = _split_header(text)
    df = pd.read_csv(io.StringIO(body), names=cols, header=None, quotechar='"',
                     skipinitialspace=True, dtype=str, index_col=False)
    for c in ("url_status", "last_online", "threat", "tags", "reporter"):
        if c not in df:
            df[c] = None
    out = pd.DataFrame({
        "url": df["url"].str.strip(),
        "date_added": pd.to_datetime(df["dateadded"], errors="coerce", utc=True).dt.tz_localize(None),
        "url_status": df["url_status"].str.lower(),
        "last_online": pd.to_datetime(df["last_online"], errors="coerce", utc=True).dt.tz_localize(None),
        "threat": df["threat"],
        "tags": df["tags"].fillna(""),
        "reporter": df["reporter"],
    })
    return out.dropna(subset=["url"])


def fetch() -> pd.DataFrame:
    if not config.ABUSECH_AUTH_KEY:
        raise RuntimeError("ABUSECH_AUTH_KEY not set. Get a free key at https://auth.abuse.ch/ "
                           "then: $env:ABUSECH_AUTH_KEY=\"your_key\"")
    return parse(http.get(config.URLHAUS_CSV.format(key=config.ABUSECH_AUTH_KEY)).text)
