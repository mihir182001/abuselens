"""Tranco top-1M ranking of legitimate domains (source of safe examples)."""
from __future__ import annotations

import io
import zipfile

import pandas as pd

from .. import config
from . import http


def parse_csv(text: str) -> pd.DataFrame:
    df = pd.read_csv(io.StringIO(text), names=["rank", "domain"], header=None)
    df["domain"] = df["domain"].astype(str).str.lower().str.strip()
    return df.dropna()


def fetch() -> pd.DataFrame:
    raw = http.get(config.TRANCO_ZIP).content
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return parse_csv(z.read(z.namelist()[0]).decode())


def sample_safe_domains(tranco: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """Sample domains from the *non-head* of the ranking to avoid popularity label bias."""
    band = tranco[(tranco["rank"] >= config.SAFE_RANK_MIN) & (tranco["rank"] <= config.SAFE_RANK_MAX)]
    return band.sample(n=min(n, len(band)), random_state=seed)
