"""Data-quality gates run before a snapshot is loaded into the warehouse."""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .. import config

REQUIRED_COLUMNS = {
    "urlhaus": {"url", "date_added", "url_status", "last_online", "threat", "tags"},
    "openphish": {"url"},
    "phishtank": {"url", "submission_time", "target"},
    "tranco": {"rank", "domain"},
}
FRESHNESS_COLUMN = {"urlhaus": "date_added", "phishtank": "submission_time"}


@dataclass
class QualityReport:
    source: str
    rows_in: int
    rows_out: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate(source: str, df: pd.DataFrame, *, prior_row_counts: list[int] | None = None,
             now: pd.Timestamp | None = None) -> tuple[pd.DataFrame, QualityReport]:
    """Schema check -> dedup -> minimum volume -> volume-drop -> freshness.

    Returns the cleaned frame and a report. Errors block loading; warnings are logged.
    """
    rep = QualityReport(source=source, rows_in=len(df))
    now = now or pd.Timestamp.now("UTC").tz_localize(None)

    missing = REQUIRED_COLUMNS.get(source, set()) - set(df.columns)
    if missing:
        rep.errors.append(f"schema change: missing columns {sorted(missing)}")
        return df, rep

    key = "domain" if source == "tranco" else "url"
    df = df.dropna(subset=[key]).drop_duplicates(subset=[key]).reset_index(drop=True)
    dupes = rep.rows_in - len(df)
    if dupes:
        rep.warnings.append(f"dropped {dupes} duplicate/null rows")
    rep.rows_out = len(df)

    floor = config.MIN_ROWS.get(source, 1)
    if len(df) < floor:
        rep.errors.append(f"volume below floor: {len(df)} < {floor}")

    if prior_row_counts:
        median = float(pd.Series(prior_row_counts).median())
        if median > 0 and len(df) < config.VOLUME_DROP_RATIO * median:
            rep.errors.append(f"sudden volume drop: {len(df)} vs trailing median {median:.0f}")

    fcol = FRESHNESS_COLUMN.get(source)
    if fcol and len(df):
        newest = pd.to_datetime(df[fcol], errors="coerce").max()
        if pd.notna(newest):
            age_h = (now - newest).total_seconds() / 3600
            if age_h > config.FRESHNESS_MAX_AGE_HOURS:
                rep.errors.append(f"stale feed: newest record is {age_h:.0f}h old")
    return df, rep
