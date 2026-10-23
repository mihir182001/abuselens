"""DuckDB warehouse helpers: connection, raw-table loading, SQL file execution."""
from __future__ import annotations

from pathlib import Path

import duckdb
import pandas as pd

from . import config

RAW_TABLES = {
    "raw_urlhaus": """
        url VARCHAR, date_added TIMESTAMP, url_status VARCHAR, last_online TIMESTAMP,
        threat VARCHAR, tags VARCHAR, reporter VARCHAR, snapshot_date DATE""",
    "raw_openphish": "url VARCHAR, snapshot_date DATE",
    "raw_phishtank": """
        url VARCHAR, phish_id VARCHAR, submission_time TIMESTAMP, verified VARCHAR,
        online VARCHAR, target VARCHAR, snapshot_date DATE""",
    "raw_tranco": "rank INTEGER, domain VARCHAR, snapshot_date DATE",
    "raw_safe_urls": "url VARCHAR, domain VARCHAR, tranco_rank INTEGER, source VARCHAR, snapshot_date DATE",
    "raw_enrichment": """
        domain VARCHAR, domain_age_days INTEGER, registrar VARCHAR, asn INTEGER,
        asn_org VARCHAR, cert_count INTEGER, enriched_at TIMESTAMP""",
    "ingest_log": """
        run_ts TIMESTAMP, source VARCHAR, snapshot_date DATE, rows_loaded INTEGER,
        status VARCHAR, message VARCHAR""",
}


def connect(path: str | Path | None = None) -> duckdb.DuckDBPyConnection:
    p = Path(path) if path else config.DB_PATH
    if str(p) != ":memory:":
        p.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(p))
    init_schema(con)
    return con


def init_schema(con: duckdb.DuckDBPyConnection) -> None:
    for name, cols in RAW_TABLES.items():
        con.execute(f"CREATE TABLE IF NOT EXISTS {name} ({cols})")


def load_snapshot(con, table: str, df: pd.DataFrame, snapshot_date) -> int:
    """Idempotently replace the snapshot for `snapshot_date` in a raw table.

    Re-running the same day never duplicates rows; earlier days are kept, so the
    warehouse grows by one snapshot per day.
    """
    if table not in RAW_TABLES:
        raise ValueError(f"unknown raw table {table}")
    df = df.copy()
    df["snapshot_date"] = pd.to_datetime(snapshot_date).date()
    cols = [c.strip().split()[0] for c in RAW_TABLES[table].split(",")]
    # Required columns are enforced upstream by quality.validate; optional ones become NULL.
    df = df.reindex(columns=cols)
    if len(df):
        con.execute(f"DELETE FROM {table} WHERE snapshot_date = ?", [df["snapshot_date"].iloc[0]])
    con.register("_df", df)
    con.execute(f"INSERT INTO {table} SELECT * FROM _df")
    con.unregister("_df")
    return len(df)


def run_sql_dir(con, subdir: str) -> list[str]:
    """Execute every .sql file in sql/<subdir> in lexical order."""
    ran = []
    for f in sorted((config.SQL_DIR / subdir).glob("*.sql")):
        con.execute(f.read_text(encoding="utf-8"))
        ran.append(f.name)
    return ran
