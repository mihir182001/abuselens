"""Orchestrates one daily ingest: fetch -> validate -> load, with an audit log."""
from __future__ import annotations

import datetime as dt
import logging

import pandas as pd

from .. import db
from ..quality.checks import validate
from . import commoncrawl, openphish, phishtank, sitelinks, tranco, urlhaus

log = logging.getLogger("abuselens.ingest")

FEEDS = {
    "urlhaus": (urlhaus.fetch, "raw_urlhaus"),
    "openphish": (openphish.fetch, "raw_openphish"),
    "phishtank": (phishtank.fetch, "raw_phishtank"),
}


def _prior_counts(con, table: str, today) -> list[int]:
    rows = con.execute(
        f"SELECT count(*) FROM {table} WHERE snapshot_date < ? GROUP BY snapshot_date "
        "ORDER BY snapshot_date DESC LIMIT 7", [today]).fetchall()
    return [r[0] for r in rows]


def _log(con, source, today, n, status, msg=""):
    con.execute("INSERT INTO ingest_log VALUES (?,?,?,?,?,?)",
                [dt.datetime.now(dt.timezone.utc).replace(tzinfo=None), source, today, n, status, msg[:500]])


def ingest_feed(con, name: str, df: pd.DataFrame, table: str, today) -> bool:
    df, rep = validate(name, df, prior_row_counts=_prior_counts(con, table, today))
    if not rep.ok:
        _log(con, name, today, 0, "rejected", "; ".join(rep.errors))
        log.error("%s rejected: %s", name, rep.errors)
        return False
    n = db.load_snapshot(con, table, df, today)
    _log(con, name, today, n, "ok", "; ".join(rep.warnings))
    return True


def run(con, sources: list[str], today: dt.date | None = None) -> dict[str, bool]:
    today = today or dt.date.today()
    results: dict[str, bool] = {}
    for name, (fetch, table) in FEEDS.items():
        if name not in sources:
            continue
        try:
            results[name] = ingest_feed(con, name, fetch(), table, today)
        except Exception as e:  # one broken feed must not stop the others
            _log(con, name, today, 0, "error", repr(e))
            log.exception("%s failed", name)
            results[name] = False

    if "tranco" in sources:
        try:
            tr = tranco.fetch()
            _, rep = validate("tranco", tr)
            if not rep.ok:
                _log(con, "tranco", today, 0, "rejected", "; ".join(rep.errors))
                results["tranco"] = False
            else:
                # Only the sampled safe URLs are stored daily (not 1M rows/day).
                seed = int(today.strftime("%Y%m%d"))
                from .. import config
                sample = tranco.sample_safe_domains(tr, config.SAFE_DOMAINS_PER_DAY, seed)
                safe = pd.DataFrame(columns=["url", "domain", "tranco_rank", "source"])
                if "commoncrawl" in sources:
                    if commoncrawl.available():
                        safe = commoncrawl.fetch_for_domains(sample)
                    else:
                        print("  commoncrawl index unavailable (5xx/timeout); using site links instead",
                              flush=True)
                if len(safe) < 50 and ("commoncrawl" in sources or "sitelinks" in sources):
                    safe = sitelinks.fetch_for_domains(sample)
                if safe.empty:  # fall back to bare-domain homepage URLs
                    safe = pd.DataFrame({"url": "https://" + sample["domain"] + "/",
                                         "domain": sample["domain"],
                                         "tranco_rank": sample["rank"], "source": "tranco"})
                n = db.load_snapshot(con, "raw_safe_urls", safe, today)
                _log(con, "tranco", today, n, "ok")
                results["tranco"] = True
        except Exception as e:
            _log(con, "tranco", today, 0, "error", repr(e))
            results["tranco"] = False
    return results
