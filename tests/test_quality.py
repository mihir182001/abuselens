import datetime as dt

import pandas as pd

from abuselens import db
from abuselens.ingest import runner
from abuselens.quality.checks import validate

NOW = pd.Timestamp("2026-10-21 12:00")


def _uh(n, ts="2026-10-21 09:00"):
    return pd.DataFrame({"url": [f"http://h{i}.example/a" for i in range(n)],
                         "date_added": pd.Timestamp(ts), "url_status": "online",
                         "last_online": pd.NaT, "threat": "malware_download", "tags": ""})


def test_schema_change_rejected():
    _, rep = validate("urlhaus", _uh(100).drop(columns=["threat"]), now=NOW)
    assert not rep.ok and "schema" in rep.errors[0]


def test_duplicates_dropped():
    df = pd.concat([_uh(100), _uh(100)])
    out, rep = validate("urlhaus", df, now=NOW)
    assert len(out) == 100 and rep.ok


def test_volume_drop_rejected():
    _, rep = validate("urlhaus", _uh(100), prior_row_counts=[1000, 1100, 900], now=NOW)
    assert any("volume drop" in e for e in rep.errors)


def test_stale_feed_rejected():
    _, rep = validate("urlhaus", _uh(100, ts="2026-10-01 00:00"), now=NOW)
    assert any("stale" in e for e in rep.errors)


def test_runner_loads_good_and_logs_rejected():
    con = db.connect(":memory:")
    today = dt.date(2026, 10, 21)
    good = _uh(100, ts=str(dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(hours=1)))
    assert runner.ingest_feed(con, "urlhaus", good, "raw_urlhaus", today)
    assert con.execute("SELECT count(*) FROM raw_urlhaus").fetchone()[0] == 100
    # same-day rerun is idempotent
    runner.ingest_feed(con, "urlhaus", good, "raw_urlhaus", today)
    assert con.execute("SELECT count(*) FROM raw_urlhaus").fetchone()[0] == 100
    assert not runner.ingest_feed(con, "urlhaus", good.head(10), "raw_urlhaus", dt.date(2026, 10, 22))
    status = con.execute("SELECT status FROM ingest_log ORDER BY run_ts DESC LIMIT 1").fetchone()[0]
    assert status == "rejected"
