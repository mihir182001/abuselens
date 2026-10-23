"""Test fixtures. NOTE: the generated rows below exist only to exercise code paths in tests;
the pipeline itself never generates data, it only ingests real feeds."""
import datetime as dt
import random

import pandas as pd
import pytest

from abuselens import config, db


@pytest.fixture(autouse=True)
def _sql_dir(monkeypatch):
    monkeypatch.setattr(config, "SQL_DIR", config.ROOT / "sql")


_CAMPAIGN_HOSTS = [f"185.{i}.{i * 3 % 250}.{i + 10}" for i in range(1, 13)]


def _malware_url(r):
    # ~60% of URLs come from a small pool of hosts (droppers re-using infrastructure).
    host = r.choice(_CAMPAIGN_HOSTS) if r.random() < 0.6 else \
        f"{r.randint(11, 220)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    return f"http://{host}:{r.choice([8080, 5555, 3000])}/bin/{r.choice(['x86', 'arm', 'mips'])}{r.randint(1, 99)}.sh"


def _phish_url(r):
    brand = r.choice(["paypal", "microsoft", "netflix", "apple"])
    return f"https://{brand}-secure-login{r.randint(1, 999)}.{r.choice(['xyz', 'top', 'click'])}" \
           f"/verify/account{r.randint(1, 99)}/signin.php?id={r.randint(10**6, 10**7)}"


def _safe_url(r):
    dom = f"{r.choice(['blue', 'garden', 'maple', 'river', 'tech', 'city'])}{r.choice(['news', 'shop', 'blog', 'works'])}" \
          f"{r.randint(1, 500)}.{r.choice(['com', 'org', 'net', 'co.uk'])}"
    return f"https://www.{dom}/{r.choice(['articles', 'products', 'about'])}/{r.randint(1, 5000)}"


def populate(con):
    """Fill a warehouse with ~30 days of raw rows across all feeds, then build staging + marts."""
    r = random.Random(0)
    start = dt.datetime(2026, 9, 1)
    rows = []
    for _ in range(900):
        added = start + dt.timedelta(hours=r.randint(0, 24 * 30))
        offline = r.random() < 0.7
        host_url = _malware_url(r)
        rows.append({
            "url": host_url, "date_added": added,
            "url_status": "offline" if offline else "online",
            "last_online": added + dt.timedelta(hours=r.expovariate(1 / 30)) if offline else pd.NaT,
            "threat": "malware_download", "tags": "elf,mirai", "reporter": "t"})
    db.load_snapshot(con, "raw_urlhaus", pd.DataFrame(rows), dt.date(2026, 10, 1))

    phish = pd.DataFrame({"url": [_phish_url(r) for _ in range(300)]})
    db.load_snapshot(con, "raw_openphish", phish, dt.date(2026, 10, 1))
    pt = pd.DataFrame({
        "url": [_phish_url(r) for _ in range(300)], "phish_id": [str(i) for i in range(300)],
        "submission_time": [start + dt.timedelta(hours=r.randint(0, 24 * 30)) for _ in range(300)],
        "verified": "yes", "online": "yes",
        "target": [r.choice(["PayPal", "Microsoft", "Netflix", "Other"]) for _ in range(300)]})
    db.load_snapshot(con, "raw_phishtank", pt, dt.date(2026, 10, 1))

    for d in range(30):
        day = (start + dt.timedelta(days=d)).date()
        safe = pd.DataFrame({"url": [_safe_url(r) for _ in range(60)]})
        safe["domain"] = safe["url"].str.extract(r"https://www\.([^/]+)/")[0]
        safe["tranco_rank"], safe["source"] = 50_000, "commoncrawl"
        db.load_snapshot(con, "raw_safe_urls", safe, day)
    db.run_sql_dir(con, "staging")
    db.run_sql_dir(con, "marts")
    return con


@pytest.fixture
def warehouse():
    return populate(db.connect(":memory:"))
