def test_staging_dedups_and_labels(warehouse):
    n, nd = warehouse.execute("SELECT count(*), count(DISTINCT url) FROM stg_malicious_urls").fetchone()
    assert n == nd and n > 800
    assert warehouse.execute("SELECT count(*) FROM stg_safe_urls").fetchone()[0] > 1000


def test_brand_targets_exclude_other(warehouse):
    brands = {r[0] for r in warehouse.execute("SELECT DISTINCT brand FROM brand_targets").fetchall()}
    assert "Other" not in brands and "PayPal" in brands


def test_campaigns_group_templates(warehouse):
    n, top = warehouse.execute("SELECT count(*), max(n_urls) FROM campaigns").fetchone()
    assert n > 0 and top >= 5


def test_takedown_censoring(warehouse):
    r = warehouse.execute("""SELECT sum(taken_down), count(*), min(lifetime_hours)
                             FROM stg_takedown""").fetchone()
    assert 0 < r[0] < r[1] and r[2] >= 0
    # censored (still-online) URLs must have a positive observed lifetime up to the newest snapshot
    assert warehouse.execute(
        "SELECT min(lifetime_hours) FROM stg_takedown WHERE taken_down = 0").fetchone()[0] > 0


def test_daily_trends_cover_both_abuse_types(warehouse):
    types = {r[0] for r in warehouse.execute("SELECT DISTINCT abuse_type FROM daily_abuse_trends").fetchall()}
    assert {"phishing", "malware_download"} <= types
