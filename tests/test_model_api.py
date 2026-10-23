import numpy as np
import pytest
from fastapi.testclient import TestClient

from abuselens import config
from abuselens.analytics import survival
from abuselens.api import app as api
from abuselens.models import metrics, train
from abuselens.monitoring import drift
from abuselens.reporting import brief


def test_threshold_at_fpr_bounds_false_positives():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(10_000), np.ones(500)]
    s = np.r_[rng.normal(0, 1, 10_000), rng.normal(3, 1, 500)]
    thr = metrics.threshold_at_fpr(y, s, 0.01)
    op = metrics.operating_point(y, s, thr, prevalence=0.01)
    assert op["fpr"] <= 0.0101 and op["recall"] > 0.5
    assert op["precision_at_prevalence"] < op["precision"]  # fewer positives => lower precision


def test_psi_detects_shift():
    rng = np.random.default_rng(1)
    a = rng.normal(0, 1, 5000)
    assert drift.psi(a, rng.normal(0, 1, 5000)) < 0.05
    assert drift.psi(a, rng.normal(2, 1, 5000)) > drift.PSI_ALERT


def test_time_split_has_no_leakage(warehouse):
    df = train.load_dataset(warehouse)
    tr, va, te = train.time_split(df)
    for typ in df.abuse_type.unique():  # temporal order must hold within each group
        a, b, c = (x[x.abuse_type == typ].event_ts for x in (tr, va, te))
        assert len(a) and len(b) and len(c)
        assert a.max() <= b.min() and b.max() <= c.min()


@pytest.fixture
def trained(warehouse, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MODEL_DIR", tmp_path)
    meta = train.train_and_promote(warehouse, tmp_path)
    return warehouse, meta, tmp_path


def test_train_promote_and_champion_challenger(trained):
    con, meta, path = trained
    assert meta["decision"].startswith("promoted") and meta["metrics"]["roc_auc"] > 0.9
    assert (path / "champion" / "bundle.joblib").exists()
    meta2 = train.train_and_promote(con, path)       # second run must compare against champion
    assert meta2["champion_metrics_on_same_holdout"] is not None


def test_monitoring_and_report(trained):
    con, meta, path = trained
    bundle, _ = train.load(path / "champion")
    res = drift.run(con, bundle)
    assert {"drift", "decay", "alerts"} <= set(res) and len(res["decay"]) >= 1
    text = brief.build(con, meta, res)
    assert "weekly risk brief" in text and "Detection model" in text


def test_survival_outputs(warehouse):
    td = survival.load(warehouse)
    km = survival.kaplan_meier(td)
    assert km.iloc[0].n == len(td) and km.iloc[0].median_hours > 0


def test_api_scores_and_explains(trained):
    _, _, path = trained
    api._model.cache_clear()
    client = TestClient(api.app)
    assert client.get("/health").json()["status"] == "ok"
    bad = client.post("/score", json={"url": "http://185.10.20.30:8080/bin/x86.sh"}).json()
    good = client.post("/score", json={"url": "https://www.blueblog12.com/articles/42"}).json()
    assert bad["risk_score"] > good["risk_score"]
    assert bad["flagged"] and not good["flagged"]
    assert len(bad["reasons"]) == 3
    assert client.post("/score", json={"url": "x"}).status_code == 422


def test_time_split_handles_single_day_safe_snapshot():
    import pandas as pd
    df = pd.DataFrame({
        "label": [1] * 400 + [0] * 400,
        "event_ts": list(pd.date_range("2026-09-01", periods=400, freq="h")) + [pd.Timestamp("2026-10-22")] * 400})
    tr, va, te = train.time_split(df)
    for part in (tr, va, te):
        assert part.label.nunique() == 2
    m = tr[tr.label == 1].event_ts.max(), te[te.label == 1].event_ts.min()
    assert m[0] <= m[1]


def test_every_abuse_type_appears_in_train_and_test():
    import pandas as pd
    df = pd.DataFrame({
        "label": [1] * 300 + [1] * 300 + [0] * 300,
        "abuse_type": ["malware_download"] * 300 + ["phishing"] * 300 + ["safe"] * 300,
        "event_ts": list(pd.date_range("2026-09-01", periods=300, freq="h")) + [pd.Timestamp("2026-10-22")] * 300
        + [pd.Timestamp("2026-10-22")] * 300})
    tr, va, te = train.time_split(df)
    for part in (tr, va, te):
        assert set(part.abuse_type) == {"malware_download", "phishing", "safe"}
