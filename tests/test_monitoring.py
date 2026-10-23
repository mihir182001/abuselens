import numpy as np
import pandas as pd

from abuselens.models import train
from abuselens.monitoring import drift
from abuselens.reporting import brief


def test_feature_drift_ignores_class_mix(warehouse):
    df = train.load_dataset(warehouse)
    bundle = train.fit(*train.time_split(df)[:2], train.feature_columns(df))
    res = drift.run(warehouse, bundle)
    # stationary generated malware => no ALERT-level drift (the old mixed-class split gave PSI > 1)
    assert (res["drift"].status != "ALERT").all()
    assert res["drift"].feature.is_unique  # one row per feature (regression: duplicated rows)


def test_weeks_inside_training_window_do_not_trigger_decay(warehouse):
    df = train.load_dataset(warehouse)
    bundle = train.fit(*train.time_split(df)[:2], train.feature_columns(df))
    res = drift.run(warehouse, bundle, trained_through="2099-01-01")
    assert not res["decay"].after_training.any()
    assert not any("DECAY" in a for a in res["alerts"])


def test_decay_alert_fires_when_recall_drops():
    decay = pd.DataFrame({"week": pd.to_datetime(["2026-10-05", "2026-10-12"]), "recall": [0.97, 0.80],
                          "fpr": [0.01, 0.01], "after_training": [True, True]})
    assert any("RECALL DECAY" in a for a in drift.alerts(pd.DataFrame(columns=["feature", "psi", "status"]), decay))


def test_md_renders_inf_as_not_reached():
    out = brief._md(pd.DataFrame({"host": ["a"], "median_hours": [np.inf]}))
    assert "not reached" in out and "inf" not in out


def test_small_or_short_history_is_skipped_not_judged():
    n = 300
    df = pd.DataFrame({"label": 1, "abuse_type": "phishing",
                       "event_ts": pd.Timestamp("2026-10-22"), "url_len": np.random.default_rng(0).normal(60, 20, n)})
    out, skipped = drift.drift_by_type(df, ["url_len"])
    assert out.empty and len(skipped) == 1 and "phishing" in skipped[0]


def test_enough_history_is_assessed_and_features_unique():
    rng = np.random.default_rng(1)
    n = 4000
    df = pd.DataFrame({"label": 1, "abuse_type": ["a"] * n, "url_len": rng.normal(60, 20, n),
                       "x": rng.normal(0, 1, n),
                       "event_ts": pd.date_range("2026-10-01", periods=n, freq="10min")})
    out, skipped = drift.drift_by_type(df, ["url_len", "x"])
    assert not skipped and out.feature.is_unique and len(out) == 2


def test_decay_uses_only_rows_after_fit_cutoff(warehouse):
    df = train.load_dataset(warehouse)
    tr, va, _ = train.time_split(df)
    bundle = train.fit(tr, va, train.feature_columns(df))
    cutoffs = {k: str(v) for k, v in pd.concat([tr, va]).groupby("abuse_type").event_ts.max().items()}
    res = drift.run(warehouse, bundle, trained_through="2099-01-01", fit_cutoffs=cutoffs)
    mal = df[df.label == 1]
    expected = int((pd.to_datetime(mal.event_ts) > mal.abuse_type.map(lambda k: pd.to_datetime(cutoffs[k]))).sum())
    assert res["decay"].n_malicious.sum() == expected and expected > 0
    assert res["decay"].after_training.all()


def test_meta_records_fit_cutoffs(warehouse, tmp_path):
    meta = train.train_and_promote(warehouse, tmp_path)
    assert {"malware_download", "phishing", "safe"} <= set(meta["fit_cutoffs"])
