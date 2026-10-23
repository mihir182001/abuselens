"""Time-based training, calibration, threshold selection and champion/challenger promotion."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression

from .. import config
from ..features.lexical import ENRICHMENT_FEATURES, FEATURE_NAMES, build_frame
from . import metrics

TARGET_FPR = 0.01
ASSUMED_PREVALENCE = 0.01


def load_dataset(con) -> pd.DataFrame:
    """Labelled URLs with the timestamp each was first observed (for time-based splits)."""
    df = con.execute("""
        SELECT url, 1 AS label, event_ts, host, abuse_type FROM stg_malicious_urls
        UNION ALL
        SELECT url, 0 AS label, event_ts, host, 'safe' AS abuse_type FROM stg_safe_urls
    """).df()
    feats = build_frame(df["url"])
    out = pd.concat([df.reset_index(drop=True), feats], axis=1)
    # Optional enrichment (NaN when absent; XGBoost handles missing natively).
    try:
        enr = con.execute("""
            SELECT DISTINCT ON (domain) domain AS host, domain_age_days, cert_count
            FROM raw_enrichment ORDER BY domain, enriched_at DESC""").df()
    except Exception:
        enr = pd.DataFrame(columns=["host", *ENRICHMENT_FEATURES])
    out = out.merge(enr, on="host", how="left")
    for c in ENRICHMENT_FEATURES:
        if c not in out:
            out[c] = np.nan
    return out


def feature_columns(df: pd.DataFrame) -> list[str]:
    cols = list(FEATURE_NAMES)
    # Only use enrichment if it covers a meaningful share of rows.
    cols += [c for c in ENRICHMENT_FEATURES if c in df and df[c].notna().mean() > 0.3]
    return cols


def time_split(df: pd.DataFrame, test_frac: float = 0.25, val_frac: float = 0.15, seed: int = 7):
    """Per-group temporal split: within each (label, abuse type), earlier -> train, next -> calibration, latest -> test.

    Each group is split on its own timeline: safe URLs arrive in daily snapshots and OpenPhish
    URLs all share the day they were pulled, so a single global cut would put a whole group on
    one side (e.g. every phishing URL in the test set). Ties are broken randomly.
    """
    parts = {"tr": [], "va": [], "te": []}
    group_cols = ["label", "abuse_type"] if "abuse_type" in df else ["label"]
    for _, g in df.groupby(group_cols):
        g = g.sample(frac=1.0, random_state=seed).sort_values("event_ts", kind="stable")
        i_test = int(len(g) * (1 - test_frac))
        i_val = int(i_test * (1 - val_frac))
        parts["tr"].append(g.iloc[:i_val])
        parts["va"].append(g.iloc[i_val:i_test])
        parts["te"].append(g.iloc[i_test:])
    return tuple(pd.concat(parts[k]).reset_index(drop=True) for k in ("tr", "va", "te"))


def fit(train: pd.DataFrame, val: pd.DataFrame, cols: list[str], seed: int = 7) -> dict:
    pos = max(int(train["label"].sum()), 1)
    clf = xgb.XGBClassifier(
        n_estimators=300, max_depth=5, learning_rate=0.08, subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=(len(train) - pos) / pos, eval_metric="aucpr",
        random_state=seed, n_jobs=2, tree_method="hist")
    clf.fit(train[cols], train["label"])
    raw_val = clf.predict_proba(val[cols])[:, 1]
    # scale_pos_weight skews probabilities; isotonic calibration on a later slice fixes that.
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw_val, val["label"])
    thr = metrics.threshold_at_fpr(val["label"], iso.predict(raw_val), TARGET_FPR)
    return {"model": clf, "calibrator": iso, "threshold": thr, "features": cols}


def score(bundle: dict, df: pd.DataFrame) -> np.ndarray:
    raw = bundle["model"].predict_proba(df[bundle["features"]])[:, 1]
    return bundle["calibrator"].predict(raw)


def evaluate_bundle(bundle: dict, test: pd.DataFrame) -> dict:
    s = score(bundle, test)
    thr_test = metrics.threshold_at_fpr(test["label"], s, TARGET_FPR)
    m = metrics.evaluate(test["label"], s, bundle["threshold"], ASSUMED_PREVALENCE)
    # Also report the best-case operating point re-tuned on test (precision@1%FPR).
    m["at_target_fpr"] = metrics.operating_point(test["label"], s, thr_test, ASSUMED_PREVALENCE)
    return m


def save(bundle: dict, path: Path, meta: dict) -> None:
    path.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path / "bundle.joblib")
    (path / "meta.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")


def load(path: Path) -> tuple[dict, dict]:
    return joblib.load(path / "bundle.joblib"), json.loads((path / "meta.json").read_text(encoding="utf-8"))


def train_and_promote(con, model_dir: Path | None = None) -> dict:
    model_dir = Path(model_dir or config.MODEL_DIR)
    df = load_dataset(con)
    if df["label"].nunique() < 2 or len(df) < 200:
        raise RuntimeError(f"not enough labelled data to train ({len(df)} rows)")
    cols = feature_columns(df)
    train, val, test = time_split(df)
    challenger = fit(train, val, cols)
    ch_metrics = evaluate_bundle(challenger, test)

    meta = {
        "trained_at": dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat(),
        "train_range": [str(train.event_ts.min()), str(train.event_ts.max())],
        "test_range": [str(test.event_ts.min()), str(test.event_ts.max())],
        "target_fpr": TARGET_FPR, "assumed_prevalence": ASSUMED_PREVALENCE,
        "n_train": len(train), "metrics": ch_metrics,
        # newest event per abuse type used to fit or calibrate: later rows are genuinely out-of-sample
        "fit_cutoffs": {k: str(v) for k, v in
                        pd.concat([train, val]).groupby("abuse_type").event_ts.max().items()},
    }
    champ_dir = model_dir / "champion"
    decision, champ_metrics = "promoted (no champion)", None
    if (champ_dir / "bundle.joblib").exists():
        champ, _ = load(champ_dir)
        # Same, newest holdout for both models -> apples-to-apples.
        champ_metrics = evaluate_bundle(champ, test)
        if ch_metrics["pr_auc"] >= champ_metrics["pr_auc"]:
            decision = "promoted (challenger >= champion on PR-AUC)"
        else:
            decision = "kept champion"
    meta["decision"], meta["champion_metrics_on_same_holdout"] = decision, champ_metrics
    save(challenger, model_dir / "challenger", meta)
    if decision.startswith("promoted"):
        save(challenger, champ_dir, meta)
    return meta
