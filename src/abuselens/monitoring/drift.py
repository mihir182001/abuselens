"""Data drift (PSI), score drift, and week-by-week detection decay with alerting."""
from __future__ import annotations

import numpy as np
import pandas as pd

from ..models import train

PSI_WARN, PSI_ALERT = 0.10, 0.25
RECALL_DROP_ALERT = 0.10  # absolute drop vs. first evaluated week


def psi(expected, actual, bins: int = 10) -> float:
    """Population Stability Index with quantile bins fixed on the reference sample."""
    e, a = np.asarray(expected, float), np.asarray(actual, float)
    e, a = e[~np.isnan(e)], a[~np.isnan(a)]
    if len(e) == 0 or len(a) == 0:
        return float("nan")
    edges = np.unique(np.quantile(e, np.linspace(0, 1, bins + 1)))
    if len(edges) < 3:
        return 0.0
    edges[0], edges[-1] = -np.inf, np.inf
    pe = np.histogram(e, edges)[0] / len(e)
    pa = np.histogram(a, edges)[0] / len(a)
    pe, pa = np.clip(pe, 1e-4, None), np.clip(pa, 1e-4, None)
    return float(np.sum((pa - pe) * np.log(pa / pe)))


def feature_drift(reference: pd.DataFrame, current: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    rows = [{"feature": c, "psi": psi(reference[c], current[c])} for c in cols]
    out = pd.DataFrame(rows).sort_values("psi", ascending=False).reset_index(drop=True)
    out["status"] = np.where(out.psi >= PSI_ALERT, "ALERT", np.where(out.psi >= PSI_WARN, "warn", "ok"))
    return out


def weekly_decay(bundle: dict, df: pd.DataFrame, trained_through=None, fit_cutoffs: dict | None = None) -> pd.DataFrame:
    """Frozen model + frozen threshold applied to weeks of *malicious* URLs the model never fit on.

    With `fit_cutoffs` ({abuse_type: newest event used to fit/calibrate}) only rows newer than their
    type's cutoff are scored, so every row is genuinely out-of-sample and a falling recall means the
    model is ageing. FPR is measured once on the safe set (safe URLs are daily samples, not a weekly
    stream). Without cutoffs (older saved models) weeks are flagged by one global `trained_through`.
    """
    d = df.copy()
    d["score"] = train.score(bundle, d)
    thr = bundle["threshold"]
    safe = d[d.label == 0]
    fpr = float((safe.score >= thr).mean()) if len(safe) else float("nan")
    mal = d[d.label == 1].copy()
    mal["event_ts"] = pd.to_datetime(mal["event_ts"])
    if fit_cutoffs:
        cut = mal["abuse_type"].map(lambda k: pd.to_datetime(fit_cutoffs.get(k)))
        mal = mal[mal["event_ts"] > cut]
    mal["week"] = mal["event_ts"].dt.to_period("W").dt.start_time
    cutoff = pd.to_datetime(trained_through) if (trained_through is not None and not fit_cutoffs) else None
    rows = []
    for wk, g in mal.groupby("week"):
        recall = float((g.score >= thr).mean())
        prev = train.ASSUMED_PREVALENCE
        denom = recall * prev + fpr * (1 - prev)
        rows.append({"week": wk, "n_malicious": len(g), "recall": recall, "fpr": fpr,
                     "precision_at_prevalence": recall * prev / denom if denom else float("nan"),
                     "mean_score_malicious": float(g.score.mean()),
                     "after_training": True if cutoff is None else bool(wk > cutoff)})
    return pd.DataFrame(rows)


def alerts(drift: pd.DataFrame, decay: pd.DataFrame) -> list[str]:
    out = [f"DATA DRIFT ({r.abuse_type}): {r.feature} PSI={r.psi:.2f}" for r in drift.itertuples()
           if r.status == "ALERT"]
    valid = decay[decay.after_training] if "after_training" in decay else decay
    if len(valid) >= 2:
        base, last = valid.iloc[0], valid.iloc[-1]
        if base.recall - last.recall >= RECALL_DROP_ALERT:
            out.append(f"RECALL DECAY: recall fell {base.recall:.2f} -> {last.recall:.2f} "
                       f"(week of {last.week:%Y-%m-%d}); attackers likely changed tactics, retrain")
    if len(decay) and decay.fpr.iloc[-1] > 2 * train.TARGET_FPR:
        out.append(f"FPR DRIFT: {decay.fpr.iloc[-1]:.3f} vs target {train.TARGET_FPR}")
    return out


MIN_ROWS_FOR_DRIFT = 2000
MIN_DAYS_FOR_DRIFT = 7


def drift_by_type(df: pd.DataFrame, cols: list[str], min_rows: int = MIN_ROWS_FOR_DRIFT,
                  min_days: int = MIN_DAYS_FOR_DRIFT, seed: int = 7) -> tuple[pd.DataFrame, list[str]]:
    """PSI of earlier-half vs later-half within each malicious abuse type; worst type per feature.

    Comparing across types (or against safe URLs) would just measure the mix of URLs. A type is only
    assessed with enough rows and enough distinct days: PSI on a few hundred URLs from one or two feed
    pulls mostly measures which campaigns happened to be listed. Returns (drift, skipped_reasons).
    """
    parts, skipped = [], []
    for typ, g in df[df.label == 1].groupby("abuse_type"):
        days = pd.to_datetime(g["event_ts"]).dt.normalize().nunique()
        if len(g) < min_rows or days < min_days:
            skipped.append(f"{typ}: have {len(g):,} URLs over {days} day(s); needs >= {min_rows:,} over >= {min_days} days")
            continue
        g = g.sample(frac=1.0, random_state=seed).sort_values("event_ts", kind="stable")
        cut = len(g) // 2
        fd = feature_drift(g.iloc[:cut], g.iloc[cut:], cols)
        fd["abuse_type"] = typ
        parts.append(fd)
    if not parts:
        return pd.DataFrame(columns=["feature", "psi", "status", "abuse_type"]), skipped
    allp = pd.concat(parts, ignore_index=True)  # unique index, so idxmax labels are unambiguous
    worst = allp.loc[allp.groupby("feature").psi.idxmax()]
    return worst.sort_values("psi", ascending=False).reset_index(drop=True), skipped


def run(con, bundle: dict, trained_through=None, fit_cutoffs: dict | None = None) -> dict:
    df = train.load_dataset(con)
    drift, skipped = drift_by_type(df, bundle["features"])
    decay = weekly_decay(bundle, df, trained_through, fit_cutoffs)
    return {"drift": drift, "decay": decay, "alerts": alerts(drift, decay), "drift_skipped": skipped}
