"""Honest breakdown of the champion model on its held-out test slice, by abuse type."""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import metrics, train


def by_type(bundle: dict, test: pd.DataFrame) -> pd.DataFrame:
    """Recall per malicious type at the frozen threshold, plus FPR on safe URLs, plus
    ROC-AUC / PR-AUC of each type against the same safe URLs."""
    s = train.score(bundle, test)
    t = test.assign(score=s)
    safe = t[t.label == 0]
    rows = [{"slice": "safe (false positives)", "n": len(safe),
             "flagged_rate": float((safe.score >= bundle["threshold"]).mean()),
             "roc_auc": np.nan, "pr_auc": np.nan}]
    for typ, g in t[t.label == 1].groupby("abuse_type"):
        both = pd.concat([g, safe])
        m = metrics.evaluate(both.label, both.score, bundle["threshold"], train.ASSUMED_PREVALENCE)
        rows.append({"slice": typ, "n": len(g), "flagged_rate": float((g.score >= bundle["threshold"]).mean()),
                     "roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"]})
    return pd.DataFrame(rows)


def importances(bundle: dict, k: int = 12) -> pd.DataFrame:
    b = bundle["model"].get_booster()
    gain = b.get_score(importance_type="total_gain")
    out = pd.DataFrame({"feature": list(gain), "gain": list(gain.values())})
    out["share"] = out.gain / out.gain.sum()
    return out.sort_values("share", ascending=False).head(k).reset_index(drop=True)


def host_split(df: pd.DataFrame, test_frac: float = 0.25, val_frac: float = 0.15, seed: int = 7):
    """Strict split: all URLs of a host go to exactly one of train / calibration / test.

    Done per (label, abuse type) so each group appears in every part. This removes the
    near-duplicate leakage of phishing kits and malware servers that reuse one host, so the
    test measures detection on hosts the model has never seen.
    """
    rng = np.random.default_rng(seed)
    parts = {0: [], 1: [], 2: []}
    for _, g in df.groupby(["label", "abuse_type"]):
        counts = g.groupby("host").size()
        hosts = counts.index.to_numpy()
        rng.shuffle(hosts)
        share = counts.loc[hosts].cumsum().to_numpy() / len(g)
        cut_test, cut_val = 1 - test_frac, (1 - test_frac) * (1 - val_frac)
        which = np.where(share <= cut_val, 0, np.where(share <= cut_test, 1, 2))
        # never leave a part empty for small groups
        for k in (0, 1, 2):
            if not (which == k).any():
                which[min(k, len(which) - 1)] = k
        assign = dict(zip(hosts, which, strict=True))
        m = g["host"].map(assign)
        for k in (0, 1, 2):
            parts[k].append(g[m == k])
    return tuple(pd.concat(parts[k]).reset_index(drop=True) for k in (0, 1, 2))


def strict_report(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Train a fresh model on host-disjoint data; return per-type results, importances, sizes."""
    tr, va, te = host_split(df)
    bundle = train.fit(tr, va, train.feature_columns(df))
    shared = len(set(tr.host) & set(te.host))
    sizes = {"train": len(tr), "calibration": len(va), "test": len(te), "hosts_shared_train_test": shared,
             "threshold": bundle["threshold"]}
    return by_type(bundle, te), importances(bundle), sizes
