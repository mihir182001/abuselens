from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def threshold_at_fpr(y_true, scores, fpr: float = 0.01) -> float:
    """Score threshold such that at most `fpr` of negatives score at or above it."""
    neg = np.sort(np.asarray(scores)[np.asarray(y_true) == 0])
    if len(neg) == 0:
        return 1.0
    k = int(np.ceil((1 - fpr) * len(neg))) - 1
    return float(np.nextafter(neg[min(max(k, 0), len(neg) - 1)], np.inf))


def operating_point(y_true, scores, threshold: float, prevalence: float | None = None) -> dict:
    """Recall / FPR / precision at a fixed threshold.

    Precision depends on class balance. `precision` uses the evaluation set's own balance;
    `precision_at_prevalence` re-weights to an assumed real-world malicious share, which is
    the number a Trust & Safety team actually cares about.
    """
    y, s = np.asarray(y_true), np.asarray(scores)
    flagged = s >= threshold
    tp, fp = int((flagged & (y == 1)).sum()), int((flagged & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    tpr = tp / pos if pos else float("nan")
    fpr = fp / neg if neg else float("nan")
    out = {"threshold": float(threshold), "recall": tpr, "fpr": fpr,
           "precision": tp / (tp + fp) if (tp + fp) else float("nan")}
    if prevalence is not None and neg and pos:
        out["precision_at_prevalence"] = (tpr * prevalence) / (
            tpr * prevalence + fpr * (1 - prevalence)) if (tpr * prevalence + fpr * (1 - prevalence)) else float("nan")
    return out


def evaluate(y_true, scores, threshold: float, prevalence: float = 0.01) -> dict:
    y = np.asarray(y_true)
    m = {"n": int(len(y)), "n_pos": int(y.sum()),
         "roc_auc": float(roc_auc_score(y, scores)) if 0 < y.sum() < len(y) else float("nan"),
         "pr_auc": float(average_precision_score(y, scores)) if y.sum() else float("nan")}
    m.update(operating_point(y, scores, threshold, prevalence))
    return m
