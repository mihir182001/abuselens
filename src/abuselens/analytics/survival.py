"""Takedown survival analysis on URLhaus lifetimes (right-censored: still-online URLs)."""
from __future__ import annotations

import pandas as pd
from lifelines import CoxPHFitter, KaplanMeierFitter
from lifelines.statistics import multivariate_logrank_test


def load(con) -> pd.DataFrame:
    df = con.execute("SELECT * FROM stg_takedown WHERE lifetime_hours IS NOT NULL").df()
    df["lifetime_hours"] = df["lifetime_hours"].clip(lower=0.01)
    return df


KM_COLUMNS = ["group", "n", "n_taken_down", "median_hours", "survival_24h", "survival_7d",
              "ci_lower_7d", "ci_upper_7d"]


def kaplan_meier(df: pd.DataFrame, group_col: str | None = None, min_n: int = 30) -> pd.DataFrame:
    """Median time-to-takedown (hours) overall or per group, with 95% CI."""
    groups = [("all", df)] if group_col is None else [
        (g, d) for g, d in df.groupby(group_col) if len(d) >= min_n]
    rows = []
    for name, d in groups:
        km = KaplanMeierFitter().fit(d["lifetime_hours"], d["taken_down"])
        ci = km.confidence_interval_survival_function_
        rows.append({"group": name, "n": len(d), "n_taken_down": int(d["taken_down"].sum()),
                     "median_hours": float(km.median_survival_time_),
                     "survival_24h": float(km.predict(24)), "survival_7d": float(km.predict(168)),
                     "ci_lower_7d": float(ci.iloc[:, 0].asof(168)) if len(ci) else None,
                     "ci_upper_7d": float(ci.iloc[:, 1].asof(168)) if len(ci) else None})
    if not rows:  # e.g. no host has >= min_n URLs yet
        return pd.DataFrame(columns=KM_COLUMNS)
    return pd.DataFrame(rows).sort_values("median_hours", ascending=False).reset_index(drop=True)


def logrank_p(df: pd.DataFrame, group_col: str, min_n: int = 30) -> float:
    d = df.groupby(group_col).filter(lambda x: len(x) >= min_n)
    if d[group_col].nunique() < 2:
        return float("nan")
    return float(multivariate_logrank_test(d["lifetime_hours"], d[group_col], d["taken_down"]).p_value)


def cox_by_host(df: pd.DataFrame, top_n: int = 10, min_n: int = 30) -> pd.DataFrame:
    """Cox PH hazard ratios for the most-abused hosts vs. everyone else.

    HR < 1 => URLs on that host are taken down *more slowly* than the baseline.
    """
    counts = df["host"].value_counts()
    top = [h for h in counts.index if counts[h] >= min_n][:top_n]
    if not top:
        return pd.DataFrame(columns=["host", "hazard_ratio", "ci_lower", "ci_upper", "p"])
    X = pd.DataFrame({f"h_{i}": (df["host"] == h).astype(int) for i, h in enumerate(top)})
    X["lifetime_hours"], X["taken_down"] = df["lifetime_hours"], df["taken_down"]
    cph = CoxPHFitter(penalizer=0.01).fit(X, "lifetime_hours", "taken_down")
    s = cph.summary
    return pd.DataFrame({
        "host": top, "hazard_ratio": s["exp(coef)"].values,
        "ci_lower": s["exp(coef) lower 95%"].values, "ci_upper": s["exp(coef) upper 95%"].values,
        "p": s["p"].values}).sort_values("hazard_ratio").reset_index(drop=True)
