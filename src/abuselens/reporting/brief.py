"""Weekly auto-generated risk brief (markdown), written for product/policy stakeholders."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import numpy as np
import pandas as pd

from .. import config
from ..analytics import survival


def _md(df: pd.DataFrame, n: int = 10) -> str:
    if not len(df):
        return "_no data_"
    out = df.head(n).copy()
    for col in out.columns:
        if out[col].dtype.kind == "f" and np.isinf(out[col]).any():
            # inf = median not reached: fewer than half were taken down within the observation window
            out[col] = out[col].astype(object).where(~np.isinf(out[col]), "not reached")
    return out.to_markdown(index=False)


def add_wow(vol: pd.DataFrame, prior: pd.DataFrame) -> pd.DataFrame:
    """Attach the previous week's count and the week-over-week change (NaN when no prior week)."""
    out = vol.merge(prior, on="abuse_type", how="left")
    out["urls_7d"] = out["urls_7d"].astype(float)
    out["urls_prev_7d"] = out["urls_prev_7d"].astype(float).fillna(0.0)
    base = out["urls_prev_7d"].where(out["urls_prev_7d"] > 0)
    out["wow_change"] = ((out["urls_7d"] - out["urls_prev_7d"]) / base).round(2)
    return out


def build(con, model_meta: dict | None = None, monitor: dict | None = None) -> str:
    today = dt.date.today()
    vol = con.execute("""
        SELECT abuse_type, count(*) AS urls_7d FROM stg_malicious_urls
        WHERE event_ts >= (SELECT max(event_ts) FROM stg_malicious_urls) - INTERVAL 7 DAY
        GROUP BY 1 ORDER BY 2 DESC""").df()
    prior = con.execute("""
        SELECT abuse_type, count(*) AS urls_prev_7d FROM stg_malicious_urls
        WHERE event_ts < (SELECT max(event_ts) FROM stg_malicious_urls) - INTERVAL 7 DAY
          AND event_ts >= (SELECT max(event_ts) FROM stg_malicious_urls) - INTERVAL 14 DAY
        GROUP BY 1""").df()
    vol = add_wow(vol, prior)

    brands = con.execute("""SELECT brand, n_urls FROM brand_targets
        WHERE month = (SELECT max(month) FROM brand_targets) ORDER BY n_urls DESC""").df()
    tlds = con.execute("SELECT tld, sum(n_urls) AS n_urls FROM tld_abuse GROUP BY 1 ORDER BY 2 DESC").df()
    camps = con.execute("""SELECT host, path_shape, n_urls, active_days, first_seen
        FROM campaigns ORDER BY n_urls DESC""").df()

    lines = [f"# AbuseLens weekly risk brief — {today:%d %b %Y}", "",
             "## Headline", ""]
    if len(vol):
        top = vol.iloc[0]
        lines.append(f"- **{top.abuse_type}** is the largest abuse category: {int(top.urls_7d):,} new URLs "
                     f"in the last 7 days.")
    if len(brands):
        lines.append(f"- Most impersonated brand this month: **{brands.iloc[0].brand}** "
                     f"({int(brands.iloc[0].n_urls)} phishing URLs).")
    if len(camps):
        lines.append(f"- Largest active campaign: {int(camps.iloc[0].n_urls)} URLs on "
                     f"`{camps.iloc[0].host}` sharing one URL template.")
    try:
        td = survival.load(con)
        if len(td) > 30:
            km = survival.kaplan_meier(td)
            lines.append(f"- Median malware-URL lifetime: **{km.iloc[0].median_hours:.0f} hours**; "
                         f"{km.iloc[0].survival_7d:.0%} are still live after 7 days.")
    except Exception:
        td = None
    lines += ["", "## Volume by abuse type (7d vs previous 7d)", "", _md(vol),
              "", "## Most impersonated brands (current month)", "", _md(brands),
              "", "## Most abused TLDs", "", _md(tlds),
              "", "## Largest campaigns", "", _md(camps, 8)]

    if td is not None and len(td) > 30:
        lines += ["", "## Takedown speed (Kaplan–Meier)", "",
                  "Hosts ranked by slowest median time-to-takedown (≥30 URLs each; censored URLs "
                  "handled correctly):", "",
                  _md(survival.kaplan_meier(td, "host").round(3), 8)]

    if model_meta:
        m = model_meta["metrics"]
        lines += ["", "## Detection model", "",
                  f"- Decision: {model_meta.get('decision')}",
                  f"- Trained on {model_meta['train_range'][0][:10]} → {model_meta['train_range'][1][:10]}; "
                  f"tested on later data {model_meta['test_range'][0][:10]} → {model_meta['test_range'][1][:10]}",
                  f"- PR-AUC {m['pr_auc']:.3f}, ROC-AUC {m['roc_auc']:.3f}",
                  f"- At the frozen threshold: recall {m['recall']:.1%}, FPR {m['fpr']:.2%}",
                  f"- Precision at assumed {model_meta['assumed_prevalence']:.0%} real-world prevalence: "
                  f"{m.get('precision_at_prevalence', float('nan')):.1%}"]
    if monitor:
        lines += ["", "## Monitoring", ""]
        lines += [f"- ⚠️ {a}" for a in monitor["alerts"]] or ["- No drift or decay alerts."]
        lines += [f"- Drift not assessed for {s}" for s in monitor.get("drift_skipped", [])]
        if len(monitor["decay"]):
            lines += ["", _md(monitor["decay"].round(3), 12)]
    lines += ["", "---", "_Data: abuse.ch URLhaus, OpenPhish, PhishTank, Tranco, Common Crawl. "
              "Auto-generated by AbuseLens._"]
    return "\n".join(lines)


def write(text: str, out_dir: Path | None = None) -> Path:
    out_dir = Path(out_dir or config.REPORT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"risk_brief_{dt.date.today():%Y-%m-%d}.md"
    p.write_text(text, encoding="utf-8")
    return p
