"""Per-prediction reasons from XGBoost's native SHAP-style contributions."""
from __future__ import annotations

import numpy as np
import pandas as pd
import xgboost as xgb

HUMAN = {
    "is_ip_host": "host is a raw IP address", "has_port": "non-standard port",
    "brand_mismatch": "brand name used on a domain the brand doesn't own",
    "brand_in_host": "brand name inside the hostname", "brand_in_path": "brand name inside the path",
    "has_exec_ext": "links directly to an executable/archive", "cheap_tld": "TLD commonly abused",
    "n_suspicious_words": "credential/account lure words", "host_entropy": "random-looking hostname",
    "url_len": "very long URL", "n_hyphens_host": "many hyphens in hostname",
    "n_subdomains": "deep subdomain nesting", "max_token_len": "long random-looking token",
    "domain_age_days": "very new domain", "cert_count": "unusual TLS certificate history",
    "digit_ratio_url": "high share of digits", "path_entropy": "random-looking path",
    "is_https": "scheme/TLS usage pattern",
}


def top_reasons(bundle: dict, row: pd.DataFrame, k: int = 3) -> list[dict]:
    cols = bundle["features"]
    booster = bundle["model"].get_booster()
    contrib = booster.predict(xgb.DMatrix(row[cols], feature_names=cols), pred_contribs=True)[0][:-1]
    order = np.argsort(-np.abs(contrib))[:k]
    return [{"feature": cols[i], "value": None if pd.isna(row[cols[i]].iloc[0]) else float(row[cols[i]].iloc[0]),
             "pushes": "malicious" if contrib[i] > 0 else "benign",
             "contribution": round(float(contrib[i]), 3),
             "description": HUMAN.get(cols[i], cols[i].replace("_", " "))} for i in order]
