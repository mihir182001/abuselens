"""Lexical + brand-impersonation features computed from the URL string alone.

Everything here is computable at request time with no network calls, so the same code path
serves training and the /score API (no train/serve skew).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import pandas as pd
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # bundled snapshot: never hits the network

# Brand -> legitimate registered domains. Extend freely; used for impersonation signals.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"}, "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"}, "google": {"google.com", "gmail.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"}, "facebook": {"facebook.com"},
    "instagram": {"instagram.com"}, "netflix": {"netflix.com"}, "dhl": {"dhl.com"},
    "fedex": {"fedex.com"}, "usps": {"usps.com"}, "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"}, "bankofamerica": {"bankofamerica.com"},
    "citi": {"citi.com", "citibank.com"}, "hsbc": {"hsbc.com"}, "sbi": {"sbi.co.in"},
    "hdfc": {"hdfcbank.com"}, "icici": {"icicibank.com"}, "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"}, "dropbox": {"dropbox.com"}, "adobe": {"adobe.com"},
    "coinbase": {"coinbase.com"}, "binance": {"binance.com"}, "metamask": {"metamask.io"},
    "outlook": {"outlook.com", "live.com"}, "docusign": {"docusign.com", "docusign.net"},
}

SUSPICIOUS_WORDS = ["login", "signin", "verify", "secure", "account", "update", "bank",
                    "wallet", "confirm", "password", "invoice", "billing", "support", "free"]
EXECUTABLE_EXT = (".exe", ".dll", ".zip", ".rar", ".sh", ".apk", ".bin", ".msi", ".scr",
                  ".jar", ".ps1", ".bat", ".7z", ".iso")
# A prior, not a label: TLDs widely reported as cheap/abused. The model decides the weight.
CHEAP_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "click", "cyou", "buzz",
              "rest", "monster", "sbs", "cfd", "live", "shop", "site", "online"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

FEATURE_NAMES: list[str] = []  # filled below


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def url_features(url: str) -> dict[str, float]:
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").lower()
        port = sp.port
    except ValueError:
        sp, host, port = urlsplit("http://invalid/"), "", None
    path, query = sp.path or "", sp.query or ""
    ext = _EXTRACT(host)
    reg_domain = ".".join(p for p in (ext.domain, ext.suffix) if p)
    subdomain_parts = [p for p in ext.subdomain.split(".") if p]
    low = u.lower()

    f: dict[str, float] = {
        "url_len": len(u), "host_len": len(host), "path_len": len(path), "query_len": len(query),
        "n_dots_host": host.count("."), "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": sum(c.isdigit() for c in u) / max(len(u), 1),
        "n_subdomains": len(subdomain_parts),
        "is_ip_host": float(bool(_IPV4.match(host))),
        "has_port": float(port is not None and port not in (80, 443)),
        "has_at": float("@" in sp.netloc), "is_https": float(sp.scheme == "https"),
        "host_entropy": _entropy(host), "path_entropy": _entropy(path),
        "n_path_segments": len([s for s in path.split("/") if s]),
        "n_query_params": len([p for p in query.split("&") if p]),
        "max_token_len": max((len(t) for t in re.split(r"[^A-Za-z0-9]+", u)), default=0),
        "has_exec_ext": float(path.lower().endswith(EXECUTABLE_EXT)),
        "cheap_tld": float(ext.suffix.split(".")[-1] in CHEAP_TLDS),
        "n_suspicious_words": sum(w in low for w in SUSPICIOUS_WORDS),
        "has_double_slash_path": float("//" in path),
    }

    # Brand impersonation: brand token appears but registered domain isn't the brand's own.
    host_tokens = re.split(r"[^a-z0-9]+", host)
    in_host = in_path = mismatch = 0
    for brand, legit in BRANDS.items():
        host_hit = brand in host
        path_hit = brand in (path + "?" + query).lower()
        if (host_hit or path_hit) and reg_domain not in legit:
            mismatch = 1
        in_host |= host_hit and reg_domain not in legit
        in_path |= path_hit and reg_domain not in legit
    f.update({"brand_in_host": float(in_host), "brand_in_path": float(in_path),
              "brand_mismatch": float(mismatch),
              "n_host_tokens": len([t for t in host_tokens if t])})
    return f


FEATURE_NAMES = list(url_features("http://example.com/").keys())

ENRICHMENT_FEATURES = ["domain_age_days", "cert_count"]


def build_frame(urls: list[str] | pd.Series) -> pd.DataFrame:
    return pd.DataFrame([url_features(u) for u in urls], columns=FEATURE_NAMES)
