"""Central configuration. Everything is overridable by environment variable."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL_DIR = Path(os.environ.get("ABUSELENS_SQL_DIR", ROOT / "sql"))
DB_PATH = Path(os.environ.get("ABUSELENS_DB", ROOT / "data" / "abuselens.duckdb"))
MODEL_DIR = Path(os.environ.get("ABUSELENS_MODEL_DIR", ROOT / "data" / "models"))
REPORT_DIR = Path(os.environ.get("ABUSELENS_REPORT_DIR", ROOT / "data" / "reports"))

USER_AGENT = "abuselens/0.1 (research; trust-and-safety analytics)"

URLHAUS_CSV = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHTANK_URL = "http://data.phishtank.com/data/{key}/online-valid.csv"
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"
COMMONCRAWL_COLLINFO = "https://index.commoncrawl.org/collinfo.json"

# Optional credentials (abuse.ch now asks for a free Auth-Key on some endpoints).
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY")
PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY")

# Safe-example sampling. Taking safe URLs only from the *lower* part of the Tranco
# ranking (not the top 1k) prevents the model learning "unpopular domain == malicious".
SAFE_RANK_MIN = int(os.environ.get("SAFE_RANK_MIN", 1_000))
SAFE_RANK_MAX = int(os.environ.get("SAFE_RANK_MAX", 1_000_000))
SAFE_DOMAINS_PER_DAY = int(os.environ.get("SAFE_DOMAINS_PER_DAY", 600))
CC_TIME_BUDGET_S = int(os.environ.get("CC_TIME_BUDGET_S", "300"))
CC_URLS_PER_DOMAIN = int(os.environ.get("CC_URLS_PER_DOMAIN", 3))

# Data-quality thresholds
MIN_ROWS = {"urlhaus": 50, "openphish": 20, "phishtank": 20, "tranco": 100_000}
VOLUME_DROP_RATIO = 0.5       # alert if today's rows < 50% of trailing 7-day median
FRESHNESS_MAX_AGE_HOURS = 72  # alert if newest record in a feed is older than this
