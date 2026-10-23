"""Run from the folder containing pyproject.toml:  python fix_urlhaus.py
Switches URLhaus to abuse.ch's new Auth-Key download URL. Safe to run twice."""
from pathlib import Path

root = Path.cwd()
if not (root / "pyproject.toml").exists():
    raise SystemExit("Run this from the folder that contains pyproject.toml")

cfg = root / "src/abuselens/config.py"
t = cfg.read_text(encoding="utf-8")
t = t.replace('URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"',
              'URLHAUS_CSV = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"')
cfg.write_text(t, encoding="utf-8", newline="")

NEW = '"""abuse.ch URLhaus: malware-distribution URLs with added-date, online status, threat, tags.\n\nabuse.ch now requires a free Auth-Key (https://auth.abuse.ch/) placed in the download URL.\n"""\nfrom __future__ import annotations\n\nimport io\n\nimport pandas as pd\n\nfrom .. import config\nfrom . import http\n\nDEFAULT_COLUMNS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags",\n                   "urlhaus_link", "reporter"]\n\n\ndef _split_header(text: str) -> tuple[list[str], str]:\n    """Find column names whether they are a \'# id,dateadded,...\' comment or a plain header row."""\n    cols, body = None, []\n    for ln in text.splitlines():\n        s = ln.strip()\n        if not s:\n            continue\n        if s.startswith("#"):\n            cand = [c.strip().strip(\'"\') for c in s.lstrip("#").strip().split(",")]\n            if "dateadded" in cand and "url" in cand:\n                cols = cand\n            continue\n        if cols is None and "dateadded" in s and "url" in s and not s.lower().startswith((\'"http\', "http")):\n            cols = [c.strip().strip(\'"\') for c in s.split(",")]\n            continue\n        body.append(ln)\n    return cols or DEFAULT_COLUMNS, "\\n".join(body)\n\n\ndef parse(text: str) -> pd.DataFrame:\n    cols, body = _split_header(text)\n    df = pd.read_csv(io.StringIO(body), names=cols, header=None, quotechar=\'"\',\n                     skipinitialspace=True, dtype=str, index_col=False)\n    for c in ("url_status", "last_online", "threat", "tags", "reporter"):\n        if c not in df:\n            df[c] = None\n    out = pd.DataFrame({\n        "url": df["url"].str.strip(),\n        "date_added": pd.to_datetime(df["dateadded"], errors="coerce", utc=True).dt.tz_localize(None),\n        "url_status": df["url_status"].str.lower(),\n        "last_online": pd.to_datetime(df["last_online"], errors="coerce", utc=True).dt.tz_localize(None),\n        "threat": df["threat"],\n        "tags": df["tags"].fillna(""),\n        "reporter": df["reporter"],\n    })\n    return out.dropna(subset=["url"])\n\n\ndef fetch() -> pd.DataFrame:\n    if not config.ABUSECH_AUTH_KEY:\n        raise RuntimeError("ABUSECH_AUTH_KEY not set. Get a free key at https://auth.abuse.ch/ "\n                           "then: $env:ABUSECH_AUTH_KEY=\\"your_key\\"")\n    return parse(http.get(config.URLHAUS_CSV.format(key=config.ABUSECH_AUTH_KEY)).text)\n'
(root / "src/abuselens/ingest/urlhaus.py").write_text(NEW, encoding="utf-8", newline="")
print("patched config.py and urlhaus.py")
