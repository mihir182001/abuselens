"""Run once from the folder that contains pyproject.toml:  python fix_windows_encoding.py
Makes every text read/write use UTF-8 (Windows defaults to cp1252 and crashes on '≥').
Safe to run twice."""
from pathlib import Path

EDITS = {
    "dashboard/app.py": [("p.read_text()", 'p.read_text(encoding="utf-8")'), ("import pandas as pd\n", "")],
    "src/abuselens/db.py": [("f.read_text()", 'f.read_text(encoding="utf-8")')],
    "tests/test_cli.py": [("briefs[0].read_text()", 'briefs[0].read_text(encoding="utf-8")')],
    "src/abuselens/models/train.py": [
        ("write_text(json.dumps(meta, indent=2, default=str))",
         'write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")'),
        ('(path / "meta.json").read_text()', '(path / "meta.json").read_text(encoding="utf-8")')],
    "src/abuselens/reporting/brief.py": [("p.write_text(text)", 'p.write_text(text, encoding="utf-8")')],
    "src/abuselens/cli.py": [("meta_path.read_text()", 'meta_path.read_text(encoding="utf-8")')],
}
root = Path.cwd()
if not (root / "pyproject.toml").exists():
    raise SystemExit("Run this from the folder that contains pyproject.toml")
for rel, pairs in EDITS.items():
    p = root / rel
    text = p.read_text(encoding="utf-8")
    for old, new in pairs:
        text = text.replace(old, new)
    p.write_text(text, encoding="utf-8", newline="")
    print("patched", rel)
