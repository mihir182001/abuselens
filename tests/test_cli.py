"""End-to-end: the exact commands the GitHub workflows run, against an on-disk warehouse."""
from abuselens import cli, config, db

from .conftest import populate


def test_cli_marts_train_monitor_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "w.duckdb")
    monkeypatch.setattr(config, "MODEL_DIR", tmp_path / "models")
    monkeypatch.setattr(config, "REPORT_DIR", tmp_path / "reports")
    con = db.connect()
    populate(con)
    con.close()

    assert cli.main(["marts"]) == 0
    assert cli.main(["train"]) == 0
    assert cli.main(["monitor"]) == 0
    assert cli.main(["report"]) == 0

    briefs = list((tmp_path / "reports").glob("risk_brief_*.md"))
    assert len(briefs) == 1
    text = briefs[0].read_text(encoding="utf-8")
    assert "Most impersonated brands" in text and "Takedown speed" in text and "Detection model" in text
    assert (tmp_path / "models" / "champion" / "meta.json").exists()
