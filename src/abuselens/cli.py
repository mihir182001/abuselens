"""`abuselens` command line: ingest | marts | enrich | train | monitor | report."""
from __future__ import annotations

import argparse
import logging
import sys

from . import config, db
from .ingest import runner

ALL_SOURCES = ["urlhaus", "openphish", "phishtank", "tranco", "commoncrawl", "sitelinks"]


def cmd_ingest(a):
    con = db.connect()
    sources = ALL_SOURCES if a.all else a.sources
    res = runner.run(con, sources)
    for k, ok in res.items():
        print(f"{k:10s} {'ok' if ok else 'FAILED (see ingest_log)'}")
    return 0 if all(res.values()) else 1


def cmd_marts(a):
    con = db.connect()
    for sub in ("staging", "marts"):
        print(sub, db.run_sql_dir(con, sub))
    return 0


def cmd_enrich(a):
    from .enrich.context import enrich_domains
    con = db.connect()
    hosts = [r[0] for r in con.execute("""
        SELECT host FROM (SELECT host FROM stg_malicious_urls UNION ALL SELECT host FROM stg_safe_urls)
        WHERE host NOT SIMILAR TO '[0-9.]+' AND host <> ''
          AND host NOT IN (SELECT domain FROM raw_enrichment)
        GROUP BY host ORDER BY random() LIMIT ?""", [a.max]).fetchall()]
    df = enrich_domains(hosts, max_n=a.max)
    con.register("_e", df)
    con.execute("INSERT INTO raw_enrichment SELECT * FROM _e")
    print(f"enriched {len(df)} domains")
    return 0


def cmd_train(a):
    from .models import train
    con = db.connect()
    db.run_sql_dir(con, "staging")
    meta = train.train_and_promote(con)
    m = meta["metrics"]
    print(f"{meta['decision']} | PR-AUC {m['pr_auc']:.3f} ROC-AUC {m['roc_auc']:.3f} "
          f"recall {m['recall']:.2%} FPR {m['fpr']:.2%}")
    return 0


def _monitor(con):
    from .models import train
    from .monitoring import drift
    bundle, meta = train.load(config.MODEL_DIR / "champion")
    return drift.run(con, bundle, trained_through=meta["train_range"][1], fit_cutoffs=meta.get("fit_cutoffs"))


def cmd_evaluate(a):
    from .models import evaluate, train
    con = db.connect()
    db.run_sql_dir(con, "staging")
    if a.strict:
        res, imp, sizes = evaluate.strict_report(train.load_dataset(con))
        print("STRICT host-disjoint evaluation (fresh model; the saved champion is untouched)")
        print(f"sizes: {sizes}\n")
        print(res.round(4).to_string(index=False))
        print("\nTop features by share of total gain:")
        print(imp.round(4).to_string(index=False))
        return 0
    bundle, meta = train.load(config.MODEL_DIR / "champion")
    _, _, test = train.time_split(train.load_dataset(con))
    print(f"Held-out test slice: {len(test)} URLs; frozen threshold {bundle['threshold']:.3f}\n")
    print(evaluate.by_type(bundle, test).round(4).to_string(index=False))
    print("\nTop features by share of total gain:")
    print(evaluate.importances(bundle).round(4).to_string(index=False))
    return 0


def cmd_monitor(a):
    con = db.connect()
    res = _monitor(con)
    print(res["decay"].round(3).to_string(index=False))
    for al in res["alerts"] or ["no alerts"]:
        print("-", al)
    return 0


def cmd_report(a):
    import json

    from .reporting import brief
    con = db.connect()
    for sub in ("staging", "marts"):
        db.run_sql_dir(con, sub)
    meta_path = config.MODEL_DIR / "champion" / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else None
    try:
        mon = _monitor(con) if meta else None
    except Exception:
        mon = None
    print(brief.write(brief.build(con, meta, mon)))
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    p = argparse.ArgumentParser(prog="abuselens")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ingest")
    s.add_argument("--all", action="store_true")
    s.add_argument("--sources", nargs="*", default=[], choices=ALL_SOURCES)
    s.set_defaults(fn=cmd_ingest)
    sub.add_parser("marts").set_defaults(fn=cmd_marts)
    s = sub.add_parser("enrich")
    s.add_argument("--max", type=int, default=200)
    s.set_defaults(fn=cmd_enrich)
    sub.add_parser("train").set_defaults(fn=cmd_train)
    sub.add_parser("monitor").set_defaults(fn=cmd_monitor)
    s = sub.add_parser("evaluate")
    s.add_argument("--strict", action="store_true", help="host-disjoint split with a freshly trained model")
    s.set_defaults(fn=cmd_evaluate)
    sub.add_parser("report").set_defaults(fn=cmd_report)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
