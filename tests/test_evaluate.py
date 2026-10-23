from abuselens.models import evaluate, train


def test_by_type_and_importances(warehouse):
    df = train.load_dataset(warehouse)
    assert {"safe", "phishing", "malware_download"} <= set(df.abuse_type)
    tr, va, te = train.time_split(df)
    bundle = train.fit(tr, va, train.feature_columns(df))
    out = evaluate.by_type(bundle, te)
    assert out.iloc[0].slice.startswith("safe") and {"phishing", "malware_download"} <= set(out.slice)
    imp = evaluate.importances(bundle)
    assert abs(imp.share.sum() - 1.0) < 1e-6 or imp.share.sum() < 1.0 + 1e-9
    assert len(imp) > 0


def test_host_split_is_host_disjoint_and_covers_all_types(warehouse):
    df = train.load_dataset(warehouse)
    tr, va, te = evaluate.host_split(df)
    assert not (set(tr.host) & set(te.host)) and not (set(tr.host) & set(va.host)) \
        and not (set(va.host) & set(te.host))
    assert len(tr) + len(va) + len(te) == len(df)
    for part in (tr, va, te):
        assert {"safe", "phishing", "malware_download"} <= set(part.abuse_type)


def test_strict_report_runs(warehouse):
    res, imp, sizes = evaluate.strict_report(train.load_dataset(warehouse))
    assert sizes["hosts_shared_train_test"] == 0 and len(res) == 3 and len(imp) > 0
