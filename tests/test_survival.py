import pandas as pd

from abuselens.analytics import survival


def test_kaplan_meier_empty_when_no_group_is_large_enough():
    df = pd.DataFrame({"host": [f"h{i}" for i in range(50)], "lifetime_hours": range(1, 51),
                       "taken_down": [1] * 50})
    out = survival.kaplan_meier(df, "host", min_n=30)
    assert out.empty and list(out.columns) == survival.KM_COLUMNS


def test_cox_and_logrank_handle_no_large_hosts():
    df = pd.DataFrame({"host": [f"h{i}" for i in range(50)], "lifetime_hours": range(1, 51),
                       "taken_down": [1] * 50})
    assert survival.cox_by_host(df).empty
