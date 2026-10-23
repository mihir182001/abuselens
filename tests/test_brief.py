import numpy as np
import pandas as pd

from abuselens.reporting import brief


def test_add_wow_when_no_previous_week_exists():
    vol = pd.DataFrame({"abuse_type": ["malware_download", "phishing"], "urls_7d": [900, 50]})
    empty_prior = pd.DataFrame({"abuse_type": pd.Series([], dtype=object),
                                "urls_prev_7d": pd.Series([], dtype="int64")})
    out = brief.add_wow(vol, empty_prior)
    assert out.wow_change.isna().all() and (out.urls_prev_7d == 0).all()
    assert out.wow_change.dtype == float


def test_add_wow_mixed():
    vol = pd.DataFrame({"abuse_type": ["a", "b"], "urls_7d": [150, 10]})
    prior = pd.DataFrame({"abuse_type": ["a"], "urls_prev_7d": [100]})
    out = brief.add_wow(vol, prior).set_index("abuse_type")
    assert out.loc["a", "wow_change"] == 0.5 and np.isnan(out.loc["b", "wow_change"])
