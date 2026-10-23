from abuselens.features.lexical import FEATURE_NAMES, build_frame, url_features


def test_ip_host_and_port():
    f = url_features("http://185.10.20.30:8080/bin/x86.sh")
    assert f["is_ip_host"] == 1 and f["has_port"] == 1 and f["has_exec_ext"] == 1


def test_brand_impersonation_flagged():
    f = url_features("https://paypal-secure-login.xyz/verify/account")
    assert f["brand_mismatch"] == 1 and f["brand_in_host"] == 1 and f["cheap_tld"] == 1


def test_legit_brand_domain_not_flagged():
    f = url_features("https://www.paypal.com/signin")
    assert f["brand_mismatch"] == 0 and f["brand_in_host"] == 0


def test_scheme_less_and_garbage_do_not_crash():
    assert url_features("example.com/path")["host_len"] == len("example.com")
    assert set(url_features("http://[bad")) == set(FEATURE_NAMES)


def test_build_frame_shape():
    df = build_frame(["http://a.com/", "https://b.org/x?y=1"])
    assert df.shape == (2, len(FEATURE_NAMES))
