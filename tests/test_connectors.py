import pandas as pd

from abuselens import config
from abuselens.ingest import commoncrawl, openphish, phishtank, tranco, urlhaus

URLHAUS = '''################################
# abuse.ch URLhaus Database Dump
################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-10-20 10:00:00","http://1.2.3.4:8080/bin/x86.sh","offline","2026-10-20 18:00:00","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/1/","bot"
"2","2026-10-21 01:00:00","http://evil.example/a.exe","online","2026-10-21 02:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/2/","bot"
'''


def test_urlhaus_parse():
    df = urlhaus.parse(URLHAUS)
    assert len(df) == 2
    assert df.url_status.tolist() == ["offline", "online"]
    assert df.date_added.iloc[0] == pd.Timestamp("2026-10-20 10:00:00")
    assert df.tags.iloc[0] == "elf,mirai"


def test_openphish_parse():
    df = openphish.parse("https://a.example/login\n\nnot-a-url\nhttp://b.example/x\n")
    assert df.url.tolist() == ["https://a.example/login", "http://b.example/x"]


def test_phishtank_parse():
    csv = ("phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,details,target\n"
           "9,http://p.example/x,u,2026-10-20T10:00:00+00:00,yes,t,yes,d,PayPal\n")
    df = phishtank.parse(csv)
    assert df.target.iloc[0] == "PayPal" and df.submission_time.iloc[0].year == 2026


def test_tranco_safe_sampling_excludes_head(monkeypatch):
    monkeypatch.setattr(config, "SAFE_RANK_MIN", 1000)
    monkeypatch.setattr(config, "SAFE_RANK_MAX", 5000)
    tr = tranco.parse_csv("\n".join(f"{i},site{i}.com" for i in range(1, 6001)))
    s = tranco.sample_safe_domains(tr, 200, seed=1)
    assert s["rank"].between(1000, 5000).all()      # no top-1k popularity shortcut
    assert len(s) == 200


def test_commoncrawl_cdx_parse():
    text = ('{"url": "https://a.com/x", "status": "200"}\n'
            '{"url": "https://a.com/y", "status": "404"}\nnot json\n'
            '{"url": "https://a.com/z", "status": "200"}\n')
    assert commoncrawl.parse_cdx(text, 5) == ["https://a.com/x", "https://a.com/z"]


def test_urlhaus_parse_plain_header_row():
    text = ('id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
            '"1","2026-10-20 10:00:00","http://1.2.3.4/a.sh","online","","malware_download","elf","l","r"\n')
    df = urlhaus.parse(text)
    assert df.url.tolist() == ["http://1.2.3.4/a.sh"] and df.url_status.iloc[0] == "online"
