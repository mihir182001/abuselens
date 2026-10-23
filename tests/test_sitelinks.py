from abuselens.ingest import sitelinks

HTML = """<a href="/news/story-1">a</a> <a href="https://www.example.com/shop?id=3">b</a>
<a href="/">home</a> <a href="/logo.png">img</a> <a href="https://other.org/x">ext</a>
<a href="mailto:a@b.c">m</a> <a href="/news/story-1#top">dup</a> <a href="/about">c</a>"""


def test_extract_links_keeps_same_site_paths_only():
    out = sitelinks.extract_links(HTML, "https://example.com/", 10)
    assert out == ["https://example.com/news/story-1", "https://www.example.com/shop?id=3",
                   "https://example.com/about"]


def test_extract_links_limit_and_garbage():
    assert len(sitelinks.extract_links(HTML, "https://example.com/", 2)) == 2
    assert sitelinks.extract_links("<<<not html", "https://example.com/", 5) == []
