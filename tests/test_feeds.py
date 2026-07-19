from threat_digest.feeds import FeedEntry, fetch_feed_entries

SAMPLE_FEED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>Test Feed</title>
<item>
<title>Critical RCE Found in Example Software</title>
<link>https://example.com/article-1</link>
<description>A critical remote code execution vulnerability was discovered.</description>
</item>
<item>
<title>Second Article About Patches</title>
<link>https://example.com/article-2</link>
<description>Vendor releases patches for several issues.</description>
</item>
<item>
<link>https://example.com/article-no-title</link>
<description>This entry has no title and should be skipped.</description>
</item>
<item>
<title>Third Article</title>
<link>https://example.com/article-3</link>
<description>Some other summary text.</description>
</item>
</channel>
</rss>
"""


def test_fetch_feed_entries_parses_title_url_summary():
    entries = fetch_feed_entries(SAMPLE_FEED_XML, max_entries=10)
    assert entries[0] == FeedEntry(
        title="Critical RCE Found in Example Software",
        url="https://example.com/article-1",
        summary="A critical remote code execution vulnerability was discovered.",
    )


def test_fetch_feed_entries_skips_entries_missing_title_or_link():
    entries = fetch_feed_entries(SAMPLE_FEED_XML, max_entries=10)
    urls = [e.url for e in entries]
    assert "https://example.com/article-no-title" not in urls
    assert len(entries) == 3


def test_fetch_feed_entries_respects_max_entries_cap():
    entries = fetch_feed_entries(SAMPLE_FEED_XML, max_entries=2)
    assert len(entries) == 2
