import pytest

from threat_digest import ingest
from threat_digest.corpus import load_corpus
from threat_digest.seen import load_seen_urls

SAMPLE_FEED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>Test Feed</title>
<item>
<title>Critical RCE Found in Example Software</title>
<link>https://example.com/article-1</link>
<description>A critical remote code execution vulnerability was discovered.</description>
</item>
</channel>
</rss>
"""


def test_slugify_lowercases_and_replaces_non_alphanumeric():
    assert (
        ingest.slugify("Critical RCE Found in Example Software!")
        == "critical-rce-found-in-example-software"
    )


def test_run_ingest_writes_new_entries_and_marks_seen(tmp_path):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"

    written = ingest.run_ingest([SAMPLE_FEED_XML], corpus_dir, seen_path)

    assert len(written) == 1
    content = written[0].read_text(encoding="utf-8")
    assert "TITLE: Critical RCE Found in Example Software" in content
    assert "SOURCE: https://example.com/article-1" in content
    assert "A critical remote code execution vulnerability was discovered." in content
    assert "https://example.com/article-1" in load_seen_urls(seen_path)


def test_run_ingest_skips_already_seen_urls(tmp_path):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"

    first_run = ingest.run_ingest([SAMPLE_FEED_XML], corpus_dir, seen_path)
    second_run = ingest.run_ingest([SAMPLE_FEED_XML], corpus_dir, seen_path)

    assert len(first_run) == 1
    assert len(second_run) == 0


def test_run_ingest_continues_past_a_feed_that_fails_to_fetch(tmp_path, monkeypatch):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"

    real_fetch = ingest.fetch_feed_entries

    def fake_fetch(feed_url, max_entries=10):
        if feed_url == "BROKEN_FEED":
            raise RuntimeError("simulated network failure")
        return real_fetch(feed_url, max_entries)

    monkeypatch.setattr(ingest, "fetch_feed_entries", fake_fetch)

    written = ingest.run_ingest(["BROKEN_FEED", SAMPLE_FEED_XML], corpus_dir, seen_path)

    assert len(written) == 1
    content = written[0].read_text(encoding="utf-8")
    assert "SOURCE: https://example.com/article-1" in content


def test_run_ingest_raises_if_every_feed_fails(tmp_path, monkeypatch):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"

    def fake_fetch(feed_url, max_entries=10):
        raise RuntimeError("simulated network failure")

    monkeypatch.setattr(ingest, "fetch_feed_entries", fake_fetch)

    with pytest.raises(RuntimeError):
        ingest.run_ingest(["BROKEN_1", "BROKEN_2"], corpus_dir, seen_path)


def test_run_ingest_handles_filename_collision_with_numeric_suffix(tmp_path):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"

    first_written = ingest.run_ingest([SAMPLE_FEED_XML], corpus_dir, seen_path)
    second_feed = SAMPLE_FEED_XML.replace("article-1", "article-1-again")
    second_written = ingest.run_ingest([second_feed], corpus_dir, seen_path)

    assert len(first_written) == 1
    assert len(second_written) == 1
    assert second_written[0].name != first_written[0].name
    assert second_written[0].stem.endswith("-2")


def test_run_ingest_output_is_parseable_by_load_corpus(tmp_path):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"

    ingest.run_ingest([SAMPLE_FEED_XML], corpus_dir, seen_path)
    documents = load_corpus(corpus_dir)

    assert len(documents) == 1
    doc = documents[0]
    assert doc.title == "Critical RCE Found in Example Software"
    assert doc.source_url == "https://example.com/article-1"
    assert "A critical remote code execution vulnerability was discovered." in doc.text


def test_run_ingest_sanitizes_newlines_in_title_and_url(tmp_path):
    corpus_dir = tmp_path / "corpus"
    seen_path = tmp_path / "seen_urls.json"
    feed_with_newline_title = SAMPLE_FEED_XML.replace(
        "Critical RCE Found in Example Software",
        "Critical RCE\nFound in Example Software",
    )

    written = ingest.run_ingest([feed_with_newline_title], corpus_dir, seen_path)

    lines = written[0].read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("TITLE:")
    assert lines[1].startswith("SOURCE:")


def test_slugify_falls_back_to_article_for_all_symbol_titles():
    assert ingest.slugify("!!!###???") == "article"
