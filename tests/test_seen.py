from threat_digest.seen import load_seen_urls, mark_seen


def test_load_seen_urls_returns_empty_set_when_file_does_not_exist(tmp_path):
    path = tmp_path / "seen_urls.json"
    assert load_seen_urls(path) == set()


def test_mark_seen_then_load_seen_urls_round_trips(tmp_path):
    path = tmp_path / "seen_urls.json"
    mark_seen(path, "https://example.com/a")
    mark_seen(path, "https://example.com/b")
    assert load_seen_urls(path) == {"https://example.com/a", "https://example.com/b"}


def test_mark_seen_is_idempotent(tmp_path):
    path = tmp_path / "seen_urls.json"
    mark_seen(path, "https://example.com/a")
    mark_seen(path, "https://example.com/a")
    assert load_seen_urls(path) == {"https://example.com/a"}
