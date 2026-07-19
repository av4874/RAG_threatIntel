# Live RSS Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Build B's manually-curated static corpus with automated, scheduled ingestion from three RSS feeds, producing the same `corpus/*.txt` format the existing pipeline already consumes unchanged.

**Architecture:** Three small modules mirroring Build B's existing style — `feeds.py` (fetch/parse RSS via `feedparser`), `seen.py` (URL dedup tracking), `ingest.py` (orchestrates the two, writes corpus files) — driven by a daily GitHub Actions workflow that runs the ingestion script and auto-commits any new files.

**Tech Stack:** Python 3.11+, `feedparser`, pytest (local dev already has these). GitHub Actions (`ubuntu-latest`, no GPU needed).

## Global Constraints

- Feed URLs (exact, per spec): `https://www.bleepingcomputer.com/feed/`, `https://feeds.feedburner.com/TheHackersNews`, `https://msrc.microsoft.com/blog/rss/`
- Cap: up to 10 entries per feed per run (before dedup filtering)
- Content: RSS summary/excerpt only — no full-article HTML scraping
- Dedup: a tracked JSON file of previously-seen URLs (`seen_urls.json`), not the corpus directory itself
- Corpus file format (already fixed by `src/threat_digest/corpus.py`'s `load_corpus`): first line `TITLE: <title>`, second line `SOURCE: <url>`, then a line containing only `---`, then body text
- Filename: `corpus/YYYY-MM-DD-<slugified-title>.txt`, numeric suffix (`-2`, `-3`, ...) on collision
- Error handling: one feed failing must not block the others; `run_ingest` raises only if every feed in the list failed
- Scheduling: GitHub Actions, daily cron + manual `workflow_dispatch` trigger, auto-commits directly to `master`
- No placeholders, no speculative error handling beyond what's specified — YAGNI

---

## File Structure

```
RAG_threatIntel/
  requirements.txt        # add feedparser
  src/threat_digest/
    feeds.py               # FeedEntry, fetch_feed_entries()
    seen.py                 # load_seen_urls(), mark_seen()
    ingest.py                # slugify(), run_ingest(), __main__ entry point
  tests/
    test_feeds.py
    test_seen.py
    test_ingest.py
  .github/workflows/
    ingest.yml
```

---

### Task 1: Feed fetching and parsing

**Files:**
- Modify: `requirements.txt`
- Create: `src/threat_digest/feeds.py`
- Test: `tests/test_feeds.py`

**Interfaces:**
- Produces: `FeedEntry` dataclass (`title: str`, `url: str`, `summary: str`), `fetch_feed_entries(feed_url: str, max_entries: int = 10) -> list[FeedEntry]`. Used by Task 3 (`ingest.py`).

`feedparser.parse()` accepts either a URL (it fetches over HTTP) or a raw XML string (if the input doesn't look like a URL, it parses the string directly as feed content, no network call) — this is what makes the tests below possible without any network mocking.

- [ ] **Step 1: Add `feedparser` to `requirements.txt`**

```
sentence-transformers==3.3.1
faiss-cpu==1.9.0
numpy==1.26.4
pytest==8.3.4
feedparser==6.0.11
```

- [ ] **Step 2: Install it in the local venv**

Run: `.venv/Scripts/pip install feedparser==6.0.11`
Expected: installs without error.

- [ ] **Step 3: Write the failing test**

`tests/test_feeds.py`:
```python
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
```

- [ ] **Step 4: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_feeds.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.feeds'`

- [ ] **Step 5: Implement `feeds.py`**

```python
import sys
from dataclasses import dataclass

import feedparser


@dataclass
class FeedEntry:
    title: str
    url: str
    summary: str


def fetch_feed_entries(feed_url: str, max_entries: int = 10) -> list[FeedEntry]:
    parsed = feedparser.parse(feed_url)
    entries = []
    for raw_entry in parsed.entries[:max_entries]:
        title = raw_entry.get("title")
        url = raw_entry.get("link")
        summary = raw_entry.get("summary", "")
        if not title or not url:
            print(
                f"WARNING: skipping feed entry with missing title/link from {feed_url}",
                file=sys.stderr,
            )
            continue
        entries.append(FeedEntry(title=title, url=url, summary=summary))
    return entries
```

- [ ] **Step 6: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_feeds.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add requirements.txt src/threat_digest/feeds.py tests/test_feeds.py
git commit -m "feat: add RSS feed fetching and parsing"
```

---

### Task 2: Seen-URL dedup tracking

**Files:**
- Create: `src/threat_digest/seen.py`
- Test: `tests/test_seen.py`

**Interfaces:**
- Produces: `load_seen_urls(path: Path) -> set[str]`, `mark_seen(path: Path, url: str) -> None`. Used by Task 3 (`ingest.py`).

- [ ] **Step 1: Write the failing test**

`tests/test_seen.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_seen.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.seen'`

- [ ] **Step 3: Implement `seen.py`**

```python
import json
from pathlib import Path


def load_seen_urls(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")))


def mark_seen(path: Path, url: str) -> None:
    seen = load_seen_urls(path)
    seen.add(url)
    path.write_text(json.dumps(sorted(seen)), encoding="utf-8")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_seen.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/seen.py tests/test_seen.py
git commit -m "feat: add seen-URL dedup tracking"
```

---

### Task 3: Ingestion orchestration

**Files:**
- Create: `src/threat_digest/ingest.py`
- Test: `tests/test_ingest.py`

**Interfaces:**
- Consumes: `FeedEntry`/`fetch_feed_entries` (Task 1), `load_seen_urls`/`mark_seen` (Task 2).
- Produces: `slugify(title: str) -> str`, `run_ingest(feed_urls: list[str], corpus_dir: Path, seen_path: Path) -> list[Path]`, plus a `__main__` entry point. Used by Task 4's GitHub Actions workflow (`python -m threat_digest.ingest`).

- [ ] **Step 1: Write the failing test**

`tests/test_ingest.py`:
```python
import pytest

from threat_digest import ingest
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_ingest.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.ingest'`

- [ ] **Step 3: Implement `ingest.py`**

```python
import re
import sys
from datetime import date
from pathlib import Path

from threat_digest.feeds import fetch_feed_entries
from threat_digest.seen import load_seen_urls, mark_seen


def slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug[:80]


def run_ingest(feed_urls: list[str], corpus_dir: Path, seen_path: Path) -> list[Path]:
    corpus_dir = Path(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    seen_path = Path(seen_path)
    seen = load_seen_urls(seen_path)

    written: list[Path] = []
    failures = 0

    for feed_url in feed_urls:
        try:
            entries = fetch_feed_entries(feed_url)
        except Exception as exc:
            print(f"WARNING: failed to fetch feed {feed_url}: {exc}", file=sys.stderr)
            failures += 1
            continue

        for entry in entries:
            if entry.url in seen:
                continue

            slug = slugify(entry.title)
            today = date.today().isoformat()
            base_name = f"{today}-{slug}"
            file_path = corpus_dir / f"{base_name}.txt"
            suffix = 2
            while file_path.exists():
                file_path = corpus_dir / f"{base_name}-{suffix}.txt"
                suffix += 1

            content = f"TITLE: {entry.title}\nSOURCE: {entry.url}\n---\n{entry.summary}\n"
            file_path.write_text(content, encoding="utf-8")
            written.append(file_path)

            mark_seen(seen_path, entry.url)
            seen.add(entry.url)

    if feed_urls and failures == len(feed_urls):
        raise RuntimeError(f"All {len(feed_urls)} feeds failed to fetch")

    return written


if __name__ == "__main__":
    FEED_URLS = [
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://msrc.microsoft.com/blog/rss/",
    ]
    written_paths = run_ingest(FEED_URLS, Path("corpus"), Path("seen_urls.json"))
    print(f"Ingested {len(written_paths)} new article(s).")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_ingest.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/Scripts/pytest -v`
Expected: all tests pass, no regressions in Build B's existing tests.

- [ ] **Step 6: Commit**

```bash
git add src/threat_digest/ingest.py tests/test_ingest.py
git commit -m "feat: add ingestion orchestration with per-feed error isolation"
```

---

### Task 4: GitHub Actions scheduled workflow

**Files:**
- Create: `.github/workflows/ingest.yml`

**Interfaces:**
- Consumes: `run_ingest`'s `__main__` entry point (Task 3), via `python -m threat_digest.ingest`.
- Produces: nothing consumed by other tasks — this is the terminal, automation-facing task.

- [ ] **Step 1: Create `.github/workflows/ingest.yml`**

```yaml
name: Ingest RSS feeds

on:
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch: {}

jobs:
  ingest:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install feedparser==6.0.11

      - name: Run ingestion
        run: PYTHONPATH=src python -m threat_digest.ingest

      - name: Commit new corpus files
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          if [ -n "$(git status --porcelain)" ]; then
            git add corpus/ seen_urls.json
            git commit -m "chore: ingest new articles from RSS feeds"
            git push
          else
            echo "No new articles to commit."
          fi
```

`permissions: contents: write` is required for the workflow's default `GITHUB_TOKEN` to be able to push the commit back to the repo. The job installs only `feedparser` (not the full `requirements.txt`) since ingestion doesn't need sentence-transformers/faiss-cpu/torch — keeping this job fast and GPU-free, per the design spec.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ingest.yml
git commit -m "feat: add daily scheduled RSS ingestion workflow"
```

- [ ] **Step 3: Push and manually trigger once to verify end-to-end**

```bash
git push origin master
```

Then on GitHub: Actions tab → "Ingest RSS feeds" → "Run workflow" (uses the `workflow_dispatch` trigger). Confirm the run succeeds and either commits new `corpus/*.txt` files (if any new articles exist across the three feeds) or logs "No new articles to commit." This is a manual verification step, not something to automate — see the design spec's Testing section, which explicitly scopes CI workflow validation to a manual trigger rather than a unit test.

---

## After this plan

Live RSS ingestion is complete once Task 4's manual workflow trigger succeeds and new `corpus/*.txt` files appear (or the workflow correctly reports nothing new). This corpus keeps growing automatically going forward — the next Kaggle run of `run_pipeline` will pick up whatever's in `corpus/` at that time, live-sourced articles included. Growth to the rest of Option A (structured KEV/NVD lane, router, rule gate, detection-engineering synthesis, LLM-analysis scheduling) remains separate future work, per the design spec's decomposition.
