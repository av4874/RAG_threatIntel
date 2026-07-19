# Live RSS Ingestion for the RAG Lane — Design

## Context and goal

This is the first sub-project of "Option A" (per `docs/superpowers/specs/2026-07-17-threat-intel-rag-digest-design.md`'s "Path to Option A" section), chosen ahead of the structured KEV/NVD lane, router, rule gate, and detection-engineering synthesis. Build B validated the RAG core (chunk → embed → retrieve → LLM-analyze → digest → audit) against a static, manually-curated corpus of 4 documents. This sub-project replaces manual curation with automated, scheduled ingestion from real RSS feeds — proving the RAG lane can sustain itself on live data before any of Option A's other pieces are built on top of it.

Option A's other sub-projects (structured lane, router, rule gate, synthesis, production scheduling of the LLM-analysis step itself) are explicitly out of scope here and remain future work.

## Scope

**In scope:**
- Fetch new articles from three RSS feeds: Dark Reading (`https://www.darkreading.com/rss.xml`), TheHackerNews (`https://feeds.feedburner.com/TheHackersNews`), Microsoft MSRC blog (`https://msrc.microsoft.com/blog/rss/`). (Originally specified BleepingComputer in place of Dark Reading; swapped after the first live run showed BleepingComputer's general feed pulling in non-security tech news — Dark Reading is entirely security-scoped, unlike BleepingComputer's mixed-topic main feed.)
- Deduplicate against previously-ingested articles via a tracked list of seen URLs
- Cap each run at up to 10 new articles per feed (before dedup filtering)
- Write each new article as a `corpus/*.txt` file in the exact format `load_corpus` already expects (`TITLE:`, `SOURCE:`, `---`, body) — using the RSS entry's summary/excerpt as the body text, not full-article extraction
- Run daily via a GitHub Actions scheduled workflow; auto-commit new corpus files and the updated seen-URLs list directly to `master`
- Per-feed error isolation: one feed failing (network error, malformed XML) doesn't block the others; the workflow only fails loudly if every feed fails

**Out of scope (deferred):**
- Full-article text extraction (HTML scraping/readability) — RSS summaries only, a known and accepted quality tradeoff versus the 4 hand-built documents currently in the corpus (summaries are typically 2-4 sentences, giving retrieval and the LLM less to work with)
- Any rule-based relevance/risk filtering at ingestion time — everything each feed publishes gets ingested, including non-security content (BleepingComputer's feed is general tech news, not security-scoped); filtering is explicitly the later rule-gate sub-project's job
- Running the LLM-analysis/digest step itself on a schedule — this sub-project only grows `corpus/`; producing a digest from it is still a separate, manually-triggered Kaggle run for now
- Structured CVE/KEV ingestion (a different sub-project)

## Architecture

```
[BleepingComputer, TheHackerNews, MSRC RSS feeds]
        │
        ▼
   ┌──────────┐
   │  feeds   │  fetch each feed, parse entries → (title, url, summary)
   └────┬─────┘
        ▼
   ┌──────────┐
   │   seen   │  filter out entries whose URL is already recorded as seen
   └────┬─────┘
        │  new entries only, capped at 10 per feed
        ▼
   ┌──────────┐
   │  ingest  │  write one corpus/*.txt per new entry, mark each URL seen
   └──────────┘
        │
        ▼
[GitHub Actions: daily cron → run ingest → commit new corpus/*.txt +
 seen_urls.json to master, if anything changed]
```

Nothing downstream of `corpus/*.txt` changes. `load_corpus`, chunking, retrieval, LLM analysis, digest formatting, and audit logging (all from Build B) consume the resulting files exactly as they do today — this sub-project is purely a new, automated front door onto the same, already-validated pipeline.

## Components

- **`src/threat_digest/feeds.py`**
  - `FeedEntry` dataclass: `title: str`, `url: str`, `summary: str`
  - `fetch_feed_entries(feed_url: str, max_entries: int = 10) -> list[FeedEntry]` — uses the `feedparser` library to fetch and parse the feed, returns at most `max_entries`, most recent first. A fetch/parse failure raises; the caller (`ingest.py`) is responsible for catching it per-feed.

- **`src/threat_digest/seen.py`**
  - `load_seen_urls(path: Path) -> set[str]` — reads a JSON array of URL strings from `path`; returns an empty set if the file doesn't exist yet.
  - `mark_seen(path: Path, url: str) -> None` — appends `url` to the JSON array at `path`, creating the file if needed.

- **`src/threat_digest/ingest.py`**
  - `slugify(title: str) -> str` — lowercases, replaces non-alphanumeric runs with `-`, trims to a reasonable length, for building filenames.
  - `run_ingest(feed_urls: list[str], corpus_dir: Path, seen_path: Path) -> list[Path]` — for each feed URL: catches and logs (to stderr) any fetch failure and continues to the next feed; for each entry not already in the seen set, writes `corpus_dir/YYYY-MM-DD-<slug>.txt` (today's date, slugified title, numeric suffix on filename collision) in the required format, and calls `mark_seen`. Returns the list of newly-written file paths. Raises only if every feed failed.
  - A `if __name__ == "__main__":` entry point calling `run_ingest` with the three feed URLs, `Path("corpus")`, and `Path("seen_urls.json")`, so the GitHub Actions workflow can run it as `python -m threat_digest.ingest`.

- **`.github/workflows/ingest.yml`**
  - Triggers: `schedule` (daily cron, e.g. `0 6 * * *`) and `workflow_dispatch` (manual trigger for testing)
  - Steps: checkout, set up Python 3.11, `pip install feedparser` (plus the project's existing install), run `python -m threat_digest.ingest`, then check `git status --porcelain` — if non-empty, `git add corpus/ seen_urls.json`, commit (`"chore: ingest N new articles"` where N is the count from `run_ingest`'s return value), and push. If nothing changed, the workflow completes without committing.

## Corpus file naming and content

Each new entry becomes `corpus/YYYY-MM-DD-<slugified-title>.txt`:
```
TITLE: <entry title>
SOURCE: <entry url>
---
<RSS summary text>
```
`YYYY-MM-DD` is the date the entry was *ingested* (run date), not necessarily the article's original publish date, since RSS feeds don't always expose a reliable structured publish date across all three sources — ingestion date is simpler and sufficient for `doc_id` uniqueness. If slugifying two different titles ingested the same day collides, a numeric suffix (`-2`, `-3`, ...) is appended before `.txt`.

## Error handling

- `fetch_feed_entries` raising for one feed (network timeout, malformed XML, HTTP error) is caught inside `run_ingest`'s per-feed loop, logged to stderr with the feed URL and error, and that feed is skipped for this run — the other feeds still get processed.
- `run_ingest` raises only if every feed in `feed_urls` failed to fetch, which fails the GitHub Actions job loudly (visible in the Actions tab) — a genuine "ingestion is completely broken" signal, distinct from a single flaky feed.
- A malformed individual RSS entry (missing title or link) is skipped with a logged warning rather than crashing the run, since one bad entry in an otherwise-healthy feed shouldn't block the rest.

## Testing approach

Following Build B's TDD pattern:
- `feeds.py`: unit tests using a small, hand-written RSS/Atom XML fixture string (no network calls) to verify parsing and the `max_entries` cap.
- `seen.py`: unit tests using `tmp_path` — round-trip load/mark/reload, and the empty-file-doesn't-exist-yet case.
- `ingest.py`: unit tests using fake `fetch_feed_entries`/`load_seen_urls`/`mark_seen` (or a fixture RSS fixture + `tmp_path` corpus dir) to verify: new entries get written in the correct format, seen entries get skipped, filename collisions get a numeric suffix, and a single feed's fetch exception doesn't stop the others from being processed. One integration-style test may hit the real feed URLs to confirm they're still reachable and parseable — acceptable to be network-dependent and marked/skippable, since Build B's own retrieval tests already accept a similar tradeoff (downloading the real embedding model).
- The GitHub Actions workflow itself is validated by triggering it manually (`workflow_dispatch`) once and confirming a commit appears, rather than unit-tested — CI workflow YAML isn't practically unit-testable.
