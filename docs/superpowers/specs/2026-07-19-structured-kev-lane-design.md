# Structured KEV Lane — Design

## Context and goal

This is the "structured CISA KEV/NVD lane + rule-based high-risk gate" sub-project from Option A's roadmap (item 2 of 5, per `docs/superpowers/specs/2026-07-17-threat-intel-rag-digest-design.md`'s "Path to Option A" section) — the other half of the RAG core validated in Build B. Where the RAG lane handles unstructured text (blog posts) that needs chunking, embedding, retrieval, and LLM judgment to extract risk signal, CISA's Known Exploited Vulnerabilities (KEV) catalog is already structured, authoritative data: a CVE's presence in the catalog *is* the risk signal (CISA has already confirmed active exploitation), with no LLM interpretation needed or wanted.

This sub-project is scoped to KEV only, not KEV+NVD as originally named — NVD enrichment (CVSS scores, richer descriptions) is deferred, since it requires API key management and rate-limit handling for no clear v1 benefit: KEV membership alone is already a complete, defensible high-risk signal (the catalog's name is literally "Known *Exploited* Vulnerabilities" — severity score is secondary to confirmed exploitation for this project's purposes).

## Scope

**In scope:**
- Fetch CISA's public KEV JSON feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`), no authentication required
- Select the 200 most recently added entries (the feed is already sorted most-recent-first by CISA, verified empirically — no client-side sorting needed, just `vulnerabilities[:200]`)
- Rank those 200: entries with `knownRansomwareCampaignUse == "Known"` ranked above entries without, preserving CISA's recency order within each group (stable sort) — this is the rule gate's actual logic for this validation pass, using a field CISA already provides at no extra fetch cost
- Produce a standalone ranked markdown digest (`kev_digest.md`), independently validating this lane's output before any router work merges it with the RAG lane
- A GitHub Actions workflow (daily cron + manual trigger) that fetches, ranks, and commits the digest — mirroring the existing RSS ingestion workflow's structure

**Out of scope (deferred):**
- NVD enrichment (CVSS scores, richer vulnerability descriptions) — a future enhancement once this simpler KEV-only lane is validated, not required for KEV membership to function as a risk signal
- The router that merges this lane's output with the RAG lane's digest (separate, still-unbuilt Option A sub-project)
- Any change to the RAG lane (corpus, chunking, retrieval, risk-scoring, synthesis) — entirely untouched by this work
- Historical accumulation of KEV entries — each run reflects CISA's current top-200 snapshot and overwrites the digest, since CISA can update existing entries (e.g. `dueDate`), not just add new ones, and there is no need to preserve stale historical snapshots for this project's purposes

## Architecture

```
[CISA KEV public JSON feed, one HTTP GET, no auth]
        │
        ▼
   ┌──────────┐
   │  fetch   │  download the full catalog (1,647 entries as of this
   │          │  writing), already sorted most-recent-first by CISA
   └────┬─────┘
        ▼
   ┌──────────┐
   │  select  │  take the first 200 entries (vulnerabilities[:200])
   └────┬─────┘
        ▼
   ┌──────────┐
   │  rank    │  ransomware-linked entries (knownRansomwareCampaignUse
   │          │  == "Known") ranked above the rest, stable sort
   └────┬─────┘
        ▼
   ┌──────────┐
   │  digest  │  kev_digest.md — ranked markdown list
   └──────────┘
        │
        ▼
[GitHub Actions: daily cron + manual trigger → fetch/select/rank/write → commit kev_digest.md if changed]
```

No chunking, embedding, retrieval, or LLM call anywhere in this lane. This is the defining architectural difference from the RAG lane: CISA's structured fields are already the content, and KEV membership is already the risk judgment.

## Components

- **`src/threat_digest/kev.py`**:
  - `KEVEntry` dataclass: `cve_id: str`, `vendor_project: str`, `product: str`, `vulnerability_name: str`, `date_added: str`, `short_description: str`, `required_action: str`, `due_date: str`, `known_ransomware_use: bool` (parsed from the feed's `"Known"`/`"Unknown"` string field — `True` only for the literal string `"Known"`)
  - `fetch_kev_catalog(url: str) -> list[KEVEntry]` — HTTP GET the feed, parse the `vulnerabilities` array into `KEVEntry` instances
  - `rank_kev_entries(entries: list[KEVEntry]) -> list[KEVEntry]` — stable sort placing `known_ransomware_use=True` entries first, preserving input order (CISA's recency order) within each group
  - `format_kev_digest_markdown(entries: list[KEVEntry]) -> str` — one section per entry: CVE ID + vendor/product as heading, short description, required action, due date, and a ransomware-linked flag when applicable
  - A `__main__` entry point: `fetch_kev_catalog(KEV_FEED_URL)` → take `[:200]` → `rank_kev_entries` → `format_kev_digest_markdown` → write `kev_digest.md`

- **`.github/workflows/kev_fetch.yml`**: `schedule` (daily cron) + `workflow_dispatch`, structurally mirrors the existing `ingest.yml` (checkout, setup Python 3.11, run the script as `PYTHONPATH=src python -m threat_digest.kev`, commit `kev_digest.md` if `git status --porcelain` is non-empty). No extra pip installs needed — the fetch uses only the Python standard library (`urllib.request`, `json`), no `feedparser`-equivalent dependency.

## Error handling

- If the CISA feed is unreachable, returns a non-200 status, or returns malformed JSON, `fetch_kev_catalog` raises and the script exits non-zero — this fails the GitHub Actions run loudly. Unlike RSS ingestion's per-feed error isolation (three independent feeds, one failing shouldn't block the others), there is exactly one source here, so there is no partial-failure case to design around: either the fetch succeeds and a real digest is produced, or it fails and nothing is committed (the previous `kev_digest.md` stays as the last-known-good state).
- No dedup/seen-URL tracking is needed (unlike RSS ingestion) — this pipeline always reflects CISA's current top-200 snapshot and overwrites the digest file each run, since existing KEV entries can be updated by CISA (not just appended to).

## Testing approach

Following the project's existing TDD pattern, no live network calls in the automated test suite:
- `fetch_kev_catalog`: a test using a small, hand-written JSON fixture matching the real feed's schema (`cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`) — verifies correct parsing, including the `"Known"`/`"Unknown"` string-to-boolean conversion for `known_ransomware_use`.
- `rank_kev_entries`: verify ransomware-linked entries sort before non-ransomware entries, and that relative order is preserved within each group (a genuine stability check, not just "ransomware entries appear somewhere earlier").
- `format_kev_digest_markdown`: verify all fields render in the output, and that the ransomware-linked flag is visibly present for flagged entries and absent for others.
- The real CISA feed is exercised manually after implementation (same validation habit as the rest of this project) by running the `__main__` entry point once and reviewing `kev_digest.md` directly — not as part of the automated suite, since automated tests must not depend on live network access.
