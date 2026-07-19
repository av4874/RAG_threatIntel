# Router (RAG + KEV Correlation) — Design

## Context and goal

This is the "router" sub-project from Option A's roadmap (item 3 of 5, per
`docs/superpowers/specs/2026-07-17-threat-intel-rag-digest-design.md`'s "Path
to Option A" section). Two independent lanes now exist and are both live in
production: the RAG lane (`digest.md`/`audit.jsonl`, LLM-analyzed articles,
pushed from Kaggle) and the structured KEV lane (`kev_digest.md`, CISA's
confirmed-exploited catalog, pushed daily by GitHub Actions). Nothing
currently connects them — if a RAG-lane article discusses a CVE that's also
CISA-confirmed exploited, a reader has no way to know that from either file
alone.

This was validated as a real, not hypothetical, gap before designing the fix:
of 6 CVE IDs found in the RAG lane's raw retrieved article text (`audit.jsonl`),
4 are already present in the current `kev_digest.md`. A router that surfaces
that overlap would produce genuinely useful output today.

## Scope

**In scope:**
- A new `unified_digest.md`, produced by joining the RAG lane and KEV lane on
  CVE ID, with dual-confirmed items (present in both lanes) ranked first
- A small addition to the existing KEV lane (`kev.py`) to emit a structured
  `kev_data.json` alongside its existing `kev_digest.md`, since the router
  needs machine-readable KEV data and markdown is not that
- A new GitHub Actions workflow that regenerates `unified_digest.md`
  automatically whenever either lane's source data changes

**Out of scope (deferred):**
- Any change to how the RAG lane or KEV lane fetch, analyze, or rank their
  own data — both lanes are untouched internally
- NVD enrichment (still deferred from the KEV lane's own original scope)
- KEV synthesis (ATT&CK/log sources/feasibility/recommendation for KEV
  entries) — a separate, still-unbuilt idea discussed but not started
- Fuzzy/semantic matching between articles and KEV entries that don't share
  an explicit CVE ID — CVE-ID matching only, per the earlier design decision

## Architecture

```
audit.jsonl (RAG lane, analysis-stage records:            kev_data.json (KEV lane,
doc_id, prompt, retrieved_chunks, raw_llm_output,          NEW structured output:
risk_score, stage)                                          list of KEV entries)
        │                                                          │
        ▼                                                          │
  per record:                                                      │
  - extract title (regex on the prompt's fixed                     │
    `document titled "..."` phrase)                                │
  - extract CVE IDs (regex over retrieved_chunks)                  │
  - parse risk_score (existing parse_llm_response)                 │
        │                                                          │
        └────────────────────── CVE ID join ─────────────────────────┘
                                 │
                                 ▼
                    unified_digest.md, three sections:
                    1. Dual-confirmed (CVE in both lanes) — all, no cap
                    2. RAG-only high-risk (risk_score >= 6, no KEV match)
                    3. KEV-only (no matching RAG article) — capped top 30,
                       ordered by recency (date_added descending), NOT
                       ransomware-first — see rationale below
```

No LLM calls anywhere in the router — pure data correlation over two
already-produced structured sources, consistent with the project's existing
"LLM only where judgment is genuinely needed" philosophy.

**Why the KEV-only section re-sorts by recency instead of reusing
`kev_data.json`'s ransomware-first order:** ransomware-linked entries are
only ~9% of the full 200 (18 of 200, as measured during the KEV lane's own
design). Ransomware-first ordering exists in `kev_digest.md` for a specific
reason — patch-priority triage over the *full* list. But applying a hard
cap of 30 on top of that same ordering would pull in all 18 ransomware
entries plus only 12 others, making the unified digest's KEV-only section
~60% ransomware — a large, artificial skew relative to the real
composition of what CISA has confirmed exploited. The KEV-only section
therefore re-sorts the unmatched entries by `date_added` descending before
capping, so the top 30 reflects the most-recently-added unmatched KEV
entries regardless of ransomware status. Each entry still carries its own
`(RANSOMWARE-LINKED)` flag inline, so that signal isn't lost — it's just
no longer used to bias which 30 entries get shown.

## Components

- **`src/threat_digest/kev.py` (modified)**: `__main__` gains one more
  write — `kev_data.json`, a JSON array of the same `[:200]`-sliced,
  ransomware-ranked `KEVEntry` list already used for `kev_digest.md`
  (`dataclasses.asdict` per entry), written alongside it. No change to
  `KEVEntry`, `fetch_kev_catalog`, `rank_kev_entries`, or
  `format_kev_digest_markdown` — this is additive only.

- **`.github/workflows/kev_fetch.yml` (modified)**: the commit step's
  `git add` gains `kev_data.json` alongside `kev_digest.md`, so both are
  committed together on the same run.

- **`src/threat_digest/router.py` (new)**:
  - `extract_cve_ids(text: str) -> set[str]` — regex `CVE-\d{4}-\d{4,7}`
    over any text, used against `retrieved_chunks`
  - `extract_title(prompt: str) -> str` — regex over the fixed phrase
    `document titled "..."` that `llm_analysis.build_prompt` always
    produces, used against the audit record's `prompt` field (no change to
    `llm_analysis.py` needed — this reads the existing fixed template)
  - `load_analysis_records(audit_path: Path) -> list[dict]` — reads
    `audit.jsonl`, filters to `stage == "analysis"` records only (synthesis
    records are not needed for correlation)
  - `load_kev_entries(kev_data_path: Path) -> list[dict]` — reads
    `kev_data.json`
  - `build_unified_digest(audit_path: Path, kev_data_path: Path) -> str` —
    performs the CVE-ID join and renders the three markdown sections
  - A `__main__` entry point: reads `audit.jsonl` and `kev_data.json` from
    the repo root, writes `unified_digest.md`

- **`.github/workflows/router.yml` (new)**: triggers on `push` to
  `digest.md`, `audit.jsonl`, or `kev_data.json` (path filter), plus
  `workflow_dispatch`. Runs `python -m threat_digest.router`
  (stdlib-only — no new pip dependencies), commits `unified_digest.md` if
  `git status --porcelain` is non-empty, mirroring `ingest.yml`/
  `kev_fetch.yml`'s conditional-commit pattern.

## Error handling

- If either `audit.jsonl` or `kev_data.json` is missing or malformed, the
  router fails loudly (raises, non-zero exit) rather than producing a
  partial or misleading unified digest — same philosophy as the KEV lane's
  single-source fail-loud behavior. The previous `unified_digest.md` stays
  as the last-known-good state if a run fails.
- A RAG-lane record whose `retrieved_chunks` contain no CVE ID at all is not
  an error — it simply has no possible KEV match and falls through to the
  "RAG-only" section if it clears the risk threshold, or is omitted
  entirely if it doesn't.
- No dedup/history tracking, matching both source lanes — each run fully
  regenerates `unified_digest.md` from the current state of both inputs.

## Testing approach

Following the project's existing TDD pattern, no live network/LLM calls:
- `kev.py`: extend the existing test to verify `kev_data.json` is written
  with the correct ranked/sliced entries as JSON (same fixture pattern
  already used for `kev_digest.md`).
- `router.py`: hand-written fixtures for both `audit.jsonl` (a small JSONL
  file with analysis-stage records, some containing CVE IDs in
  `retrieved_chunks`, some not) and `kev_data.json` (a small JSON array).
  Tests verify: CVE extraction from chunk text; title extraction from the
  prompt's fixed phrase; a CVE present in both sources produces a
  dual-confirmed entry; a KEV entry with no matching RAG CVE lands in the
  KEV-only section, capped at 30 and ordered by recency (not
  ransomware-first, per the rationale above); a
  RAG record below the risk threshold with no KEV match is omitted
  entirely; a RAG record above the threshold with no KEV match lands in the
  RAG-only section.
