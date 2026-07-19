# Production Readiness Gaps — Future Enhancements

## Context

This is not a design spec for a sub-project to build next — it's a
recorded gap analysis from a software-engineering and business-management
review of the pipeline as it stood after Option A sub-projects 1-4 (RSS
ingestion, structured KEV lane, router, detection-engineering synthesis)
were built and validated against real data. Nothing here is scoped or
prioritized for immediate implementation; it exists so these gaps are
tracked deliberately rather than forgotten, and can be pulled into a real
design (brainstorm → spec → plan) whenever one of them becomes a priority.

The pipeline is technically sound and tested for what it currently does
(72 passing tests, all three lanes verified against live data). What's
listed below is everything *around* the working pipeline that would need
to exist before calling this a true unattended production service, not
problems with the code that's already shipped.

## Software engineering gaps

**Reliability / observability**
- No alerting. Every GitHub Actions workflow fails silently into the
  Actions tab — nobody is notified if the CISA feed schema changes, an RSS
  feed goes down, or the Kaggle push-back token expires.
- No retries or backoff on any external fetch (CISA KEV, RSS feeds). A
  transient network failure just fails the run; nothing distinguishes
  "will recover next cron" from "will keep failing."
- No schema-drift detection. `fetch_kev_catalog` and the RSS ingestion path
  assume today's field names never change; a silent upstream rename
  surfaces as a raw `KeyError`/`AttributeError`, not a clear diagnostic.
- No live canary test. All 72 tests run against hand-written fixtures
  (deliberately — no live network in CI), so nothing periodically confirms
  the real upstream APIs still match those fixtures. Schema drift would
  only be caught as a production failure, never as a caught regression.

**Resilience**
- Bus factor of 1 on the RAG lane — only one person can currently trigger
  the Kaggle notebook; no documented handoff or second operator.
- No secrets rotation policy for the Kaggle→GitHub PAT (no expiry/rotation
  cadence defined).

**Scale**
- Single-threaded, 3 RSS feeds, KEV catalog capped at 200 entries — fine
  for validation, would need rework (concurrency, pagination, more
  sources) before real production volume.

## Business / process gaps

**Value and ROI story is undefined**
- No feedback loop: when a detection engineer reads a digest item and
  decides to build (or skip) a use case, that decision isn't captured
  anywhere. Without it, there's no way to measure precision (how many
  recommendations were actually good) or demonstrate ROI.
- No success metric defined — reduced time-to-detect? use cases shipped
  per month? Nothing has been decided as "what does this working well
  look like."

**Ownership and process**
- No on-call/escalation path if a pipeline breaks.
- No incident/postmortem process for when the tool is *wrong* — and it
  demonstrably can be: the detection-engineering synthesis feature's
  ATT&CK technique grounding bug (found during real Kaggle validation,
  fixed in commit `eb04327`) is a concrete example. A wrong recommendation
  reaching a detection engineer with no defined "how do we catch and
  correct this" process is a real risk once this is more than a personal
  project.
- No consumption workflow for the actual audience. Digests are markdown
  files in a repo right now — nothing notifies anyone when new high-risk
  or dual-confirmed items appear (see the notifications gap already noted
  in the main README's Known Limitations section).

## Overall assessment

The pipeline itself is solid: real data, real tests, real validation at
every stage, and issues that were found got fixed and re-verified against
production data rather than assumed away. What's missing is not more
Python — it's the organizational and operational scaffolding (alerting,
ownership, a feedback loop, a defined success metric) that turns "a
working pipeline" into "a production service."
