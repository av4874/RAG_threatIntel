# Detection-Engineering Synthesis — Design

## Context and goal

This is the "detection-engineering synthesis" sub-project from Option A's roadmap (item 4 of 5, per `docs/superpowers/specs/2026-07-17-threat-intel-rag-digest-design.md`'s "Path to Option A" section). Build B and its live-ingestion extension produce a ranked digest of grounded summaries and risk scores — useful for triage, but not yet actionable for a detection engineer. A DE reading a digest entry today has no way to know: what log source would even show this activity, whether detecting it is realistically feasible, or what kind of detection work it implies (a brand-new use case, tuning something that already exists, a watchlist entry, or a hunting query).

This sub-project adds exactly those four fields — technique mapping, required log sources, detection feasibility, and a recommendation — to digest entries that clear a risk threshold, without touching anything else already built and validated (corpus loading, chunking, retrieval, risk-scoring, ranking, audit logging, live ingestion).

## Scope

**In scope:**
- A second LLM call, made only for digest items with `risk_score >= 6`, using the same retrieved chunks already fetched for that item's risk-scoring call
- Four new fields per qualifying item: ATT&CK technique ID + name (validated against a bundled reference list, not trusted blindly), required log source(s) (from a fixed vocabulary), detection feasibility rating + one-line reason (from a fixed vocabulary), and a recommendation + one-line reason (from a fixed vocabulary)
- A bundled, static reference list of real MITRE ATT&CK technique IDs and names, generated once from MITRE's public data and checked into the repo — used only to validate the LLM's technique claim, not fetched live
- Extending `digest.md`'s formatting to show these four fields for qualifying items, with items below the threshold rendered exactly as they are today (no visual change for non-qualifying entries)
- A second audit record per qualifying item for the synthesis call, using the existing `write_audit_record` shape unchanged

**Out of scope (deferred):**
- A real detection-rule inventory to make the recommendation environment-aware (still "generic reasoning only," per the original project decision) — the recommendation reflects what's typical for this threat type in general, not what you specifically already have
- The structured CISA KEV/NVD lane, router, and rule-based high-risk gate (separate, still-unbuilt Option A sub-projects)
- Any change to the risk-scoring call, retrieval, ingestion, or corpus format — all untouched by this work
- Live/automatic ATT&CK reference updates — the bundled list is a point-in-time snapshot, refreshed manually if it goes stale

## Architecture

```
[existing pipeline, unchanged through risk-scoring]
        │
        ▼
   risk_score >= 6?
        │yes                                    │no
        ▼                                        ▼
   ┌─────────────┐                    (digest entry as today:
   │ synthesis   │                     summary + rationale + score,
   │ LLM call    │                     no synthesis fields)
   │ (2nd call,  │
   │ same chunks)│
   └──────┬──────┘
          ▼
   ┌───────────────┐
   │ validate      │  check the LLM's claimed technique ID against
   │ technique ID  │  the bundled ATT&CK reference list
   └──────┬────────┘
          ▼
   [DigestItem gets 4 extra fields; audit log gets a second record]
```

## Components

- **`src/threat_digest/attack_reference.py`**: a bundled, static mapping of real ATT&CK technique IDs to names (e.g. `{"T1190": "Exploit Public-Facing Application", ...}`), generated once from MITRE's public ATT&CK Enterprise matrix STIX data (the enterprise/IT technique set — not Mobile or ICS, which aren't relevant to this project's threat sources) and checked into the repo as source code (a plain Python dict, not fetched at runtime). One function: `is_valid_technique_id(technique_id: str) -> bool`.

- **`src/threat_digest/synthesis.py`**:
  - `SynthesisResult` dataclass: `technique_id: str`, `technique_name: str`, `technique_verified: bool`, `log_sources: list[str]`, `feasibility: str`, `feasibility_reason: str`, `recommendation: str`, `recommendation_reason: str`
  - `build_synthesis_prompt(title: str, chunks: list[str]) -> str` — states the four fixed vocabularies explicitly (see below) and asks for a technique ID + justification
  - `parse_synthesis_response(raw: str) -> SynthesisResult` — parses the LLM's JSON response, sets `technique_verified` by checking the claimed ID against `attack_reference.is_valid_technique_id`; malformed JSON raises `ValueError` (same contract as `llm_analysis.parse_llm_response`)

- **`pipeline.py` change**: after `analysis = parse_llm_response(raw_output)` succeeds and its `risk_score >= 6`, call `build_synthesis_prompt`/`llm_client.generate`/`parse_synthesis_response` with the same `retrieved_texts`, write a second audit record (same `write_audit_record` call shape, describing this as the synthesis stage's prompt/output), and attach the `SynthesisResult` fields onto that item's `DigestItem`. Items scoring below 6, or where the synthesis call itself fails to parse, get no synthesis fields (the digest entry looks exactly as it does today) — a synthesis failure never blocks or crashes the item's existing risk-scored entry from appearing.

- **`digest.py` change**: `DigestItem` gains optional fields (defaulting to `None`) for the four synthesis outputs. `format_digest_markdown` appends a section for these fields only when present on an item.

## Fixed vocabularies (exact values — used verbatim in both the prompt and any validation)

- **Log sources** (LLM picks one or more): `Windows Security Event Log`, `Web server access logs`, `Firewall/VPN logs`, `EDR/endpoint logs`, `Cloud audit logs`, `DNS logs`, `Email gateway logs`, `Application/database logs`
- **Feasibility** (exactly one): `High`, `Medium`, `Low`, `Not currently feasible`
- **Recommendation** (exactly one): `New use case`, `Tune existing rule`, `Watchlist`, `Hunting query`

## Error handling

- The synthesis call reuses the same JSON-parsing robustness already proven in `llm_analysis.parse_llm_response` (catches `json.JSONDecodeError`, `KeyError`, `TypeError`, `ValueError`, normalizes to a single `ValueError`).
- If the synthesis call's response fails to parse, the pipeline logs an audit record noting the failure (mirroring the existing `risk_score=-1` sentinel pattern from the main pipeline) and the item's `DigestItem` simply has no synthesis fields — it still appears in the digest with its risk score and summary, exactly as every item does today. A broken synthesis call never causes a document to be dropped or the run to fail.
- If the LLM claims a technique ID not found in `attack_reference`'s bundled list, `technique_verified` is `False` — the digest still shows the claimed ID and name, but visibly marked unverified, rather than silently presenting a possibly-fabricated ID as authoritative.

## Testing approach

Following the project's existing TDD pattern, using fake LLM clients (no real Kaggle/GPU calls in tests):
- `attack_reference.py`: unit tests for `is_valid_technique_id` — a real bundled ID returns `True`, a made-up one returns `False`.
- `synthesis.py`: unit tests for `build_synthesis_prompt` (includes title/chunks/vocabularies) and `parse_synthesis_response` (valid JSON parses correctly; a response naming a fake technique ID sets `technique_verified: False`; malformed JSON raises `ValueError`).
- `pipeline.py`: integration tests verifying threshold gating — a fake LLM client scripted to return `risk_score: 5` results in no second (synthesis) call being made; one scripted to return `risk_score: 8` results in the synthesis call happening and its fields appearing on the resulting `DigestItem`. A synthesis call that returns malformed JSON is verified not to remove the item from the digest, just to omit its synthesis fields.
- `digest.py`: unit tests confirming the markdown output includes the four synthesis fields when present, and omits that section entirely (no visual change from today) when absent.
