# Threat Intel RAG Digest — Design

## Context and goal

Long-term goal: an **Emerging Threat Detection Agent** for a detection engineering (DE) team. It continuously monitors trusted threat intel sources, filters out noise, and for each high-risk emerging threat (zero-days, actively exploited CVEs, CISA KEV entries, ransomware campaigns, critical exploit chains) produces a detection-engineering analysis — TTP mapping, required log sources, detection feasibility, and a recommendation (new use case / tune existing rule / watchlist / hunting query). This is referred to as **Option A**.

Option A has two lanes feeding a shared pipeline:
- a **structured lane** over clean, already-structured sources (CISA KEV, NVD/CVE) that get filtered/queried directly, no retrieval needed
- a **RAG lane** over unstructured sources (threat research blogs, vendor advisory prose) that need embedding + retrieval to ground any generated summary
- a **router** deciding which lane(s) answer a given item, then **filter** (rule-based high-risk gate) and **synthesis** (TTP/detection analysis) stages on top, producing the final DE-ready digest with full audit trail (raw input, gate decision + reason, LLM prompt/output, final recommendation, logged per item)

Building all of Option A first risks not knowing, when an output is wrong, whether the bug is in retrieval, the router, the filter, or the synthesis step.

**This spec covers Build B only**: the RAG lane in isolation, run standalone against a static corpus, to validate that retrieval and grounded generation actually work before adding the structured lane, router, rule gate, and detection-action synthesis on top. Build B is a stepping stone to Option A, not a separate product — its storage/audit shape is deliberately chosen to carry forward unchanged.

## Scope of Build B

**In scope:**
- Static, manually-collected corpus of unstructured threat intel documents (blog posts, vendor advisory pages), stored as local text/HTML files
- Chunk + embed the corpus into a FAISS index using a local sentence-transformers model
- Treat **one source document = one candidate item** (no sub-document threat extraction)
- For each item: retrieve its own top-k relevant chunks, then an open-source LLM (via LangChain) generates a grounded summary, a risk rationale, and a risk score (1–10) — LLM-only scoring, no rule-based pre-filter in this build
- Rank items by risk score, descending
- Output: a single markdown digest, items in ranked order, each with summary + rationale + source citation (doc title/link)
- Per-item audit record (JSON lines, one file per run): source doc, retrieved chunk IDs + text, full LLM prompt, LLM output, timestamp
- Manual validation: spot-check digest entries against source docs to confirm the summary is actually grounded in retrieved content, not invented

**Out of scope for Build B** (deferred to Option A):
- CISA KEV / NVD structured lane
- Router between structured and RAG lanes
- Rule-based high-risk gate (hard filters like KEV membership, CVSS threshold, campaign keyword match)
- Detection engineering synthesis (TTP/ATT&CK mapping, log source mapping, feasibility assessment, use-case/tune/watchlist/hunt recommendation)
- Scheduling / daily automation (HF Space scheduled job)
- Live corpus ingestion (RSS/scraper) — corpus is a static snapshot
- Dedup against previously-seen items
- Splitting a single document into multiple distinct threats (e.g. weekly roundup posts)
- Automated retrieval eval harness — validation is manual review in this build

## Architecture

```
[Static corpus: blog posts / vendor advisories, one file per doc]
        │
        ▼
   ┌───────────┐
   │  chunk +  │  split docs into passages, embed with sentence-transformers,
   │  embed    │  store in a FAISS index (rebuilt whenever corpus changes)
   └────┬──────┘
        ▼
   ┌───────────┐
   │ retrieve  │  per item (= per source doc), pull top-k relevant chunks
   │           │  from FAISS
   └────┬──────┘
        ▼
   ┌────────────┐
   │llm_analysis│  open-source model via LangChain: reads retrieved chunks,
   │            │  writes grounded summary + risk rationale + risk score
   └────┬───────┘
        ▼
   ┌─────────┐
   │  rank   │  sort items by LLM-assigned risk score, descending
   │ + digest│  → ranked markdown report, each entry cites its source
   └─────────┘
```

Each stage's input/output for each item is written to the per-run audit log before moving to the next.

## Components

- **Corpus**: local directory of collected documents (e.g. `/corpus`), one file per source document, collected manually for this build.
- **Index builder**: chunks each document, embeds chunks with a local sentence-transformers model, writes a FAISS index (e.g. `/index`). Rebuilt on demand when the corpus snapshot changes — not incremental.
- **Retriever**: given an item (source document), retrieves its own top-k chunks from FAISS.
- **LLM analysis (LangChain)**: open-source instruct model, prompted with the retrieved chunks and a scoring rubric; returns summary, rationale, and a 1–10 risk score. Default to Qwen2.5-7B-Instruct — strong structured-output/reasoning for its size, runs quantized on a single Kaggle GPU or a decent local GPU. Swappable for a larger Qwen2.5 size (14B/32B) if 7B's summaries prove unreliable during manual validation.
- **Ranker + digest writer**: sorts items by score, writes the markdown report.
- **Audit logger**: appends one JSON-lines record per item per run, capturing source doc, retrieved chunks, LLM prompt, LLM output, and timestamp.

## Execution environment

- Core pipeline logic (chunking, embedding, retrieval, prompt construction, ranking, digest formatting, audit logging) lives in a plain, importable Python package with no GPU dependency at import time — this is what gets unit tested locally (pytest, CPU only, LLM calls mocked).
- The actual end-to-end run — including the Qwen2.5-7B-Instruct inference step — executes inside a **Kaggle notebook with GPU enabled**, which installs the package (from the repo, e.g. via `pip install -e .` after cloning/uploading) and calls its functions. This is where free GPU access comes from; there is no local-venv end-to-end run.
- Corpus documents are supplied to the Kaggle notebook as a Kaggle Dataset (uploaded once as the static snapshot). FAISS index is built fresh each notebook session from that dataset.
- Digest markdown output and the per-run audit JSONL both write to the notebook's `/kaggle/working` output directory, downloadable after the run.
- Local dependency management is venv + requirements.txt for the package itself and its test suite; the Kaggle notebook has its own environment (Kaggle's base image + `pip install` of this package), not the local venv.

## Testing / validation approach

No automated retrieval eval harness in this build. Validation is manual: after a digest run, spot-check several entries by reading the source document alongside the generated summary and rationale, checking that every claim in the summary traces back to retrieved chunk content. This is the primary purpose of Build B — proving the RAG core is trustworthy before adding the structured lane, filter, and synthesis stages that depend on it.

## Path to Option A

Once Build B's retrieval and grounding are validated, growth to Option A adds (without changing Build B's core loop):
1. A structured lane over CISA KEV / NVD, queried/filtered directly (no embedding)
2. A router deciding which lane(s) apply per item
3. A rule-based high-risk gate before the LLM analysis step (hard filters: KEV membership, CVSS ≥ 9 + confirmed exploitation, named campaign keyword match)
4. A synthesis stage after grounded analysis: TTP/ATT&CK mapping, required log sources, detection feasibility, and a recommendation (new use case / tune existing rule / watchlist / hunting query)
5. Scheduling as a daily HF Space background job, dedup against previously-seen items, and delivery as a markdown report + email digest
6. The audit log format defined here (per-item record: input, decision, LLM prompt/output) carries forward unchanged as the audit trail for the full pipeline
