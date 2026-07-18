# Threat Intel RAG Digest — Build B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the standalone RAG core (Build B) from `docs/superpowers/specs/2026-07-17-threat-intel-rag-digest-design.md`: chunk + embed a static unstructured threat-intel corpus, retrieve each document's most risk-relevant passages, generate a grounded per-document summary/risk score via an LLM, and produce a ranked markdown digest with a full per-item audit log.

**Architecture:** A plain, GPU-free Python package (`src/threat_digest/`) holds all pipeline logic — corpus loading, chunking, embedding, per-document retrieval (sentence-transformers + FAISS), prompt construction, response parsing, ranking, digest formatting, and audit logging. The LLM call is behind an `LLMClient` protocol so local tests inject a fake client (no GPU/network) while a real `QwenLLMClient` runs only inside a Kaggle notebook with GPU enabled, which imports this package and drives the actual end-to-end run.

**Tech Stack:** Python 3.11+, sentence-transformers, faiss-cpu, numpy, pytest. Kaggle notebook uses transformers + torch for Qwen2.5-7B-Instruct inference.

## Global Constraints

- Dependency management: venv + `requirements.txt` (per spec's Execution Environment section).
- Embedding model: `sentence-transformers/all-MiniLM-L6-v2` (small, CPU-friendly, runs in local tests).
- LLM model: Qwen2.5-7B-Instruct, real inference only inside the Kaggle notebook — never required for local unit/integration tests.
- Every pipeline stage's input/output is captured in the per-run audit log (per spec).
- No placeholders, no speculative error handling beyond what's specified — YAGNI.

---

## File Structure

```
RAG_threatIntel/
  requirements.txt
  src/threat_digest/
    __init__.py
    corpus.py         # Document dataclass, load_corpus()
    chunking.py        # chunk_text()
    retrieval.py        # RISK_QUERY, retrieve_top_chunks_for_document()
    llm_analysis.py    # AnalysisResult, LLMClient, build_prompt(), parse_llm_response(), analyze_document()
    digest.py          # DigestItem, rank_items(), format_digest_markdown()
    audit.py           # write_audit_record()
    pipeline.py        # run_pipeline()
  tests/
    __init__.py
    test_corpus.py
    test_chunking.py
    test_retrieval.py
    test_llm_analysis.py
    test_digest.py
    test_audit.py
    test_pipeline.py
    fixtures/
      corpus/
        doc001.txt
        doc002.txt
  corpus/
    README.md          # real-corpus file format + collection instructions (empty otherwise)
  notebooks/
    run_build_b.ipynb  # Kaggle notebook: real Qwen client + end-to-end run
```

---

### Task 1: Repository & environment scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `src/threat_digest/__init__.py`
- Create: `tests/__init__.py`
- Create: `pytest.ini`
- Create: `.gitignore`

**Interfaces:**
- Produces: an installable local package `threat_digest` importable from tests via `src` on the path (configured in `pytest.ini`).

- [ ] **Step 1: Create `requirements.txt`**

```
sentence-transformers==3.3.1
faiss-cpu==1.9.0
numpy==1.26.4
pytest==8.3.4
```

- [ ] **Step 2: Create `.gitignore`**

```
.venv/
__pycache__/
*.pyc
*.egg-info/
.pytest_cache/
```

- [ ] **Step 3: Create package and test package markers**

`src/threat_digest/__init__.py`:
```python
```

`tests/__init__.py`:
```python
```

- [ ] **Step 4: Create `pytest.ini` so tests can import `threat_digest` from `src/`**

```ini
[pytest]
pythonpath = src
testpaths = tests
```

- [ ] **Step 5: Create venv and install dependencies**

Run:
```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
```
Expected: dependencies install without error.

- [ ] **Step 6: Verify pytest runs (no tests yet, but harness must work)**

Run: `.venv/Scripts/pytest -v`
Expected: `no tests ran` (exit code 5) — confirms pytest is wired up correctly with no errors.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt .gitignore src/threat_digest/__init__.py tests/__init__.py pytest.ini
git commit -m "chore: scaffold threat_digest package and test harness"
```

---

### Task 2: Corpus loader

**Files:**
- Create: `src/threat_digest/corpus.py`
- Test: `tests/test_corpus.py`
- Create: `tests/fixtures/corpus/doc001.txt`
- Create: `tests/fixtures/corpus/doc002.txt`

**Interfaces:**
- Produces: `Document` dataclass (`doc_id: str`, `title: str`, `source_url: str`, `text: str`) and `load_corpus(corpus_dir: Path) -> list[Document]`, used by Task 8 (pipeline).
- Corpus file format (also documented in Task 9's `corpus/README.md`): each `.txt` file's first two lines are `TITLE: <title>` and `SOURCE: <url>`, then a line containing only `---`, then the body text. The filename stem (without `.txt`) is the `doc_id`.

- [ ] **Step 1: Create fixture documents**

`tests/fixtures/corpus/doc001.txt`:
```
TITLE: Critical RCE in Widget Server Actively Exploited
SOURCE: https://example.com/blog/widget-rce
---
Security researchers have observed active exploitation of a remote code
execution vulnerability in Widget Server versions prior to 4.2.1. The flaw
allows unauthenticated attackers to execute arbitrary code by sending a
crafted request to the admin API endpoint. Proof-of-concept exploit code
is publicly available and multiple ransomware affiliates have been
observed using it to gain initial access before deploying ransomware
payloads. Organizations running Widget Server should patch immediately.
```

`tests/fixtures/corpus/doc002.txt`:
```
TITLE: Widget Server 4.3 Adds Dark Mode
SOURCE: https://example.com/blog/widget-dark-mode
---
The latest Widget Server release adds a long-requested dark mode theme
for the admin dashboard, along with minor performance improvements to
the search indexing subsystem. No security-relevant changes are included
in this release.
```

- [ ] **Step 2: Write the failing test**

`tests/test_corpus.py`:
```python
from pathlib import Path
from threat_digest.corpus import Document, load_corpus

FIXTURES = Path(__file__).parent / "fixtures" / "corpus"


def test_load_corpus_returns_one_document_per_file():
    docs = load_corpus(FIXTURES)
    assert len(docs) == 2


def test_load_corpus_parses_fields():
    docs = load_corpus(FIXTURES)
    doc = next(d for d in docs if d.doc_id == "doc001")
    assert doc.title == "Critical RCE in Widget Server Actively Exploited"
    assert doc.source_url == "https://example.com/blog/widget-rce"
    assert "remote code" in doc.text
    assert "TITLE:" not in doc.text
    assert "---" not in doc.text.splitlines()[0]


def test_document_is_a_dataclass_with_expected_fields():
    doc = Document(doc_id="x", title="t", source_url="u", text="body")
    assert doc.doc_id == "x"
    assert doc.title == "t"
    assert doc.source_url == "u"
    assert doc.text == "body"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_corpus.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.corpus'`

- [ ] **Step 4: Implement `corpus.py`**

```python
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Document:
    doc_id: str
    title: str
    source_url: str
    text: str


def load_corpus(corpus_dir: Path) -> list[Document]:
    documents = []
    for path in sorted(Path(corpus_dir).glob("*.txt")):
        raw = path.read_text(encoding="utf-8")
        lines = raw.splitlines()
        title = lines[0].removeprefix("TITLE: ").strip()
        source_url = lines[1].removeprefix("SOURCE: ").strip()
        separator_index = lines.index("---")
        body = "\n".join(lines[separator_index + 1:]).strip()
        documents.append(
            Document(
                doc_id=path.stem,
                title=title,
                source_url=source_url,
                text=body,
            )
        )
    return documents
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_corpus.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add src/threat_digest/corpus.py tests/test_corpus.py tests/fixtures/corpus/doc001.txt tests/fixtures/corpus/doc002.txt
git commit -m "feat: add corpus loader for threat intel documents"
```

---

### Task 3: Chunking

**Files:**
- Create: `src/threat_digest/chunking.py`
- Test: `tests/test_chunking.py`

**Interfaces:**
- Consumes: nothing (pure text in).
- Produces: `chunk_text(text: str, chunk_size: int = 80, overlap: int = 20) -> list[str]`, used by Task 4 (retrieval).

- [ ] **Step 1: Write the failing test**

`tests/test_chunking.py`:
```python
from threat_digest.chunking import chunk_text


def test_short_text_returns_single_chunk():
    text = "one two three four five"
    chunks = chunk_text(text, chunk_size=80, overlap=20)
    assert chunks == ["one two three four five"]


def test_long_text_splits_into_multiple_overlapping_chunks():
    words = [f"word{i}" for i in range(100)]
    text = " ".join(words)
    chunks = chunk_text(text, chunk_size=40, overlap=10)
    assert len(chunks) > 1
    # every chunk must be non-empty and made of whole words
    for chunk in chunks:
        assert chunk.strip() != ""
        assert "word" in chunk
    # overlap: last 10 words of chunk N should appear at the start of chunk N+1
    first_chunk_words = chunks[0].split()
    second_chunk_words = chunks[1].split()
    assert first_chunk_words[-10:] == second_chunk_words[:10]


def test_empty_text_returns_no_chunks():
    assert chunk_text("", chunk_size=40, overlap=10) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_chunking.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.chunking'`

- [ ] **Step 3: Implement `chunking.py`**

```python
def chunk_text(text: str, chunk_size: int = 80, overlap: int = 20) -> list[str]:
    words = text.split()
    if not words:
        return []

    step = chunk_size - overlap
    chunks = []
    start = 0
    while start < len(words):
        chunk_words = words[start:start + chunk_size]
        chunks.append(" ".join(chunk_words))
        if start + chunk_size >= len(words):
            break
        start += step
    return chunks
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_chunking.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/chunking.py tests/test_chunking.py
git commit -m "feat: add word-based text chunking with overlap"
```

---

### Task 4: Embedding + per-document retrieval

**Files:**
- Create: `src/threat_digest/retrieval.py`
- Test: `tests/test_retrieval.py`

**Interfaces:**
- Consumes: `chunk_text()` from Task 3 (test builds chunks directly, doesn't call it).
- Produces: `RISK_QUERY: str`, `retrieve_top_chunks_for_document(chunks: list[str], k: int = 5) -> list[tuple[str, float]]`, used by Task 8 (pipeline). Returns `(chunk_text, similarity_score)` pairs, highest similarity first.

This is the one test file that downloads and runs a real (small, CPU) embedding model — `sentence-transformers/all-MiniLM-L6-v2`. First run will download ~80MB; subsequent runs use the local cache.

- [ ] **Step 1: Write the failing test**

`tests/test_retrieval.py`:
```python
from threat_digest.retrieval import retrieve_top_chunks_for_document


def test_returns_at_most_k_chunks_sorted_by_score_descending():
    chunks = [
        "The admin dashboard now supports a dark theme for night owls.",
        "Attackers are actively exploiting this remote code execution flaw in the wild.",
        "Search indexing performance was improved by roughly ten percent.",
        "A ransomware affiliate is using this critical vulnerability for initial access.",
    ]
    results = retrieve_top_chunks_for_document(chunks, k=2)
    assert len(results) == 2
    scores = [score for _, score in results]
    assert scores == sorted(scores, reverse=True)


def test_risk_relevant_chunks_rank_above_unrelated_chunks():
    chunks = [
        "The admin dashboard now supports a dark theme for night owls.",
        "Attackers are actively exploiting this critical remote code execution "
        "vulnerability in the wild, and it has been added to the CISA KEV catalog.",
    ]
    results = retrieve_top_chunks_for_document(chunks, k=2)
    top_chunk_text, _ = results[0]
    assert "exploit" in top_chunk_text.lower()


def test_k_larger_than_chunk_count_returns_all_chunks():
    chunks = ["only one chunk here"]
    results = retrieve_top_chunks_for_document(chunks, k=5)
    assert len(results) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_retrieval.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.retrieval'`

- [ ] **Step 3: Implement `retrieval.py`**

```python
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

RISK_QUERY = (
    "actively exploited vulnerability, zero-day exploit, ransomware campaign, "
    "critical severity, proof-of-concept exploit code, exploited in the wild"
)

_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _model


def retrieve_top_chunks_for_document(
    chunks: list[str], k: int = 5
) -> list[tuple[str, float]]:
    if not chunks:
        return []

    model = _get_model()
    chunk_vectors = model.encode(chunks, normalize_embeddings=True)
    query_vector = model.encode([RISK_QUERY], normalize_embeddings=True)

    dimension = chunk_vectors.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(np.asarray(chunk_vectors, dtype=np.float32))

    top_k = min(k, len(chunks))
    scores, indices = index.search(np.asarray(query_vector, dtype=np.float32), top_k)

    return [(chunks[idx], float(score)) for idx, score in zip(indices[0], scores[0])]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_retrieval.py -v`
Expected: PASS (3 passed). First run downloads the embedding model — allow extra time.

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/retrieval.py tests/test_retrieval.py
git commit -m "feat: add per-document risk-relevant chunk retrieval via FAISS"
```

---

### Task 5: LLM analysis (prompt, parsing, fake client for tests)

**Files:**
- Create: `src/threat_digest/llm_analysis.py`
- Test: `tests/test_llm_analysis.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (takes plain strings — title + retrieved chunk texts).
- Produces: `AnalysisResult` dataclass (`summary: str`, `rationale: str`, `risk_score: int`), `LLMClient` protocol (`generate(self, prompt: str) -> str`), `build_prompt(title: str, chunks: list[str]) -> str`, `parse_llm_response(raw: str) -> AnalysisResult`, `analyze_document(client: LLMClient, title: str, chunks: list[str]) -> AnalysisResult`. Used by Task 8 (pipeline); `LLMClient` is also what the Kaggle notebook's `QwenLLMClient` (Task 9) implements.

- [ ] **Step 1: Write the failing test**

`tests/test_llm_analysis.py`:
```python
import pytest

from threat_digest.llm_analysis import (
    AnalysisResult,
    build_prompt,
    parse_llm_response,
    analyze_document,
)


class FakeLLMClient:
    def __init__(self, response: str):
        self.response = response
        self.last_prompt = None

    def generate(self, prompt: str) -> str:
        self.last_prompt = prompt
        return self.response


def test_build_prompt_includes_title_and_all_chunks():
    prompt = build_prompt("Widget RCE", ["chunk one text", "chunk two text"])
    assert "Widget RCE" in prompt
    assert "chunk one text" in prompt
    assert "chunk two text" in prompt


def test_parse_llm_response_reads_valid_json():
    raw = '{"summary": "s", "rationale": "r", "risk_score": 8}'
    result = parse_llm_response(raw)
    assert result == AnalysisResult(summary="s", rationale="r", risk_score=8)


def test_parse_llm_response_strips_markdown_code_fences():
    raw = '```json\n{"summary": "s", "rationale": "r", "risk_score": 5}\n```'
    result = parse_llm_response(raw)
    assert result.risk_score == 5


def test_parse_llm_response_raises_on_malformed_json():
    with pytest.raises(ValueError, match="could not parse LLM response as JSON"):
        parse_llm_response("not json at all")


def test_analyze_document_calls_client_with_built_prompt_and_parses_result():
    client = FakeLLMClient('{"summary": "s", "rationale": "r", "risk_score": 9}')
    result = analyze_document(client, "Widget RCE", ["chunk text"])
    assert result.risk_score == 9
    assert "Widget RCE" in client.last_prompt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_llm_analysis.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.llm_analysis'`

- [ ] **Step 3: Implement `llm_analysis.py`**

```python
import json
import re
from dataclasses import dataclass
from typing import Protocol


@dataclass
class AnalysisResult:
    summary: str
    rationale: str
    risk_score: int


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str:
        ...


PROMPT_TEMPLATE = """You are a threat intelligence analyst. Read the following \
retrieved passages from a document titled "{title}" and produce a grounded \
assessment using ONLY the information in these passages. Do not invent details \
that are not present in the text below.

Passages:
{chunks_block}

Respond with ONLY a JSON object with exactly these keys:
- "summary": a 2-3 sentence grounded summary of the threat described
- "rationale": 1-2 sentences explaining why this is or isn't high-risk
- "risk_score": an integer from 1 (not risky) to 10 (critical, actively exploited)
"""


def build_prompt(title: str, chunks: list[str]) -> str:
    chunks_block = "\n\n".join(f"- {chunk}" for chunk in chunks)
    return PROMPT_TEMPLATE.format(title=title, chunks_block=chunks_block)


def parse_llm_response(raw: str) -> AnalysisResult:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError("could not parse LLM response as JSON") from exc

    return AnalysisResult(
        summary=data["summary"],
        rationale=data["rationale"],
        risk_score=int(data["risk_score"]),
    )


def analyze_document(client: LLMClient, title: str, chunks: list[str]) -> AnalysisResult:
    prompt = build_prompt(title, chunks)
    raw_response = client.generate(prompt)
    return parse_llm_response(raw_response)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_llm_analysis.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/llm_analysis.py tests/test_llm_analysis.py
git commit -m "feat: add LLM prompt building, response parsing, and analysis"
```

---

### Task 6: Digest ranking and markdown formatting

**Files:**
- Create: `src/threat_digest/digest.py`
- Test: `tests/test_digest.py`

**Interfaces:**
- Consumes: nothing directly (test constructs `DigestItem`s directly); conceptually assembled from `Document` (Task 2) + `AnalysisResult` (Task 5) fields in Task 8.
- Produces: `DigestItem` dataclass (`doc_id: str`, `title: str`, `source_url: str`, `summary: str`, `rationale: str`, `risk_score: int`), `rank_items(items: list[DigestItem]) -> list[DigestItem]`, `format_digest_markdown(items: list[DigestItem]) -> str`. Used by Task 8 (pipeline).

- [ ] **Step 1: Write the failing test**

`tests/test_digest.py`:
```python
from threat_digest.digest import DigestItem, rank_items, format_digest_markdown

LOW = DigestItem(
    doc_id="doc002", title="Dark Mode Release", source_url="https://example.com/dm",
    summary="A UI update.", rationale="No security relevance.", risk_score=1,
)
HIGH = DigestItem(
    doc_id="doc001", title="Widget RCE", source_url="https://example.com/rce",
    summary="Actively exploited RCE.", rationale="In CISA KEV, ransomware use.", risk_score=9,
)


def test_rank_items_sorts_by_risk_score_descending():
    ranked = rank_items([LOW, HIGH])
    assert [item.doc_id for item in ranked] == ["doc001", "doc002"]


def test_format_digest_markdown_includes_all_fields_in_ranked_order():
    md = format_digest_markdown([HIGH, LOW])
    high_pos = md.index("Widget RCE")
    low_pos = md.index("Dark Mode Release")
    assert high_pos < low_pos
    assert "9" in md
    assert "https://example.com/rce" in md
    assert "Actively exploited RCE." in md


def test_format_digest_markdown_handles_empty_list():
    md = format_digest_markdown([])
    assert "No high-risk items" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_digest.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.digest'`

- [ ] **Step 3: Implement `digest.py`**

```python
from dataclasses import dataclass


@dataclass
class DigestItem:
    doc_id: str
    title: str
    source_url: str
    summary: str
    rationale: str
    risk_score: int


def rank_items(items: list[DigestItem]) -> list[DigestItem]:
    return sorted(items, key=lambda item: item.risk_score, reverse=True)


def format_digest_markdown(items: list[DigestItem]) -> str:
    if not items:
        return "# Threat Intel Digest\n\nNo high-risk items found in this run.\n"

    ranked = rank_items(items)
    lines = ["# Threat Intel Digest", ""]
    for item in ranked:
        lines.append(f"## {item.title} (risk score: {item.risk_score}/10)")
        lines.append(f"Source: {item.source_url}")
        lines.append("")
        lines.append(f"**Summary:** {item.summary}")
        lines.append("")
        lines.append(f"**Why high-risk:** {item.rationale}")
        lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_digest.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/digest.py tests/test_digest.py
git commit -m "feat: add digest ranking and markdown formatting"
```

---

### Task 7: Audit logging

**Files:**
- Create: `src/threat_digest/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: nothing directly (test passes plain values); assembled from pipeline data in Task 8.
- Produces: `write_audit_record(path: Path, doc_id: str, retrieved_chunks: list[tuple[str, float]], prompt: str, raw_llm_output: str, risk_score: int, timestamp: str) -> None`, appends one JSON line to `path`. Used by Task 8 (pipeline).

- [ ] **Step 1: Write the failing test**

`tests/test_audit.py`:
```python
import json
from pathlib import Path

from threat_digest.audit import write_audit_record


def test_write_audit_record_appends_one_json_line(tmp_path):
    audit_path = tmp_path / "audit.jsonl"

    write_audit_record(
        audit_path,
        doc_id="doc001",
        retrieved_chunks=[("some chunk text", 0.87)],
        prompt="the full prompt sent to the llm",
        raw_llm_output='{"summary": "s"}',
        risk_score=9,
        timestamp="2026-07-18T00:00:00Z",
    )
    write_audit_record(
        audit_path,
        doc_id="doc002",
        retrieved_chunks=[("other chunk", 0.5)],
        prompt="another prompt",
        raw_llm_output='{"summary": "s2"}',
        risk_score=1,
        timestamp="2026-07-18T00:00:01Z",
    )

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    first_record = json.loads(lines[0])
    assert first_record["doc_id"] == "doc001"
    assert first_record["retrieved_chunks"] == [["some chunk text", 0.87]]
    assert first_record["prompt"] == "the full prompt sent to the llm"
    assert first_record["raw_llm_output"] == '{"summary": "s"}'
    assert first_record["risk_score"] == 9
    assert first_record["timestamp"] == "2026-07-18T00:00:00Z"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_audit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.audit'`

- [ ] **Step 3: Implement `audit.py`**

```python
import json
from pathlib import Path


def write_audit_record(
    path: Path,
    doc_id: str,
    retrieved_chunks: list[tuple[str, float]],
    prompt: str,
    raw_llm_output: str,
    risk_score: int,
    timestamp: str,
) -> None:
    record = {
        "doc_id": doc_id,
        "retrieved_chunks": [list(chunk) for chunk in retrieved_chunks],
        "prompt": prompt,
        "raw_llm_output": raw_llm_output,
        "risk_score": risk_score,
        "timestamp": timestamp,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_audit.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/audit.py tests/test_audit.py
git commit -m "feat: add per-item audit logging"
```

---

### Task 8: Pipeline orchestration

**Files:**
- Create: `src/threat_digest/pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `load_corpus` (Task 2), `chunk_text` (Task 3), `retrieve_top_chunks_for_document` (Task 4), `LLMClient`/`analyze_document` (Task 5), `DigestItem`/`rank_items`/`format_digest_markdown` (Task 6), `write_audit_record` (Task 7).
- Produces: `run_pipeline(corpus_dir: Path, output_dir: Path, llm_client: LLMClient, k: int = 5) -> Path`, returns path to the written digest markdown file. This is what the Kaggle notebook (Task 9) calls with a real `QwenLLMClient`.

This is the integration test: real corpus loading, real chunking, real embedding/retrieval (small CPU model, same as Task 4), but a `FakeLLMClient` in place of Qwen — confirming the full wiring works without needing a GPU.

- [ ] **Step 1: Write the failing test**

`tests/test_pipeline.py`:
```python
import json
from pathlib import Path

from threat_digest.pipeline import run_pipeline

FIXTURES = Path(__file__).parent / "fixtures" / "corpus"


class FakeLLMClient:
    """Returns a risk_score based on whether 'exploit' appears in the prompt,
    so the fake behaves plausibly enough to test ranking end-to-end."""

    def generate(self, prompt: str) -> str:
        risk_score = 9 if "exploit" in prompt.lower() else 1
        return json.dumps(
            {
                "summary": "generated summary",
                "rationale": "generated rationale",
                "risk_score": risk_score,
            }
        )


def test_run_pipeline_writes_ranked_digest_and_audit_log(tmp_path):
    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=FakeLLMClient(),
        k=3,
    )

    assert digest_path == tmp_path / "digest.md"
    digest_text = digest_path.read_text(encoding="utf-8")
    rce_pos = digest_text.index("Critical RCE in Widget Server")
    dark_mode_pos = digest_text.index("Widget Server 4.3 Adds Dark Mode")
    assert rce_pos < dark_mode_pos

    audit_path = tmp_path / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    doc_ids = {json.loads(line)["doc_id"] for line in lines}
    assert doc_ids == {"doc001", "doc002"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_pipeline.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.pipeline'`

- [ ] **Step 3: Implement `pipeline.py`**

```python
from datetime import datetime, timezone
from pathlib import Path

from threat_digest.audit import write_audit_record
from threat_digest.chunking import chunk_text
from threat_digest.corpus import load_corpus
from threat_digest.digest import DigestItem, format_digest_markdown
from threat_digest.llm_analysis import LLMClient, analyze_document, build_prompt
from threat_digest.retrieval import retrieve_top_chunks_for_document


def run_pipeline(
    corpus_dir: Path,
    output_dir: Path,
    llm_client: LLMClient,
    k: int = 5,
) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_path = output_dir / "audit.jsonl"

    documents = load_corpus(corpus_dir)
    digest_items = []

    for document in documents:
        chunks = chunk_text(document.text)
        retrieved = retrieve_top_chunks_for_document(chunks, k=k)
        retrieved_texts = [text for text, _score in retrieved]

        prompt = build_prompt(document.title, retrieved_texts)
        analysis = analyze_document(llm_client, document.title, retrieved_texts)

        write_audit_record(
            audit_path,
            doc_id=document.doc_id,
            retrieved_chunks=retrieved,
            prompt=prompt,
            raw_llm_output=llm_client.generate(prompt),
            risk_score=analysis.risk_score,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        digest_items.append(
            DigestItem(
                doc_id=document.doc_id,
                title=document.title,
                source_url=document.source_url,
                summary=analysis.summary,
                rationale=analysis.rationale,
                risk_score=analysis.risk_score,
            )
        )

    digest_markdown = format_digest_markdown(digest_items)
    digest_path = output_dir / "digest.md"
    digest_path.write_text(digest_markdown, encoding="utf-8")
    return digest_path
```

**Note on the duplicate `llm_client.generate(prompt)` call:** `analyze_document` calls the client internally to get a parsed `AnalysisResult`, but the audit log needs the *raw* response text too. Calling `generate` twice keeps `llm_analysis.py`'s interface clean (parsed result only) without threading raw output through it — acceptable here because `FakeLLMClient` and the real `QwenLLMClient` are both deterministic per prompt within a run. If this doubles real LLM cost/latency in Task 9, that's the trigger to revisit — not before.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_pipeline.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/Scripts/pytest -v`
Expected: All tests across all files PASS.

- [ ] **Step 6: Commit**

```bash
git add src/threat_digest/pipeline.py tests/test_pipeline.py
git commit -m "feat: wire up end-to-end pipeline orchestration"
```

---

### Task 9: Kaggle notebook + real corpus collection guide

**Files:**
- Create: `notebooks/run_build_b.ipynb`
- Create: `corpus/README.md`

**Interfaces:**
- Consumes: `run_pipeline` (Task 8), implements `LLMClient` (Task 5) as `QwenLLMClient`.
- Produces: nothing consumed by other tasks — this is the terminal, real-world-facing task.

- [ ] **Step 1: Write `corpus/README.md` documenting the real-corpus file format**

```markdown
# Corpus

Place one `.txt` file per source document here (blog posts, vendor advisories).
Filename (without `.txt`) becomes the document's `doc_id` — use something
stable and readable, e.g. `2026-07-18-widget-server-rce.txt`.

## Required format

```
TITLE: <document title>
SOURCE: <source URL>
---
<full body text of the document>
```

The first two lines must be `TITLE:` and `SOURCE:`, followed by a line
containing only `---`, then the body. Everything after `---` is treated as
the document text and gets chunked/embedded as-is — paste the article's
plain text (not raw HTML).

## Scope (per the Build B design spec)

Static, unstructured sources only: threat research blog posts and vendor
security advisory pages. Do not add structured CVE/NVD/KEV data here — that
becomes its own structured lane in Option A, not part of this corpus.
```

- [ ] **Step 2: Create `notebooks/run_build_b.ipynb`**

A Jupyter notebook with the following cells (create via `nbformat` or by hand — content below is the cell-by-cell source):

Cell 1 (markdown):
```markdown
# Build B — Threat Intel RAG Digest (Kaggle GPU run)

Prerequisites: enable GPU (Settings → Accelerator → GPU) and enable internet
access for this notebook. Attach the corpus as a Kaggle Dataset, or upload
the `corpus/` folder's `.txt` files directly to `/kaggle/input/`.

**Before running Cell 2:** edit `REPO_URL` below to your own GitHub repo URL
once this project has been pushed there (see the finishing-a-development-branch
step at the end of this plan's execution).
```

Cell 2 (code — install package):
```python
REPO_URL = "https://github.com/REPLACE_WITH_YOUR_USERNAME/RAG_threatIntel.git"

!pip install -q transformers accelerate torch sentence-transformers faiss-cpu
!git clone {REPO_URL} /kaggle/working/repo
!pip install -q -e /kaggle/working/repo
```

Cell 3 (code — real LLM client):
```python
import json
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME, torch_dtype=torch.bfloat16, device_map="auto"
)


class QwenLLMClient:
    def generate(self, prompt: str) -> str:
        messages = [{"role": "user", "content": prompt}]
        inputs = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        ).to(model.device)
        output_ids = model.generate(inputs, max_new_tokens=512, temperature=0.2)
        generated = output_ids[0][inputs.shape[-1]:]
        return tokenizer.decode(generated, skip_special_tokens=True)
```

Cell 4 (code — run the pipeline):
```python
from pathlib import Path
from threat_digest.pipeline import run_pipeline

digest_path = run_pipeline(
    corpus_dir=Path("/kaggle/input/threat-intel-corpus"),  # adjust to your dataset path
    output_dir=Path("/kaggle/working/output"),
    llm_client=QwenLLMClient(),
    k=5,
)
print(f"Digest written to: {digest_path}")
print(digest_path.read_text())
```

Cell 5 (markdown):
```markdown
## Validate before trusting the digest

Before treating any entry as real, open `output/audit.jsonl` and check, for a
few items: do the retrieved chunks actually support the summary and risk
score? If the model is inventing detail not present in the retrieved text,
that's a grounding failure — see the design spec's Testing/Validation section.
```

- [ ] **Step 3: Commit**

```bash
git add notebooks/run_build_b.ipynb corpus/README.md
git commit -m "docs: add Kaggle GPU notebook and corpus collection guide"
```

---

## After this plan

Build B is complete once Task 9 is committed and you've run the Kaggle notebook once against a small set of real documents you've placed in `corpus/` (per `corpus/README.md`), and manually spot-checked a few `audit.jsonl` records against their source documents (per the design spec's validation approach). Growth to Option A — structured KEV/NVD lane, router, rule-based gate, detection-engineering synthesis, scheduling — is a separate future plan, not part of this one.
