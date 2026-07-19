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
    stage: str = "analysis",
) -> None:
    record = {
        "doc_id": doc_id,
        "stage": stage,
        "retrieved_chunks": [list(chunk) for chunk in retrieved_chunks],
        "prompt": prompt,
        "raw_llm_output": raw_llm_output,
        "risk_score": risk_score,
        "timestamp": timestamp,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
