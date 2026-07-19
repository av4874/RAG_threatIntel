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


def test_write_audit_record_defaults_stage_to_analysis(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    write_audit_record(
        audit_path,
        doc_id="doc001",
        retrieved_chunks=[("chunk", 0.5)],
        prompt="prompt text",
        raw_llm_output='{"summary": "s"}',
        risk_score=5,
        timestamp="2026-07-19T00:00:00Z",
    )
    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["stage"] == "analysis"


def test_write_audit_record_accepts_explicit_stage(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    write_audit_record(
        audit_path,
        doc_id="doc001",
        retrieved_chunks=[("chunk", 0.5)],
        prompt="prompt text",
        raw_llm_output='{"technique_id": "T1190"}',
        risk_score=9,
        timestamp="2026-07-19T00:00:00Z",
        stage="synthesis",
    )
    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["stage"] == "synthesis"
