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


class PartiallyFailingLLMClient:
    """Returns invalid JSON for the RCE doc, valid JSON for everything else,
    so failure handling can be tested without killing the whole run."""

    def generate(self, prompt: str) -> str:
        if "Critical RCE in Widget Server" in prompt:
            return "not valid json at all"
        return json.dumps(
            {
                "summary": "generated summary",
                "rationale": "generated rationale",
                "risk_score": 3,
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
    # 3, not 2: doc001 ("Critical RCE...") now legitimately scores high enough
    # to trigger a second (synthesis) LLM call. FakeLLMClient doesn't implement
    # synthesis responses, so that call fails to parse and correctly writes its
    # own "malformed synthesis" audit record alongside the two analysis records.
    assert len(lines) == 3
    doc_ids = {json.loads(line)["doc_id"] for line in lines}
    assert doc_ids == {"doc001", "doc002"}


def test_run_pipeline_continues_past_a_document_with_unparseable_llm_output(tmp_path):
    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=PartiallyFailingLLMClient(),
        k=3,
    )

    digest_text = digest_path.read_text(encoding="utf-8")
    assert "Widget Server 4.3 Adds Dark Mode" in digest_text
    assert "Critical RCE in Widget Server" not in digest_text

    audit_path = tmp_path / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    records = {json.loads(line)["doc_id"]: json.loads(line) for line in lines}
    assert records["doc001"]["risk_score"] == -1
    assert records["doc001"]["raw_llm_output"] == "not valid json at all"
    assert records["doc002"]["risk_score"] == 3


def test_run_pipeline_adds_synthesis_fields_for_high_risk_items(tmp_path):
    class SynthesizingLLMClient:
        def generate(self, prompt: str) -> str:
            if "detection engineer" in prompt:
                return json.dumps(
                    {
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "log_sources": ["Web server access logs"],
                        "feasibility": "High",
                        "feasibility_reason": "visible in logs",
                        "recommendation": "New use case",
                        "recommendation_reason": "no existing coverage",
                    }
                )
            risk_score = 9 if "exploit" in prompt.lower() else 3
            return json.dumps(
                {
                    "summary": "generated summary",
                    "rationale": "generated rationale",
                    "risk_score": risk_score,
                }
            )

    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=SynthesizingLLMClient(),
        k=3,
    )

    digest_text = digest_path.read_text(encoding="utf-8")
    assert "T1190 - Exploit Public-Facing Application" in digest_text
    dark_mode_section = digest_text[digest_text.index("Widget Server 4.3 Adds Dark Mode"):]
    assert "ATT&CK Technique" not in dark_mode_section


def test_run_pipeline_skips_synthesis_for_low_risk_items(tmp_path):
    class LowRiskLLMClient:
        def generate(self, prompt: str) -> str:
            if "detection engineer" in prompt:
                raise AssertionError("synthesis should not be called for low-risk items")
            return json.dumps(
                {
                    "summary": "generated summary",
                    "rationale": "generated rationale",
                    "risk_score": 3,
                }
            )

    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=LowRiskLLMClient(),
        k=3,
    )
    assert digest_path.exists()


def test_run_pipeline_keeps_item_when_synthesis_response_is_malformed(tmp_path):
    class BrokenSynthesisLLMClient:
        def generate(self, prompt: str) -> str:
            if "detection engineer" in prompt:
                return "not valid json"
            risk_score = 9 if "exploit" in prompt.lower() else 3
            return json.dumps(
                {
                    "summary": "generated summary",
                    "rationale": "generated rationale",
                    "risk_score": risk_score,
                }
            )

    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=BrokenSynthesisLLMClient(),
        k=3,
    )

    digest_text = digest_path.read_text(encoding="utf-8")
    assert "Critical RCE in Widget Server" in digest_text
    assert "ATT&CK Technique" not in digest_text
