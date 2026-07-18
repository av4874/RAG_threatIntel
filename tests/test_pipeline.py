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
