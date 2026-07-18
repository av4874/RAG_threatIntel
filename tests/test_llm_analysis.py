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
