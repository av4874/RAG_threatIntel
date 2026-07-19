import pytest

from threat_digest.synthesis import (
    SynthesisResult,
    build_synthesis_prompt,
    parse_synthesis_response,
)


def test_build_synthesis_prompt_includes_title_chunks_and_vocabularies():
    prompt = build_synthesis_prompt("SonicWall Zero-Day", ["chunk one text"])
    assert "SonicWall Zero-Day" in prompt
    assert "chunk one text" in prompt
    assert "Windows Security Event Log" in prompt
    assert "New use case" in prompt
    assert "High" in prompt


def test_parse_synthesis_response_reads_valid_json_with_verified_technique():
    raw = (
        '{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", '
        '"log_sources": ["Web server access logs"], "feasibility": "High", '
        '"feasibility_reason": "reason", "recommendation": "New use case", '
        '"recommendation_reason": "reason2"}'
    )
    result = parse_synthesis_response(raw)
    assert result == SynthesisResult(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        technique_verified=True,
        log_sources=["Web server access logs"],
        feasibility="High",
        feasibility_reason="reason",
        recommendation="New use case",
        recommendation_reason="reason2",
    )


def test_parse_synthesis_response_corrects_wrong_name_for_valid_technique_id():
    raw = (
        '{"technique_id": "T1190", "technique_name": "Remote Code Execution", '
        '"log_sources": ["Web server access logs"], "feasibility": "High", '
        '"feasibility_reason": "reason", "recommendation": "New use case", '
        '"recommendation_reason": "reason2"}'
    )
    result = parse_synthesis_response(raw)
    assert result.technique_verified is True
    assert result.technique_name == "Exploit Public-Facing Application"


def test_parse_synthesis_response_marks_fake_technique_id_unverified():
    raw = (
        '{"technique_id": "T9999", "technique_name": "Made Up Technique", '
        '"log_sources": ["DNS logs"], "feasibility": "Low", '
        '"feasibility_reason": "reason", "recommendation": "Watchlist", '
        '"recommendation_reason": "reason2"}'
    )
    result = parse_synthesis_response(raw)
    assert result.technique_verified is False


def test_parse_synthesis_response_raises_on_malformed_json():
    with pytest.raises(ValueError, match="could not parse synthesis response as JSON"):
        parse_synthesis_response("not json at all")
