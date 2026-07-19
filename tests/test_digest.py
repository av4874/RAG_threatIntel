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


ITEM_WITH_SYNTHESIS = DigestItem(
    doc_id="doc002", title="High Score Item", source_url="https://example.com/b",
    summary="summary", rationale="rationale", risk_score=9,
    technique_id="T1190", technique_name="Exploit Public-Facing Application",
    technique_verified=True, log_sources=["Web server access logs"],
    feasibility="High", feasibility_reason="visible in logs",
    recommendation="New use case", recommendation_reason="no existing coverage",
)

ITEM_WITH_UNVERIFIED_SYNTHESIS = DigestItem(
    doc_id="doc003", title="Unverified Item", source_url="https://example.com/c",
    summary="summary", rationale="rationale", risk_score=8,
    technique_id="T9999", technique_name="Made Up", technique_verified=False,
    log_sources=["DNS logs"], feasibility="Low", feasibility_reason="reason",
    recommendation="Watchlist", recommendation_reason="reason2",
)


def test_format_digest_markdown_omits_synthesis_section_when_absent():
    md = format_digest_markdown([LOW])
    assert "ATT&CK Technique" not in md
    assert "Recommendation" not in md


def test_format_digest_markdown_includes_synthesis_section_when_present():
    md = format_digest_markdown([ITEM_WITH_SYNTHESIS])
    assert "T1190 - Exploit Public-Facing Application" in md
    assert "Web server access logs" in md
    assert "High - visible in logs" in md
    assert "New use case - no existing coverage" in md


def test_format_digest_markdown_flags_unverified_technique():
    md = format_digest_markdown([ITEM_WITH_UNVERIFIED_SYNTHESIS])
    assert "T9999 - Made Up (UNVERIFIED)" in md
