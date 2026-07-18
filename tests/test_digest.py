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
