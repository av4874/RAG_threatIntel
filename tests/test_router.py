import json
from datetime import date, timedelta

from threat_digest.router import (
    build_unified_digest,
    extract_cve_ids,
    extract_title,
    load_analysis_records,
    load_kev_entries,
)


def test_extract_cve_ids_finds_all_matches_in_text():
    text = "This affects CVE-2026-15409 and also CVE-2026-15410, chained together."
    assert extract_cve_ids(text) == {"CVE-2026-15409", "CVE-2026-15410"}


def test_extract_cve_ids_returns_empty_set_when_none_present():
    assert extract_cve_ids("No CVE mentioned in this passage at all.") == set()


def test_extract_title_reads_fixed_prompt_phrase():
    prompt = (
        'You are a threat intelligence analyst. Read the following retrieved '
        'passages from a document titled "SonicWall SMA1000 Zero-Days" and '
        'produce a grounded assessment.'
    )
    assert extract_title(prompt) == "SonicWall SMA1000 Zero-Days"


def test_extract_title_handles_embedded_quote_in_title():
    prompt = (
        'You are a threat intelligence analyst. Read the following retrieved '
        'passages from a document titled "WordPress Core "wp2shell" RCE flaws '
        'get public exploits, patch now" and produce a grounded assessment.'
    )
    assert extract_title(prompt) == 'WordPress Core "wp2shell" RCE flaws get public exploits, patch now'


def _write_audit_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def _analysis_record(doc_id, title, chunk_text, risk_score):
    return {
        "doc_id": doc_id,
        "stage": "analysis",
        "retrieved_chunks": [[chunk_text, 0.9]],
        "prompt": (
            f'Read the following retrieved passages from a document titled '
            f'"{title}" and produce a grounded assessment.'
        ),
        "raw_llm_output": "{}",
        "risk_score": risk_score,
        "timestamp": "2026-07-19T00:00:00",
    }


def test_load_analysis_records_filters_out_synthesis_stage(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    analysis = _analysis_record("doc1", "Title One", "no cve here", 8)
    synthesis = {**analysis, "stage": "synthesis"}
    _write_audit_jsonl(audit_path, [analysis, synthesis])

    records = load_analysis_records(audit_path)

    assert len(records) == 1
    assert records[0]["doc_id"] == "doc1"


def test_load_kev_entries_reads_json_array(tmp_path):
    kev_path = tmp_path / "kev_data.json"
    kev_path.write_text(json.dumps([{"cve_id": "CVE-2026-15409"}]), encoding="utf-8")

    entries = load_kev_entries(kev_path)

    assert entries == [{"cve_id": "CVE-2026-15409"}]


def _kev_entry(cve_id, vendor="Vendor", product="Product", ransomware=False, date_added="2026-07-01"):
    return {
        "cve_id": cve_id,
        "vendor_project": vendor,
        "product": product,
        "vulnerability_name": f"{cve_id} vulnerability",
        "date_added": date_added,
        "short_description": "desc",
        "required_action": "patch",
        "due_date": "2026-07-10",
        "known_ransomware_use": ransomware,
    }


def test_build_unified_digest_puts_dual_confirmed_cve_in_first_section(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [
        _analysis_record(
            "doc1", "SonicWall Zero-Day",
            "Attackers are exploiting CVE-2026-15409 in the wild.", 9,
        ),
    ])
    kev_path.write_text(
        json.dumps([_kev_entry("CVE-2026-15409", vendor="SonicWall")]),
        encoding="utf-8",
    )

    result = build_unified_digest(audit_path, kev_path)

    dual_section = result.split("## RAG-Only")[0]
    assert "CVE-2026-15409" in dual_section
    assert "SonicWall Zero-Day" in dual_section
    assert "SonicWall" in dual_section


def _synthesis_record(doc_id):
    return {
        "doc_id": doc_id,
        "stage": "synthesis",
        "retrieved_chunks": [["irrelevant for synthesis lookup", 0.9]],
        "prompt": "irrelevant for synthesis lookup",
        "raw_llm_output": json.dumps({
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "log_sources": ["Web server access logs", "Firewall/VPN logs"],
            "feasibility": "High",
            "feasibility_reason": "Directly observable in web server logs.",
            "recommendation": "New use case",
            "recommendation_reason": "No existing rule covers this pattern.",
        }),
        "risk_score": 9,
        "timestamp": "2026-07-19T00:00:00",
    }


def test_build_unified_digest_includes_synthesis_fields_when_present(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [
        _analysis_record("doc1", "SonicWall Zero-Day", "Attackers are exploiting CVE-2026-15409.", 9),
        _synthesis_record("doc1"),
    ])
    kev_path.write_text(
        json.dumps([_kev_entry("CVE-2026-15409", vendor="SonicWall")]),
        encoding="utf-8",
    )

    result = build_unified_digest(audit_path, kev_path)

    dual_section = result.split("## RAG-Only")[0]
    assert "**ATT&CK Technique:** T1190 - Exploit Public-Facing Application" in dual_section
    assert "**Log Sources:** Web server access logs, Firewall/VPN logs" in dual_section
    assert "**Detection Feasibility:** High - Directly observable in web server logs." in dual_section
    assert "**Recommendation:** New use case - No existing rule covers this pattern." in dual_section


def test_build_unified_digest_omits_synthesis_fields_when_absent(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [
        _analysis_record("doc1", "Unmatched High Risk Article", "no cve mentioned", 8),
    ])
    kev_path.write_text(json.dumps([]), encoding="utf-8")

    result = build_unified_digest(audit_path, kev_path)

    assert "ATT&CK Technique" not in result


def test_build_unified_digest_puts_unmatched_high_risk_article_in_rag_only_section(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [
        _analysis_record("doc1", "Unmatched High Risk Article", "no cve mentioned", 8),
    ])
    kev_path.write_text(json.dumps([]), encoding="utf-8")

    result = build_unified_digest(audit_path, kev_path)

    rag_only_section = result.split("## RAG-Only")[1].split("## KEV-Only")[0]
    assert "Unmatched High Risk Article" in rag_only_section


def test_build_unified_digest_omits_low_risk_unmatched_article(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [
        _analysis_record("doc1", "Low Risk Article", "no cve mentioned", 3),
    ])
    kev_path.write_text(json.dumps([]), encoding="utf-8")

    result = build_unified_digest(audit_path, kev_path)

    assert "Low Risk Article" not in result


def test_build_unified_digest_kev_only_section_excludes_matched_cves_and_caps_at_30(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [
        _analysis_record("doc1", "Matched Article", "See CVE-2026-00001 for details.", 9),
    ])
    base_date = date(2026, 7, 19)
    kev_entries = [
        _kev_entry("CVE-2026-00001", date_added=base_date.isoformat())
    ] + [
        _kev_entry(f"CVE-2026-{i:05d}", date_added=(base_date - timedelta(days=i)).isoformat())
        for i in range(2, 40)
    ]
    kev_path.write_text(json.dumps(kev_entries), encoding="utf-8")

    result = build_unified_digest(audit_path, kev_path)

    kev_only_section = result.split("## KEV-Only")[1]
    assert "CVE-2026-00001" not in kev_only_section
    assert kev_only_section.count("### CVE-") == 30
    # CVE-2026-00002 has the most recent date_added among the unmatched
    # entries, so it must survive the recency-ordered cap.
    assert "CVE-2026-00002" in kev_only_section


def test_build_unified_digest_kev_only_orders_by_recency_not_ransomware_status(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kev_path = tmp_path / "kev_data.json"

    _write_audit_jsonl(audit_path, [])
    kev_path.write_text(
        json.dumps([
            _kev_entry("CVE-2026-00001", ransomware=False, date_added="2026-07-19"),
            _kev_entry("CVE-2026-00002", ransomware=True, date_added="2026-07-01"),
        ]),
        encoding="utf-8",
    )

    result = build_unified_digest(audit_path, kev_path)

    kev_only_section = result.split("## KEV-Only")[1]
    # CVE-2026-00001 is more recent (2026-07-19) despite not being
    # ransomware-linked, and CVE-2026-00002 is older despite being
    # ransomware-linked -- confirms ordering is by recency, not by
    # ransomware status.
    assert kev_only_section.index("CVE-2026-00001") < kev_only_section.index("CVE-2026-00002")
