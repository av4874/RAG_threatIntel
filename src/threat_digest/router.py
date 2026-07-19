import json
import re
from pathlib import Path

from threat_digest.synthesis import SynthesisResult, parse_synthesis_response

RISK_THRESHOLD = 6
KEV_ONLY_CAP = 30

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
TITLE_PATTERN = re.compile(r'document titled "(.*)" and produce a grounded assessment')


def extract_cve_ids(text: str) -> set[str]:
    return set(CVE_PATTERN.findall(text))


def extract_title(prompt: str) -> str:
    match = TITLE_PATTERN.search(prompt)
    if not match:
        raise ValueError("could not extract title from prompt")
    return match.group(1)


def load_analysis_records(audit_path: Path) -> list[dict]:
    records = []
    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("stage") == "analysis":
                records.append(record)
    return records


def load_kev_entries(kev_data_path: Path) -> list[dict]:
    with open(kev_data_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_synthesis_by_doc_id(audit_path: Path) -> dict[str, SynthesisResult]:
    results = {}
    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("stage") != "synthesis":
                continue
            try:
                results[record["doc_id"]] = parse_synthesis_response(record["raw_llm_output"])
            except ValueError:
                continue
    return results


def _append_synthesis_lines(lines: list[str], synthesis: SynthesisResult | None) -> None:
    if synthesis is None:
        return
    verified_note = "" if synthesis.technique_verified else " (UNVERIFIED)"
    lines.append(
        f"**ATT&CK Technique:** {synthesis.technique_id} - "
        f"{synthesis.technique_name}{verified_note}"
    )
    lines.append(f"**Log Sources:** {', '.join(synthesis.log_sources)}")
    lines.append(
        f"**Detection Feasibility:** {synthesis.feasibility} - {synthesis.feasibility_reason}"
    )
    lines.append(
        f"**Recommendation:** {synthesis.recommendation} - {synthesis.recommendation_reason}"
    )


def build_unified_digest(audit_path: Path, kev_data_path: Path) -> str:
    analysis_records = load_analysis_records(audit_path)
    kev_entries = load_kev_entries(kev_data_path)
    kev_by_cve = {entry["cve_id"]: entry for entry in kev_entries}
    synthesis_by_doc_id = load_synthesis_by_doc_id(audit_path)

    dual_confirmed = []
    rag_only = []
    matched_cve_ids = set()

    for record in analysis_records:
        title = extract_title(record["prompt"])
        chunk_text = " ".join(chunk[0] for chunk in record["retrieved_chunks"])
        cve_ids = extract_cve_ids(chunk_text)
        risk_score = record["risk_score"]
        synthesis = synthesis_by_doc_id.get(record["doc_id"])

        matched_entries = [kev_by_cve[cve_id] for cve_id in cve_ids if cve_id in kev_by_cve]
        if matched_entries:
            matched_cve_ids.update(entry["cve_id"] for entry in matched_entries)
            dual_confirmed.append((title, risk_score, matched_entries, synthesis))
        elif risk_score >= RISK_THRESHOLD:
            rag_only.append((title, risk_score, synthesis))

    unmatched_kev = [
        entry for entry in kev_entries if entry["cve_id"] not in matched_cve_ids
    ]
    # Re-sort by recency (not the ransomware-first order kev_data.json
    # arrives in) so a hard cap doesn't overrepresent the ~9% of entries
    # that are ransomware-linked -- see design spec rationale.
    kev_only = sorted(
        unmatched_kev, key=lambda entry: entry["date_added"], reverse=True
    )[:KEV_ONLY_CAP]

    lines = ["# Unified Threat Digest", ""]

    lines.append("## Dual-Confirmed (RAG article + CISA KEV)")
    lines.append("")
    if dual_confirmed:
        for title, risk_score, matched_entries, synthesis in dual_confirmed:
            for entry in matched_entries:
                lines.append(
                    f"### {entry['cve_id']} - {title} (risk score: {risk_score}/10)"
                )
                lines.append(
                    f"**Vendor/Product:** {entry['vendor_project']} {entry['product']}"
                )
                lines.append(f"**Vulnerability:** {entry['vulnerability_name']}")
                _append_synthesis_lines(lines, synthesis)
                lines.append("")
    else:
        lines.append("No dual-confirmed items in this run.")
        lines.append("")

    lines.append("## RAG-Only High-Risk (not in CISA KEV)")
    lines.append("")
    if rag_only:
        for title, risk_score, synthesis in rag_only:
            lines.append(f"### {title} (risk score: {risk_score}/10)")
            _append_synthesis_lines(lines, synthesis)
            lines.append("")
    else:
        lines.append("No RAG-only high-risk items in this run.")
        lines.append("")

    lines.append("## KEV-Only (not covered by RAG lane)")
    lines.append("")
    if kev_only:
        for entry in kev_only:
            ransomware_note = (
                " (RANSOMWARE-LINKED)" if entry["known_ransomware_use"] else ""
            )
            lines.append(
                f"### {entry['cve_id']} - {entry['vendor_project']} "
                f"{entry['product']}{ransomware_note}"
            )
            lines.append(f"**Vulnerability:** {entry['vulnerability_name']}")
            lines.append("")
    else:
        lines.append("No KEV-only items in this run.")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    digest_markdown = build_unified_digest(Path("audit.jsonl"), Path("kev_data.json"))
    with open("unified_digest.md", "w", encoding="utf-8") as f:
        f.write(digest_markdown)
    print("Wrote unified_digest.md")
