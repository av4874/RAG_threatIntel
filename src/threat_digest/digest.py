from dataclasses import dataclass


@dataclass
class DigestItem:
    doc_id: str
    title: str
    source_url: str
    summary: str
    rationale: str
    risk_score: int
    technique_id: str | None = None
    technique_name: str | None = None
    technique_verified: bool | None = None
    log_sources: list[str] | None = None
    feasibility: str | None = None
    feasibility_reason: str | None = None
    recommendation: str | None = None
    recommendation_reason: str | None = None


def rank_items(items: list[DigestItem]) -> list[DigestItem]:
    return sorted(items, key=lambda item: item.risk_score, reverse=True)


def format_digest_markdown(items: list[DigestItem]) -> str:
    if not items:
        return "# Threat Intel Digest\n\nNo high-risk items found in this run.\n"

    ranked = rank_items(items)
    lines = ["# Threat Intel Digest", ""]
    for item in ranked:
        lines.append(f"## {item.title} (risk score: {item.risk_score}/10)")
        lines.append(f"Source: {item.source_url}")
        lines.append("")
        lines.append(f"**Summary:** {item.summary}")
        lines.append("")
        lines.append(f"**Why high-risk:** {item.rationale}")
        lines.append("")
        if item.technique_id is not None:
            verified_note = "" if item.technique_verified else " (UNVERIFIED)"
            lines.append(
                f"**ATT&CK Technique:** {item.technique_id} - "
                f"{item.technique_name}{verified_note}"
            )
            lines.append(f"**Log Sources:** {', '.join(item.log_sources)}")
            lines.append(
                f"**Detection Feasibility:** {item.feasibility} - {item.feasibility_reason}"
            )
            lines.append(
                f"**Recommendation:** {item.recommendation} - {item.recommendation_reason}"
            )
            lines.append("")
    return "\n".join(lines)
