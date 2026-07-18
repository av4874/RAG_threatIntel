from dataclasses import dataclass


@dataclass
class DigestItem:
    doc_id: str
    title: str
    source_url: str
    summary: str
    rationale: str
    risk_score: int


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
    return "\n".join(lines)
