import json
import urllib.request
from dataclasses import dataclass

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KEVEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: bool


def fetch_kev_catalog(url: str) -> list[KEVEntry]:
    with urllib.request.urlopen(url) as response:
        data = json.loads(response.read().decode("utf-8"))

    entries = []
    for item in data["vulnerabilities"]:
        entries.append(
            KEVEntry(
                cve_id=item["cveID"],
                vendor_project=item["vendorProject"],
                product=item["product"],
                vulnerability_name=item["vulnerabilityName"],
                date_added=item["dateAdded"],
                short_description=item["shortDescription"],
                required_action=item["requiredAction"],
                due_date=item["dueDate"],
                known_ransomware_use=item["knownRansomwareCampaignUse"] == "Known",
            )
        )
    return entries


def rank_kev_entries(entries: list[KEVEntry]) -> list[KEVEntry]:
    return sorted(entries, key=lambda entry: not entry.known_ransomware_use)


def format_kev_digest_markdown(entries: list[KEVEntry]) -> str:
    if not entries:
        return "# CISA KEV Digest\n\nNo entries in this run.\n"

    lines = ["# CISA KEV Digest", ""]
    for entry in entries:
        ransomware_note = " (RANSOMWARE-LINKED)" if entry.known_ransomware_use else ""
        lines.append(
            f"## {entry.cve_id} - {entry.vendor_project} {entry.product}{ransomware_note}"
        )
        lines.append(f"**Vulnerability:** {entry.vulnerability_name}")
        lines.append("")
        lines.append(f"**Description:** {entry.short_description}")
        lines.append("")
        lines.append(f"**Required Action:** {entry.required_action}")
        lines.append("")
        lines.append(f"**Date Added:** {entry.date_added} | **Due Date:** {entry.due_date}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    catalog = fetch_kev_catalog(KEV_FEED_URL)
    top_200 = catalog[:200]
    ranked = rank_kev_entries(top_200)
    digest_markdown = format_kev_digest_markdown(ranked)
    with open("kev_digest.md", "w", encoding="utf-8") as f:
        f.write(digest_markdown)
    ransomware_count = sum(1 for e in ranked if e.known_ransomware_use)
    print(f"Wrote KEV digest with {len(ranked)} entries ({ransomware_count} ransomware-linked).")
