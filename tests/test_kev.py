import json

from threat_digest.kev import (
    KEVEntry,
    fetch_kev_catalog,
    format_kev_digest_markdown,
    rank_kev_entries,
)

SAMPLE_KEV_JSON = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.07.16",
    "dateReleased": "2026-07-16T00:00:00.0000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-56164",
            "vendorProject": "Microsoft",
            "product": "SharePoint Server",
            "vulnerabilityName": "Microsoft SharePoint Server Elevation of Privilege Vulnerability",
            "dateAdded": "2026-07-14",
            "shortDescription": "Microsoft SharePoint Server contains an elevation of privilege vulnerability.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2026-07-17",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-287"],
        },
        {
            "cveID": "CVE-2026-15409",
            "vendorProject": "SonicWall",
            "product": "SMA1000",
            "vulnerabilityName": "SonicWall SMA1000 Server-Side Request Forgery Vulnerability",
            "dateAdded": "2026-07-13",
            "shortDescription": "SonicWall SMA1000 contains a server-side request forgery vulnerability.",
            "requiredAction": "Apply hotfix per vendor instructions.",
            "dueDate": "2026-07-17",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-918"],
        },
        {
            "cveID": "CVE-2026-99999",
            "vendorProject": "ExampleCorp",
            "product": "ExampleProduct",
            "vulnerabilityName": "Example Vulnerability",
            "dateAdded": "2026-07-12",
            "shortDescription": "An example vulnerability for testing.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2026-07-20",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-79"],
        },
    ],
}


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def test_fetch_kev_catalog_parses_entries(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda url: FakeResponse(SAMPLE_KEV_JSON)
    )

    entries = fetch_kev_catalog("https://example.com/kev.json")

    assert len(entries) == 3
    assert entries[0] == KEVEntry(
        cve_id="CVE-2026-56164",
        vendor_project="Microsoft",
        product="SharePoint Server",
        vulnerability_name="Microsoft SharePoint Server Elevation of Privilege Vulnerability",
        date_added="2026-07-14",
        short_description="Microsoft SharePoint Server contains an elevation of privilege vulnerability.",
        required_action="Apply mitigations per vendor instructions.",
        due_date="2026-07-17",
        known_ransomware_use=False,
    )
    assert entries[1].known_ransomware_use is True
    assert entries[2].known_ransomware_use is False


def test_rank_kev_entries_puts_ransomware_linked_first_preserving_order():
    entries = [
        KEVEntry("CVE-1", "V1", "P1", "N1", "2026-07-01", "D1", "R1", "2026-07-10", False),
        KEVEntry("CVE-2", "V2", "P2", "N2", "2026-07-02", "D2", "R2", "2026-07-11", True),
        KEVEntry("CVE-3", "V3", "P3", "N3", "2026-07-03", "D3", "R3", "2026-07-12", False),
        KEVEntry("CVE-4", "V4", "P4", "N4", "2026-07-04", "D4", "R4", "2026-07-13", True),
    ]

    ranked = rank_kev_entries(entries)

    assert [e.cve_id for e in ranked] == ["CVE-2", "CVE-4", "CVE-1", "CVE-3"]


def test_format_kev_digest_markdown_includes_fields_and_ransomware_flag():
    entries = [
        KEVEntry(
            cve_id="CVE-2026-15409",
            vendor_project="SonicWall",
            product="SMA1000",
            vulnerability_name="SonicWall SMA1000 SSRF Vulnerability",
            date_added="2026-07-13",
            short_description="A server-side request forgery vulnerability.",
            required_action="Apply hotfix per vendor instructions.",
            due_date="2026-07-17",
            known_ransomware_use=True,
        ),
        KEVEntry(
            cve_id="CVE-2026-56164",
            vendor_project="Microsoft",
            product="SharePoint Server",
            vulnerability_name="Microsoft SharePoint Elevation of Privilege",
            date_added="2026-07-14",
            short_description="An elevation of privilege vulnerability.",
            required_action="Apply mitigations per vendor instructions.",
            due_date="2026-07-17",
            known_ransomware_use=False,
        ),
    ]

    md = format_kev_digest_markdown(entries)

    assert "CVE-2026-15409" in md
    assert "SonicWall SMA1000" in md
    assert "(RANSOMWARE-LINKED)" in md
    assert "A server-side request forgery vulnerability." in md
    assert "Apply hotfix per vendor instructions." in md
    assert "2026-07-13" in md and "2026-07-17" in md
    sharepoint_heading_line = next(
        line for line in md.splitlines() if line.startswith("## CVE-2026-56164")
    )
    assert "(RANSOMWARE-LINKED)" not in sharepoint_heading_line


def test_format_kev_digest_markdown_handles_empty_list():
    md = format_kev_digest_markdown([])
    assert "No entries" in md
