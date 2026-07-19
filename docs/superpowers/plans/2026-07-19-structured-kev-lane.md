# Structured KEV Lane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fetch CISA's public KEV catalog, select the 200 most recently added entries, rank ransomware-linked entries first, and produce a standalone `kev_digest.md`, driven by a daily GitHub Actions workflow — a second, structured-data lane alongside the existing RAG lane, with no LLM/chunking/embedding involved.

**Architecture:** One new module (`kev.py`) mirroring the existing project's style (dataclass + pure functions + `__main__` entry point, same shape as `ingest.py`), plus a GitHub Actions workflow mirroring `ingest.yml`'s structure.

**Tech Stack:** Python 3.11+ standard library only (`urllib.request`, `json`) — no new dependencies. pytest for tests.

## Global Constraints

- KEV feed URL (exact): `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- The feed's `vulnerabilities` array is already sorted most-recent-first by CISA (verified empirically) — select the top 200 via plain slicing, no client-side sorting
- Ranking rule: entries with `knownRansomwareCampaignUse == "Known"` rank above entries without, via a **stable** sort (relative order preserved within each group)
- No dedup/seen-tracking — each run overwrites `kev_digest.md` with the current top-200 snapshot (KEV entries can be updated by CISA, not just added)
- No placeholders, no speculative error handling beyond what's specified — YAGNI
- No new pip dependencies — fetch uses only the Python standard library

---

## File Structure

```
RAG_threatIntel/
  src/threat_digest/
    kev.py              # KEVEntry, fetch_kev_catalog(), rank_kev_entries(), format_kev_digest_markdown()
  tests/
    test_kev.py
  .github/workflows/
    kev_fetch.yml
```

---

### Task 1: KEV fetch, ranking, and digest formatting

**Files:**
- Create: `src/threat_digest/kev.py`
- Test: `tests/test_kev.py`

**Interfaces:**
- Produces: `KEVEntry` dataclass (`cve_id: str`, `vendor_project: str`, `product: str`, `vulnerability_name: str`, `date_added: str`, `short_description: str`, `required_action: str`, `due_date: str`, `known_ransomware_use: bool`), `fetch_kev_catalog(url: str) -> list[KEVEntry]`, `rank_kev_entries(entries: list[KEVEntry]) -> list[KEVEntry]`, `format_kev_digest_markdown(entries: list[KEVEntry]) -> str`, plus a `__main__` entry point. Used by Task 2's GitHub Actions workflow (`python -m threat_digest.kev`).

- [ ] **Step 1: Write the failing test**

`tests/test_kev.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_kev.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.kev'`

- [ ] **Step 3: Implement `kev.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_kev.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/Scripts/pytest -v`
Expected: all existing tests plus these 4 pass, no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/threat_digest/kev.py tests/test_kev.py
git commit -m "feat: add CISA KEV catalog fetch, ranking, and digest formatting"
```

---

### Task 2: GitHub Actions scheduled workflow

**Files:**
- Create: `.github/workflows/kev_fetch.yml`

**Interfaces:**
- Consumes: `kev.py`'s `__main__` entry point (Task 1), via `python -m threat_digest.kev`.
- Produces: nothing consumed by other tasks — this is the terminal, automation-facing task.

- [ ] **Step 1: Create `.github/workflows/kev_fetch.yml`**

```yaml
name: Fetch CISA KEV catalog

on:
  schedule:
    - cron: '0 7 * * *'
  workflow_dispatch: {}

jobs:
  fetch:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Fetch KEV catalog and build digest
        run: PYTHONPATH=src python -m threat_digest.kev

      - name: Commit digest
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          if [ -n "$(git status --porcelain)" ]; then
            git add kev_digest.md
            git commit -m "chore: refresh CISA KEV digest"
            git push
          else
            echo "No changes to commit."
          fi
```

The cron time (`0 7 * * *`) is deliberately offset by one hour from the RSS ingestion workflow's `0 6 * * *`, so the two workflows' commits don't race against each other on the same branch.

`permissions: contents: write` is required for the default `GITHUB_TOKEN` to push. No dependency install step is needed — `kev.py` uses only the standard library.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/kev_fetch.yml
git commit -m "feat: add daily scheduled CISA KEV fetch workflow"
```

- [ ] **Step 3: Push and manually trigger once to verify end-to-end**

```bash
git push origin master
```

Then on GitHub: Actions tab → "Fetch CISA KEV catalog" → "Run workflow" (uses the `workflow_dispatch` trigger). Confirm the run succeeds and commits a real `kev_digest.md` — spot-check a few entries against the actual CISA KEV catalog to confirm correctness, same validation habit as the rest of this project. This is a manual verification step, not something to automate.

---

## After this plan

The structured KEV lane is complete once Task 2's manual workflow trigger succeeds and `kev_digest.md` contains real, ranked CISA KEV data. This lane runs entirely independently of the RAG lane — no shared code, no shared output file. Growth to the rest of Option A (the router merging both lanes' output, and eventually NVD enrichment) remains separate future work.
