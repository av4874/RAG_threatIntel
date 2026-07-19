# Detection-Engineering Synthesis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TTP mapping, required log sources, detection feasibility, and a detection-engineering recommendation to digest entries that score >= 6, via a second LLM call using the same retrieved chunks — without changing anything about the existing risk-scoring pipeline for items that don't qualify.

**Architecture:** Three new/extended modules mirroring the existing project style — `attack_reference.py` (a bundled, real, static MITRE ATT&CK Enterprise technique list for validating the LLM's technique claim), `synthesis.py` (the second-call prompt/parse logic, same shape as `llm_analysis.py`), and extensions to `digest.py` (new optional `DigestItem` fields + markdown section) and `pipeline.py` (threshold gating + the second call + a second audit record).

**Tech Stack:** Python 3.11+, pytest (already set up). No new dependencies.

## Global Constraints

- Synthesis threshold: `risk_score >= 6` triggers the second LLM call; below that, an item is unchanged from today (no synthesis fields, no second call, no second audit record)
- Log sources (LLM must pick one or more from exactly this set): `Windows Security Event Log`, `Web server access logs`, `Firewall/VPN logs`, `EDR/endpoint logs`, `Cloud audit logs`, `DNS logs`, `Email gateway logs`, `Application/database logs`
- Feasibility (exactly one of): `High`, `Medium`, `Low`, `Not currently feasible`
- Recommendation (exactly one of): `New use case`, `Tune existing rule`, `Watchlist`, `Hunting query`
- The ATT&CK reference list must be real MITRE ATT&CK Enterprise data (not fabricated) — the exact list to use is given verbatim in Task 1
- A synthesis call that fails to parse must never remove the item's existing risk-scored entry from the digest — it just gets no synthesis fields, same as an item below the threshold
- No placeholders, no speculative error handling beyond what's specified — YAGNI

---

## File Structure

```
RAG_threatIntel/
  src/threat_digest/
    attack_reference.py   # ATTACK_TECHNIQUES dict, is_valid_technique_id()
    synthesis.py           # SynthesisResult, build_synthesis_prompt(), parse_synthesis_response()
    digest.py               # MODIFY: DigestItem gains 8 optional fields, format_digest_markdown() extended
    pipeline.py              # MODIFY: threshold gating + second LLM call + second audit record
  tests/
    test_attack_reference.py
    test_synthesis.py
    test_digest.py           # MODIFY: add synthesis-section tests
    test_pipeline.py          # MODIFY: add synthesis-gating tests
```

---

### Task 1: ATT&CK technique reference

**Files:**
- Create: `src/threat_digest/attack_reference.py`
- Test: `tests/test_attack_reference.py`

**Interfaces:**
- Produces: `ATTACK_TECHNIQUES: dict[str, str]` (technique ID → name), `is_valid_technique_id(technique_id: str) -> bool`. Used by Task 2 (`synthesis.py`).

This is real MITRE ATT&CK Enterprise matrix data (222 top-level techniques, revoked/deprecated/sub-techniques excluded), fetched and extracted from MITRE's public STIX bundle (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`) at plan-writing time. Use it verbatim — do not regenerate or edit these values.

- [ ] **Step 1: Write the failing test**

`tests/test_attack_reference.py`:
```python
from threat_digest.attack_reference import is_valid_technique_id


def test_is_valid_technique_id_returns_true_for_real_technique():
    assert is_valid_technique_id("T1190") is True


def test_is_valid_technique_id_returns_false_for_fake_technique():
    assert is_valid_technique_id("T9999") is False


def test_is_valid_technique_id_returns_false_for_empty_string():
    assert is_valid_technique_id("") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_attack_reference.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.attack_reference'`

- [ ] **Step 3: Implement `attack_reference.py`**

```python
ATTACK_TECHNIQUES: dict[str, str] = {
    "T1001": "Data Obfuscation",
    "T1003": "OS Credential Dumping",
    "T1005": "Data from Local System",
    "T1006": "Direct Volume Access",
    "T1007": "System Service Discovery",
    "T1008": "Fallback Channels",
    "T1010": "Application Window Discovery",
    "T1011": "Exfiltration Over Other Network Medium",
    "T1012": "Query Registry",
    "T1014": "Rootkit",
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1020": "Automated Exfiltration",
    "T1021": "Remote Services",
    "T1025": "Data from Removable Media",
    "T1027": "Obfuscated Files or Information",
    "T1029": "Scheduled Transfer",
    "T1030": "Data Transfer Size Limits",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1037": "Boot or Logon Initialization Scripts",
    "T1039": "Data from Network Shared Drive",
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1049": "System Network Connections Discovery",
    "T1052": "Exfiltration Over Physical Medium",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1056": "Input Capture",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1068": "Exploitation for Privilege Escalation",
    "T1069": "Permission Groups Discovery",
    "T1070": "Indicator Removal",
    "T1071": "Application Layer Protocol",
    "T1072": "Software Deployment Tools",
    "T1074": "Data Staged",
    "T1078": "Valid Accounts",
    "T1080": "Taint Shared Content",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1090": "Proxy",
    "T1091": "Replication Through Removable Media",
    "T1092": "Communication Through Removable Media",
    "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1102": "Web Service",
    "T1104": "Multi-Stage Channels",
    "T1105": "Ingress Tool Transfer",
    "T1106": "Native API",
    "T1110": "Brute Force",
    "T1111": "Multi-Factor Authentication Interception",
    "T1112": "Modify Registry",
    "T1113": "Screen Capture",
    "T1114": "Email Collection",
    "T1115": "Clipboard Data",
    "T1119": "Automated Collection",
    "T1120": "Peripheral Device Discovery",
    "T1123": "Audio Capture",
    "T1124": "System Time Discovery",
    "T1125": "Video Capture",
    "T1127": "Trusted Developer Utilities Proxy Execution",
    "T1129": "Shared Modules",
    "T1132": "Data Encoding",
    "T1133": "External Remote Services",
    "T1134": "Access Token Manipulation",
    "T1135": "Network Share Discovery",
    "T1136": "Create Account",
    "T1137": "Office Application Startup",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1176": "Software Extensions",
    "T1185": "Browser Session Hijacking",
    "T1187": "Forced Authentication",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1197": "BITS Jobs",
    "T1199": "Trusted Relationship",
    "T1200": "Hardware Additions",
    "T1201": "Password Policy Discovery",
    "T1202": "Indirect Command Execution",
    "T1203": "Exploitation for Client Execution",
    "T1204": "User Execution",
    "T1205": "Traffic Signaling",
    "T1207": "Rogue Domain Controller",
    "T1210": "Exploitation of Remote Services",
    "T1211": "Exploitation for Stealth",
    "T1212": "Exploitation for Credential Access",
    "T1213": "Data from Information Repositories",
    "T1216": "System Script Proxy Execution",
    "T1217": "Browser Information Discovery",
    "T1218": "System Binary Proxy Execution",
    "T1219": "Remote Access Tools",
    "T1220": "XSL Script Processing",
    "T1221": "Template Injection",
    "T1222": "File and Directory Permissions Modification",
    "T1480": "Execution Guardrails",
    "T1482": "Domain Trust Discovery",
    "T1484": "Domain or Tenant Policy Modification",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1495": "Firmware Corruption",
    "T1496": "Resource Hijacking",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service",
    "T1505": "Server Software Component",
    "T1518": "Software Discovery",
    "T1525": "Implant Internal Image",
    "T1526": "Cloud Service Discovery",
    "T1528": "Steal Application Access Token",
    "T1529": "System Shutdown/Reboot",
    "T1530": "Data from Cloud Storage",
    "T1531": "Account Access Removal",
    "T1534": "Internal Spearphishing",
    "T1535": "Unused/Unsupported Cloud Regions",
    "T1537": "Transfer Data to Cloud Account",
    "T1538": "Cloud Service Dashboard",
    "T1539": "Steal Web Session Cookie",
    "T1542": "Pre-OS Boot",
    "T1543": "Create or Modify System Process",
    "T1546": "Event Triggered Execution",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1550": "Use Alternate Authentication Material",
    "T1552": "Unsecured Credentials",
    "T1553": "Subvert Trust Controls",
    "T1554": "Compromise Host Software Binary",
    "T1555": "Credentials from Password Stores",
    "T1556": "Modify Authentication Process",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1559": "Inter-Process Communication",
    "T1560": "Archive Collected Data",
    "T1561": "Disk Wipe",
    "T1563": "Remote Service Session Hijacking",
    "T1564": "Hide Artifacts",
    "T1565": "Data Manipulation",
    "T1566": "Phishing",
    "T1567": "Exfiltration Over Web Service",
    "T1568": "Dynamic Resolution",
    "T1569": "System Services",
    "T1570": "Lateral Tool Transfer",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1573": "Encrypted Channel",
    "T1574": "Hijack Execution Flow",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1580": "Cloud Infrastructure Discovery",
    "T1583": "Acquire Infrastructure",
    "T1584": "Compromise Infrastructure",
    "T1585": "Establish Accounts",
    "T1586": "Compromise Accounts",
    "T1587": "Develop Capabilities",
    "T1588": "Obtain Capabilities",
    "T1589": "Gather Victim Identity Information",
    "T1590": "Gather Victim Network Information",
    "T1591": "Gather Victim Org Information",
    "T1592": "Gather Victim Host Information",
    "T1593": "Search Open Websites/Domains",
    "T1594": "Search Victim-Owned Websites",
    "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
    "T1597": "Search Closed Sources",
    "T1598": "Phishing for Information",
    "T1599": "Network Boundary Bridging",
    "T1600": "Weaken Encryption",
    "T1601": "Modify System Image",
    "T1602": "Data from Configuration Repository",
    "T1606": "Forge Web Credentials",
    "T1608": "Stage Capabilities",
    "T1609": "Container Administration Command",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
    "T1612": "Build Image on Host",
    "T1613": "Container and Resource Discovery",
    "T1614": "System Location Discovery",
    "T1615": "Group Policy Discovery",
    "T1619": "Cloud Storage Object Discovery",
    "T1620": "Reflective Code Loading",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1622": "Debugger Evasion",
    "T1647": "Plist File Modification",
    "T1648": "Serverless Execution",
    "T1649": "Steal or Forge Authentication Certificates",
    "T1650": "Acquire Access",
    "T1651": "Cloud Administration Command",
    "T1652": "Device Driver Discovery",
    "T1653": "Power Settings",
    "T1654": "Log Enumeration",
    "T1657": "Financial Theft",
    "T1659": "Content Injection",
    "T1665": "Hide Infrastructure",
    "T1666": "Modify Cloud Resource Hierarchy",
    "T1667": "Email Bombing",
    "T1668": "Exclusive Control",
    "T1669": "Wi-Fi Networks",
    "T1671": "Cloud Application Integration",
    "T1673": "Virtual Machine Discovery",
    "T1674": "Input Injection",
    "T1675": "ESXi Administration Command",
    "T1677": "Poisoned Pipeline Execution",
    "T1678": "Delay Execution",
    "T1679": "Selective Exclusion",
    "T1680": "Local Storage Discovery",
    "T1681": "Search Threat Vendor Data",
    "T1682": "Query Public AI Services",
    "T1683": "Generate Content",
    "T1684": "Social Engineering",
    "T1685": "Disable or Modify Tools",
    "T1686": "Disable or Modify System Firewall",
    "T1687": "Exploitation for Defense Impairment",
    "T1688": "Safe Mode Boot",
    "T1689": "Downgrade Attack",
    "T1690": "Prevent Command History Logging",
}


def is_valid_technique_id(technique_id: str) -> bool:
    return technique_id in ATTACK_TECHNIQUES
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_attack_reference.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/attack_reference.py tests/test_attack_reference.py
git commit -m "feat: add bundled MITRE ATT&CK Enterprise technique reference"
```

---

### Task 2: Synthesis prompt building and response parsing

**Files:**
- Create: `src/threat_digest/synthesis.py`
- Test: `tests/test_synthesis.py`

**Interfaces:**
- Consumes: `is_valid_technique_id` (Task 1).
- Produces: `SynthesisResult` dataclass, `LOG_SOURCES`, `FEASIBILITY_LEVELS`, `RECOMMENDATIONS` (the three fixed vocabularies as lists), `build_synthesis_prompt(title: str, chunks: list[str]) -> str`, `parse_synthesis_response(raw: str) -> SynthesisResult`. Used by Task 4 (`pipeline.py`).

- [ ] **Step 1: Write the failing test**

`tests/test_synthesis.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_synthesis.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_digest.synthesis'`

- [ ] **Step 3: Implement `synthesis.py`**

```python
import json
import re
from dataclasses import dataclass
from typing import Protocol

from threat_digest.attack_reference import is_valid_technique_id

LOG_SOURCES = [
    "Windows Security Event Log",
    "Web server access logs",
    "Firewall/VPN logs",
    "EDR/endpoint logs",
    "Cloud audit logs",
    "DNS logs",
    "Email gateway logs",
    "Application/database logs",
]

FEASIBILITY_LEVELS = ["High", "Medium", "Low", "Not currently feasible"]

RECOMMENDATIONS = ["New use case", "Tune existing rule", "Watchlist", "Hunting query"]


@dataclass
class SynthesisResult:
    technique_id: str
    technique_name: str
    technique_verified: bool
    log_sources: list[str]
    feasibility: str
    feasibility_reason: str
    recommendation: str
    recommendation_reason: str


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str:
        ...


SYNTHESIS_PROMPT_TEMPLATE = """You are a detection engineer. Read the following \
retrieved passages from a document titled "{title}" and produce a detection-engineering \
assessment using ONLY the information in these passages. Do not invent details \
that are not present in the text below.

Passages:
{chunks_block}

Respond with ONLY a JSON object with exactly these keys:
- "technique_id": the MITRE ATT&CK technique ID (e.g. "T1190") that best matches this threat
- "technique_name": the name of that technique
- "log_sources": a list of one or more log sources from this exact set that would show this activity: {log_sources_list}
- "feasibility": one of exactly these values: {feasibility_list}
- "feasibility_reason": 1 sentence explaining the feasibility rating
- "recommendation": one of exactly these values: {recommendation_list}
- "recommendation_reason": 1 sentence explaining the recommendation
"""


def build_synthesis_prompt(title: str, chunks: list[str]) -> str:
    chunks_block = "\n\n".join(f"- {chunk}" for chunk in chunks)
    return SYNTHESIS_PROMPT_TEMPLATE.format(
        title=title,
        chunks_block=chunks_block,
        log_sources_list=", ".join(LOG_SOURCES),
        feasibility_list=", ".join(FEASIBILITY_LEVELS),
        recommendation_list=", ".join(RECOMMENDATIONS),
    )


def parse_synthesis_response(raw: str) -> SynthesisResult:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        data = json.loads(cleaned)
        technique_id = data["technique_id"]
        return SynthesisResult(
            technique_id=technique_id,
            technique_name=data["technique_name"],
            technique_verified=is_valid_technique_id(technique_id),
            log_sources=list(data["log_sources"]),
            feasibility=data["feasibility"],
            feasibility_reason=data["feasibility_reason"],
            recommendation=data["recommendation"],
            recommendation_reason=data["recommendation_reason"],
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("could not parse synthesis response as JSON") from exc
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_synthesis.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/synthesis.py tests/test_synthesis.py
git commit -m "feat: add detection-engineering synthesis prompt building and response parsing"
```

---

### Task 3: Extend digest formatting with synthesis fields

**Files:**
- Modify: `src/threat_digest/digest.py`
- Modify: `tests/test_digest.py`

**Interfaces:**
- Produces: `DigestItem` gains 8 new optional fields (all default `None`): `technique_id: str | None`, `technique_name: str | None`, `technique_verified: bool | None`, `log_sources: list[str] | None`, `feasibility: str | None`, `feasibility_reason: str | None`, `recommendation: str | None`, `recommendation_reason: str | None`. `format_digest_markdown` renders a synthesis section for an item only when `technique_id is not None`. Used by Task 4 (`pipeline.py`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_digest.py` (the existing `LOW`/`HIGH` fixtures and their tests stay as-is; add these new fixtures and tests alongside them):

```python
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
```

(`LOW` is the existing fixture already defined at the top of `tests/test_digest.py` — reuse it, don't redefine it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_digest.py -v`
Expected: FAIL — the new `DigestItem(...)` calls with synthesis keyword arguments raise `TypeError: __init__() got an unexpected keyword argument 'technique_id'`

- [ ] **Step 3: Modify `digest.py`**

Replace the whole file with:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_digest.py -v`
Expected: PASS (6 passed — 3 existing + 3 new)

- [ ] **Step 5: Commit**

```bash
git add src/threat_digest/digest.py tests/test_digest.py
git commit -m "feat: extend digest formatting with detection-engineering synthesis fields"
```

---

### Task 4: Wire synthesis into the pipeline with threshold gating

**Files:**
- Modify: `src/threat_digest/pipeline.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `build_synthesis_prompt`/`parse_synthesis_response` (Task 2), extended `DigestItem` (Task 3).
- Produces: `run_pipeline`'s behavior is extended (signature unchanged) — for any document whose `risk_score >= 6`, a second LLM call happens and its result (if parseable) populates the item's synthesis fields.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_pipeline.py` (the existing `FIXTURES`, `FakeLLMClient`, and existing tests stay as-is; add these alongside them):

```python
def test_run_pipeline_adds_synthesis_fields_for_high_risk_items(tmp_path):
    class SynthesizingLLMClient:
        def generate(self, prompt: str) -> str:
            if "detection engineer" in prompt:
                return json.dumps(
                    {
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "log_sources": ["Web server access logs"],
                        "feasibility": "High",
                        "feasibility_reason": "visible in logs",
                        "recommendation": "New use case",
                        "recommendation_reason": "no existing coverage",
                    }
                )
            risk_score = 9 if "exploit" in prompt.lower() else 3
            return json.dumps(
                {
                    "summary": "generated summary",
                    "rationale": "generated rationale",
                    "risk_score": risk_score,
                }
            )

    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=SynthesizingLLMClient(),
        k=3,
    )

    digest_text = digest_path.read_text(encoding="utf-8")
    assert "T1190 - Exploit Public-Facing Application" in digest_text
    dark_mode_section = digest_text[digest_text.index("Widget Server 4.3 Adds Dark Mode"):]
    assert "ATT&CK Technique" not in dark_mode_section


def test_run_pipeline_skips_synthesis_for_low_risk_items(tmp_path):
    class LowRiskLLMClient:
        def generate(self, prompt: str) -> str:
            if "detection engineer" in prompt:
                raise AssertionError("synthesis should not be called for low-risk items")
            return json.dumps(
                {
                    "summary": "generated summary",
                    "rationale": "generated rationale",
                    "risk_score": 3,
                }
            )

    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=LowRiskLLMClient(),
        k=3,
    )
    assert digest_path.exists()


def test_run_pipeline_keeps_item_when_synthesis_response_is_malformed(tmp_path):
    class BrokenSynthesisLLMClient:
        def generate(self, prompt: str) -> str:
            if "detection engineer" in prompt:
                return "not valid json"
            risk_score = 9 if "exploit" in prompt.lower() else 3
            return json.dumps(
                {
                    "summary": "generated summary",
                    "rationale": "generated rationale",
                    "risk_score": risk_score,
                }
            )

    digest_path = run_pipeline(
        corpus_dir=FIXTURES,
        output_dir=tmp_path,
        llm_client=BrokenSynthesisLLMClient(),
        k=3,
    )

    digest_text = digest_path.read_text(encoding="utf-8")
    assert "Critical RCE in Widget Server" in digest_text
    assert "ATT&CK Technique" not in digest_text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/pytest tests/test_pipeline.py -v`
Expected: FAIL — `test_run_pipeline_adds_synthesis_fields_for_high_risk_items` fails because `digest_text` never contains "T1190" (synthesis never runs yet); the other two new tests pass trivially by accident at this point, but will be genuinely exercised once Step 3 lands (Step 4 confirms all three for real).

- [ ] **Step 3: Modify `pipeline.py`**

Replace the whole file with:

```python
from datetime import datetime, timezone
from pathlib import Path

from threat_digest.audit import write_audit_record
from threat_digest.chunking import chunk_text
from threat_digest.corpus import load_corpus
from threat_digest.digest import DigestItem, format_digest_markdown
from threat_digest.llm_analysis import LLMClient, build_prompt, parse_llm_response
from threat_digest.retrieval import retrieve_top_chunks_for_document
from threat_digest.synthesis import build_synthesis_prompt, parse_synthesis_response

SYNTHESIS_THRESHOLD = 6


def run_pipeline(
    corpus_dir: Path,
    output_dir: Path,
    llm_client: LLMClient,
    k: int = 5,
) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_path = output_dir / "audit.jsonl"

    documents = load_corpus(corpus_dir)
    digest_items = []

    for document in documents:
        chunks = chunk_text(document.text)
        retrieved = retrieve_top_chunks_for_document(chunks, k=k)
        retrieved_texts = [text for text, _score in retrieved]

        prompt = build_prompt(document.title, retrieved_texts)
        raw_output = llm_client.generate(prompt)

        try:
            analysis = parse_llm_response(raw_output)
        except ValueError:
            write_audit_record(
                audit_path,
                doc_id=document.doc_id,
                retrieved_chunks=retrieved,
                prompt=prompt,
                raw_llm_output=raw_output,
                # -1 sentinel: LLM output could not be parsed as JSON
                risk_score=-1,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            continue

        write_audit_record(
            audit_path,
            doc_id=document.doc_id,
            retrieved_chunks=retrieved,
            prompt=prompt,
            raw_llm_output=raw_output,
            risk_score=analysis.risk_score,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        item = DigestItem(
            doc_id=document.doc_id,
            title=document.title,
            source_url=document.source_url,
            summary=analysis.summary,
            rationale=analysis.rationale,
            risk_score=analysis.risk_score,
        )

        if analysis.risk_score >= SYNTHESIS_THRESHOLD:
            synthesis_prompt = build_synthesis_prompt(document.title, retrieved_texts)
            synthesis_raw_output = llm_client.generate(synthesis_prompt)

            try:
                synthesis = parse_synthesis_response(synthesis_raw_output)
            except ValueError:
                write_audit_record(
                    audit_path,
                    doc_id=document.doc_id,
                    retrieved_chunks=retrieved,
                    prompt=synthesis_prompt,
                    raw_llm_output=synthesis_raw_output,
                    # -1 sentinel: synthesis output could not be parsed as JSON
                    risk_score=-1,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            else:
                write_audit_record(
                    audit_path,
                    doc_id=document.doc_id,
                    retrieved_chunks=retrieved,
                    prompt=synthesis_prompt,
                    raw_llm_output=synthesis_raw_output,
                    risk_score=analysis.risk_score,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                item.technique_id = synthesis.technique_id
                item.technique_name = synthesis.technique_name
                item.technique_verified = synthesis.technique_verified
                item.log_sources = synthesis.log_sources
                item.feasibility = synthesis.feasibility
                item.feasibility_reason = synthesis.feasibility_reason
                item.recommendation = synthesis.recommendation
                item.recommendation_reason = synthesis.recommendation_reason

        digest_items.append(item)

    digest_markdown = format_digest_markdown(digest_items)
    digest_path = output_dir / "digest.md"
    digest_path.write_text(digest_markdown, encoding="utf-8")
    return digest_path
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/pytest tests/test_pipeline.py -v`
Expected: PASS (5 passed — 2 existing + 3 new)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/Scripts/pytest -v`
Expected: all tests pass (37 existing + 3 + 4 + 3 + 3 = 50), no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/threat_digest/pipeline.py tests/test_pipeline.py
git commit -m "feat: gate detection-engineering synthesis on risk_score >= 6"
```

---

## After this plan

Detection-engineering synthesis is complete once Task 4's full-suite run is green and committed. The next Kaggle run (with a real `QwenLLMClient`, unchanged) will exercise the real second LLM call for any document scoring >= 6 — worth a manual spot-check afterward of `audit.jsonl`'s synthesis records (same validation habit as the rest of this project: does the retrieved text actually support the claimed technique, log sources, and recommendation, or is the model inventing detail?). Remaining Option A sub-projects (structured KEV/NVD lane + rule gate, router, production scheduling of the LLM-analysis step) stay separate future work.
