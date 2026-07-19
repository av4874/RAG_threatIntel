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
