import json
import re
from dataclasses import dataclass
from typing import Protocol


@dataclass
class AnalysisResult:
    summary: str
    rationale: str
    risk_score: int


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str:
        ...


PROMPT_TEMPLATE = """You are a threat intelligence analyst. Read the following \
retrieved passages from a document titled "{title}" and produce a grounded \
assessment using ONLY the information in these passages. Do not invent details \
that are not present in the text below.

Passages:
{chunks_block}

Respond with ONLY a JSON object with exactly these keys:
- "summary": a 2-3 sentence grounded summary of the threat described
- "rationale": 1-2 sentences explaining why this is or isn't high-risk
- "risk_score": an integer from 1 (not risky) to 10 (critical, actively exploited)
"""


def build_prompt(title: str, chunks: list[str]) -> str:
    chunks_block = "\n\n".join(f"- {chunk}" for chunk in chunks)
    return PROMPT_TEMPLATE.format(title=title, chunks_block=chunks_block)


def parse_llm_response(raw: str) -> AnalysisResult:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        data = json.loads(cleaned)
        return AnalysisResult(
            summary=data["summary"],
            rationale=data["rationale"],
            risk_score=int(data["risk_score"]),
        )
    except (json.JSONDecodeError, KeyError) as exc:
        raise ValueError("could not parse LLM response as JSON") from exc


def analyze_document(client: LLMClient, title: str, chunks: list[str]) -> AnalysisResult:
    prompt = build_prompt(title, chunks)
    raw_response = client.generate(prompt)
    return parse_llm_response(raw_response)
