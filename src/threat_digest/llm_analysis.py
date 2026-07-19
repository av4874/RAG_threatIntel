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

If these passages do NOT describe an actual cybersecurity threat, vulnerability, \
or attack in progress (for example: general tech/business news, regulatory or legal \
stories, or unrelated topics like cooking or lifestyle content), say so plainly \
in the rationale and assign risk_score 1. Do not invent a tenuous security angle \
for content that is not actually about a security threat.

Passages:
{chunks_block}

Respond with ONLY a JSON object with exactly these keys:
- "summary": a 2-3 sentence grounded summary of what the passages actually describe
- "rationale": 1-2 sentences explaining why this is or isn't high-risk. If it is \
not a security threat at all, state that directly instead of speculating about \
indirect or hypothetical risk.
- "risk_score": an integer from 1 (not risky / not a security threat) to 10 \
(critical, confirmed in the wild)
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
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("could not parse LLM response as JSON") from exc


def analyze_document(client: LLMClient, title: str, chunks: list[str]) -> AnalysisResult:
    prompt = build_prompt(title, chunks)
    raw_response = client.generate(prompt)
    return parse_llm_response(raw_response)
