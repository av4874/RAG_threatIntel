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
