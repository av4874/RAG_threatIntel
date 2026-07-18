from threat_digest.retrieval import retrieve_top_chunks_for_document


def test_returns_at_most_k_chunks_sorted_by_score_descending():
    chunks = [
        "The admin dashboard now supports a dark theme for night owls.",
        "Attackers are actively exploiting this remote code execution flaw in the wild.",
        "Search indexing performance was improved by roughly ten percent.",
        "A ransomware affiliate is using this critical vulnerability for initial access.",
    ]
    results = retrieve_top_chunks_for_document(chunks, k=2)
    assert len(results) == 2
    scores = [score for _, score in results]
    assert scores == sorted(scores, reverse=True)


def test_risk_relevant_chunks_rank_above_unrelated_chunks():
    chunks = [
        "The admin dashboard now supports a dark theme for night owls.",
        "Attackers are actively exploiting this critical remote code execution "
        "vulnerability in the wild, and it has been added to the CISA KEV catalog.",
    ]
    results = retrieve_top_chunks_for_document(chunks, k=2)
    top_chunk_text, _ = results[0]
    assert "exploit" in top_chunk_text.lower()


def test_k_larger_than_chunk_count_returns_all_chunks():
    chunks = ["only one chunk here"]
    results = retrieve_top_chunks_for_document(chunks, k=5)
    assert len(results) == 1
