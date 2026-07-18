import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

RISK_QUERY = (
    "actively exploited vulnerability, zero-day exploit, ransomware campaign, "
    "critical severity, proof-of-concept exploit code, exploited in the wild"
)

_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _model


def retrieve_top_chunks_for_document(
    chunks: list[str], k: int = 5
) -> list[tuple[str, float]]:
    if not chunks:
        return []

    model = _get_model()
    chunk_vectors = model.encode(chunks, normalize_embeddings=True)
    query_vector = model.encode([RISK_QUERY], normalize_embeddings=True)

    dimension = chunk_vectors.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(np.asarray(chunk_vectors, dtype=np.float32))

    top_k = min(k, len(chunks))
    scores, indices = index.search(np.asarray(query_vector, dtype=np.float32), top_k)

    return [(chunks[idx], float(score)) for idx, score in zip(indices[0], scores[0])]
