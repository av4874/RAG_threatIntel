from threat_digest.chunking import chunk_text


def test_short_text_returns_single_chunk():
    text = "one two three four five"
    chunks = chunk_text(text, chunk_size=80, overlap=20)
    assert chunks == ["one two three four five"]


def test_long_text_splits_into_multiple_overlapping_chunks():
    words = [f"word{i}" for i in range(100)]
    text = " ".join(words)
    chunks = chunk_text(text, chunk_size=40, overlap=10)
    assert len(chunks) > 1
    # every chunk must be non-empty and made of whole words
    for chunk in chunks:
        assert chunk.strip() != ""
        assert "word" in chunk
    # overlap: last 10 words of chunk N should appear at the start of chunk N+1
    first_chunk_words = chunks[0].split()
    second_chunk_words = chunks[1].split()
    assert first_chunk_words[-10:] == second_chunk_words[:10]


def test_empty_text_returns_no_chunks():
    assert chunk_text("", chunk_size=40, overlap=10) == []
