from pathlib import Path
from threat_digest.corpus import Document, load_corpus

FIXTURES = Path(__file__).parent / "fixtures" / "corpus"


def test_load_corpus_returns_one_document_per_file():
    docs = load_corpus(FIXTURES)
    assert len(docs) == 2


def test_load_corpus_parses_fields():
    docs = load_corpus(FIXTURES)
    doc = next(d for d in docs if d.doc_id == "doc001")
    assert doc.title == "Critical RCE in Widget Server Actively Exploited"
    assert doc.source_url == "https://example.com/blog/widget-rce"
    assert "remote code" in doc.text
    assert "TITLE:" not in doc.text
    assert "---" not in doc.text.splitlines()[0]


def test_document_is_a_dataclass_with_expected_fields():
    doc = Document(doc_id="x", title="t", source_url="u", text="body")
    assert doc.doc_id == "x"
    assert doc.title == "t"
    assert doc.source_url == "u"
    assert doc.text == "body"
