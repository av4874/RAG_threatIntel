from dataclasses import dataclass
from pathlib import Path


@dataclass
class Document:
    doc_id: str
    title: str
    source_url: str
    text: str


def load_corpus(corpus_dir: Path) -> list[Document]:
    documents = []
    for path in sorted(Path(corpus_dir).glob("*.txt")):
        raw = path.read_text(encoding="utf-8")
        lines = raw.splitlines()
        title = lines[0].removeprefix("TITLE: ").strip()
        source_url = lines[1].removeprefix("SOURCE: ").strip()
        separator_index = lines.index("---")
        body = "\n".join(lines[separator_index + 1:]).strip()
        documents.append(
            Document(
                doc_id=path.stem,
                title=title,
                source_url=source_url,
                text=body,
            )
        )
    return documents
