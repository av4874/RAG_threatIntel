import json
from pathlib import Path


def load_seen_urls(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")))


def mark_seen(path: Path, url: str) -> None:
    seen = load_seen_urls(path)
    seen.add(url)
    path.write_text(json.dumps(sorted(seen)), encoding="utf-8")
