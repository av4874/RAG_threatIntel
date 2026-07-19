import re
import sys
from datetime import date
from pathlib import Path

from threat_digest.feeds import fetch_feed_entries
from threat_digest.seen import load_seen_urls, mark_seen


def slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug[:80] or "article"


def run_ingest(feed_urls: list[str], corpus_dir: Path, seen_path: Path) -> list[Path]:
    corpus_dir = Path(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    seen_path = Path(seen_path)
    seen = load_seen_urls(seen_path)

    written: list[Path] = []
    failures = 0

    for feed_url in feed_urls:
        try:
            entries = fetch_feed_entries(feed_url)
        except Exception as exc:
            print(f"WARNING: failed to fetch feed {feed_url}: {exc}", file=sys.stderr)
            failures += 1
            continue

        for entry in entries:
            if entry.url in seen:
                continue

            slug = slugify(entry.title)
            today = date.today().isoformat()
            base_name = f"{today}-{slug}"
            file_path = corpus_dir / f"{base_name}.txt"
            suffix = 2
            while file_path.exists():
                file_path = corpus_dir / f"{base_name}-{suffix}.txt"
                suffix += 1

            safe_title = entry.title.replace("\n", " ")
            safe_url = entry.url.replace("\n", " ")
            content = f"TITLE: {safe_title}\nSOURCE: {safe_url}\n---\n{entry.summary}\n"
            file_path.write_text(content, encoding="utf-8")
            written.append(file_path)

            mark_seen(seen_path, entry.url)
            seen.add(entry.url)

    if feed_urls and failures == len(feed_urls):
        raise RuntimeError(f"All {len(feed_urls)} feeds failed to fetch")

    return written


if __name__ == "__main__":
    FEED_URLS = [
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://msrc.microsoft.com/blog/rss/",
    ]
    written_paths = run_ingest(FEED_URLS, Path("corpus"), Path("seen_urls.json"))
    print(f"Ingested {len(written_paths)} new article(s).")
