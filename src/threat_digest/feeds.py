import sys
from dataclasses import dataclass

import feedparser


@dataclass
class FeedEntry:
    title: str
    url: str
    summary: str


def fetch_feed_entries(feed_url: str, max_entries: int = 10) -> list[FeedEntry]:
    parsed = feedparser.parse(feed_url)
    entries = []
    for raw_entry in parsed.entries[:max_entries]:
        title = raw_entry.get("title")
        url = raw_entry.get("link")
        summary = raw_entry.get("summary", "")
        if not title or not url:
            print(
                f"WARNING: skipping feed entry with missing title/link from {feed_url}",
                file=sys.stderr,
            )
            continue
        entries.append(FeedEntry(title=title, url=url, summary=summary))
    return entries
