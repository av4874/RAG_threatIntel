# Corpus

Place one `.txt` file per source document here (blog posts, vendor advisories).
Filename (without `.txt`) becomes the document's `doc_id` — use something
stable and readable, e.g. `2026-07-18-widget-server-rce.txt`.

## Required format

```
TITLE: <document title>
SOURCE: <source URL>
---
<full body text of the document>
```

The first two lines must be `TITLE:` and `SOURCE:`, followed by a line
containing only `---`, then the body. Everything after `---` is treated as
the document text and gets chunked/embedded as-is — paste the article's
plain text (not raw HTML).

## Scope (per the Build B design spec)

Static, unstructured sources only: threat research blog posts and vendor
security advisory pages. Do not add structured CVE/NVD/KEV data here — that
becomes its own structured lane in Option A, not part of this corpus.
