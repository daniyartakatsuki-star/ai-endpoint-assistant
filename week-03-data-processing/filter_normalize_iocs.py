"""
filter_normalize_iocs.py — Week 3: Data Processing and Exploitation
"""
import csv
import json
import requests
from urllib.parse import urlparse

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OUTPUT_FILE = "iocs_normalized.json"

# The real-world flagged domain investigated in Week 2 — used here to check
# whether it still shows up in a fresh, independent feed pull (correlation).
WEEK2_FLAGGED_DOMAIN = "timestampasa.howto.rocks"


def fetch_feed() -> str:
    resp = requests.get(FEED_URL, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse_urlhaus_csv(raw_text: str):
    """URLhaus prefixes comment/metadata lines with '#', including the header
    row itself. We pull the header out of that comment block, then parse the
    remaining lines as normal quoted CSV."""
    lines = raw_text.splitlines()
    header_fields = None
    data_lines = []
    for line in lines:
        if line.startswith("# id,"):
            header_fields = line.lstrip("# ").strip().split(",")
        elif not line.startswith("#") and line.strip():
            data_lines.append(line)

    if not header_fields:
        raise ValueError("Could not find header row in feed data — feed format may have changed")

    reader = csv.reader(data_lines)
    rows = [dict(zip(header_fields, row)) for row in reader if len(row) == len(header_fields)]
    return rows


def normalize_row(row: dict) -> dict:
    """Turns a raw feed row into our project's common schema."""
    url = row.get("url", "").strip()
    domain = urlparse(url).netloc.lower().split(":")[0]  # normalize case, strip port
    tags = [t.strip() for t in row.get("tags", "").split(",") if t.strip()]
    return {
        "type": "url",
        "value": url,
        "domain": domain,
        "first_seen": row.get("dateadded", ""),
        "source": "urlhaus",
        "confidence": 1.0,  # URLhaus 'online' entries are confirmed, currently active threats
        "tags": tags,
        "threat": row.get("threat", ""),
        "status": row.get("url_status", "").lower(),
    }


def filter_and_normalize(raw_rows):
    normalized = [normalize_row(r) for r in raw_rows]

    # Filtering step 1: keep only currently active threats (cuts stale/noisy entries)
    online_only = [r for r in normalized if r["status"] == "online"]

    # Filtering step 2: deduplicate by domain (many URLs on the same bad domain
    # would otherwise flood the assistant with repeat alerts for one root cause)
    seen_domains = set()
    deduped = []
    for r in online_only:
        if r["domain"] not in seen_domains:
            seen_domains.add(r["domain"])
            deduped.append(r)

    return normalized, online_only, deduped


def correlate(deduped):
    """Simple enrichment/correlation step: tag frequency, and a direct check
    against the real domain flagged during Week 2's OSINT investigation."""
    tag_counts = {}
    for r in deduped:
        for t in r["tags"]:
            tag_counts[t] = tag_counts.get(t, 0) + 1

    match = any(WEEK2_FLAGGED_DOMAIN in r["domain"] for r in deduped)
    return tag_counts, match


def main():
    raw_text = fetch_feed()
    raw_rows = parse_urlhaus_csv(raw_text)
    print(f"Raw rows fetched from URLhaus (recent feed, online + offline): {len(raw_rows)}")

    normalized, online_only, deduped = filter_and_normalize(raw_rows)
    print(f"After filtering to status=online only: {len(online_only)}")
    print(f"After deduplication by domain: {len(deduped)}")

    tag_counts, match = correlate(deduped)
    print(f"Tag frequency across current feed: {tag_counts}")
    print(f"Week 2 flagged domain ({WEEK2_FLAGGED_DOMAIN}) present in today's feed: {match}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(deduped, f, indent=2)
    print(f"Saved {len(deduped)} clean IOCs to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
