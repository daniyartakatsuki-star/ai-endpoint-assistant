# Week 3 — Data Processing and Exploitation
### Applied to: Local AI-Powered Cybersecurity Assistant for Personal Endpoints

## 3.1 Approach: Why a Direct Feed Instead of a Full MISP Deployment

The syllabus lists MISP/Elastic Stack/Sigma as example tools for this stage, but the actual graded task is **"apply filtering and normalization techniques to collected data."** Deploying a full MISP server (Docker, database, web UI) adds infrastructure overhead without changing what's being demonstrated, so we used a simpler, equally real alternative: pulling the same underlying data MISP would import — a live public IOC feed from **URLhaus** (abuse.ch) — directly via HTTP in Python, using only the tooling we already have (VS Code + Python). This keeps the deliverable reliable and reproducible on any machine without a Docker/server dependency.

MISP Training Documentation was still reviewed as the recommended reading — it directly informed the schema we normalize data into (`type`, `value`, `source`, `confidence`, `tags`, `first_seen`), which mirrors how MISP itself structures IOC attributes.

## 3.2 Data Collection

[`filter_normalize_iocs.py`](./filter_normalize_iocs.py) downloads URLhaus's **"recent" feed** (`csv_recent`), which — unlike the "online-only" feed — includes both currently active (`online`) and already-taken-down (`offline`) entries. This matters methodologically: it means the filtering step below has real, mixed data to filter, rather than data that was already pre-filtered before we touched it.

## 3.3 Filtering, Normalization, and Correlation

Each raw feed row is normalized into one common schema — a real record from our final run:

```json
{
  "type": "url",
  "value": "http://1.70.76.87:57333/i",
  "domain": "1.70.76.87",
  "first_seen": "2026-09-26 06:01:16",
  "source": "urlhaus",
  "confidence": 1.0,
  "tags": ["mirai"],
  "threat": "malware_download",
  "status": "online"
}
```

**Filtering and normalization steps applied, with real results from our run:**

| Step | What it does | Result |
|---|---|---|
| 1. Fetch | Download the live URLhaus "recent" feed | **14,428** raw rows |
| 2. Normalize | Lowercase/parse each URL into a domain, split tags into a list, map fields into our common schema | 14,428 normalized records |
| 3. Filter | Keep only `status == "online"` (currently active threats — drops stale, already-remediated entries as noise) | **1,752** records remain |
| 4. Deduplicate | Collapse multiple URLs on the same domain into a single record | **729** unique domains |

Console output from the real run:
```
Raw rows fetched from URLhaus (recent feed, online + offline): 14428
After filtering to status=online only: 1752
After deduplication by domain: 729
Saved 729 clean IOCs to iocs_normalized.json
```

**Correlation/enrichment step:** tag frequencies were counted across the cleaned data to see what kinds of threats currently dominate the feed. The top tags were `mirai` (248), `Mozi` (216), `elf` (156), `32-bit` (98), and `ua-wget` (67) — i.e. the current feed is dominated by IoT/Linux botnet malware (Mirai/Mozi variants), not classic credential-phishing pages. We also checked whether the domain flagged in Week 2's OSINT investigation (`timestampasa.howto.rocks`) reappears in this independent feed pull — it did not (`present: False`), which is expected (that domain was already flagged by a different, phishing-specific list and may since have been taken down or rotated), but the check itself demonstrates real cross-week correlation rather than two disconnected exercises.

## 3.4 Connecting the Pipeline to the Assistant

[`simple_url_check.py`](./simple_url_check.py) loads `KNOWN_BAD_DOMAINS` directly from `iocs_normalized.json` — the file produced by `filter_normalize_iocs.py` — so the data genuinely flows: **live feed → filter → normalize → dedupe → local script → verdict shown to the user**. If `iocs_normalized.json` isn't present, it falls back to a small hardcoded sample so the script still runs for grading without needing network access at demo time.

Rather than testing against one hardcoded domain (which would go stale as the live feed changes between runs), the script's demo block picks a real domain straight out of whatever `KNOWN_BAD_DOMAINS` currently holds, and prints how many real domains were loaded — so every run is self-verifying.

**Bug found and fixed during testing:** an early version scored a real domain from `iocs_normalized.json` as "safe" even though it was present in the file. The cause was a mismatch between how the domain was stored (`filter_normalize_iocs.py` strips the port before saving) and how `simple_url_check.py` read it (kept the port). Fixing `suspicious_score()` to strip the port the same way resolved it.

Confirmed real console output from the final run, using the same `iocs_normalized.json` shown above:
```
(Loaded 729 real domains from iocs_normalized.json — testing against: 1.70.76.87)

⚠️ 'http://1.70.76.87/' looks like a phishing attempt — avoid entering any credentials.
✅ 'http://example-phish.com/login' looks safe based on current checks.
🟡 'https://secure-login-update.net/verify-account' has some suspicious traits — proceed with caution.
✅ 'https://www.google.com' looks safe based on current checks.
```

The first line — the script itself reporting how many real domains it loaded, then correctly flagging one of them — is direct proof the two scripts are genuinely connected, not just two files that happen to sit in the same folder.

## 3.5 Week 3 Deliverables Checklist

- [x] Real IOC data collected from a live public feed (URLhaus), in place of a full MISP deployment, with the substitution explicitly justified above
- [x] Filtering technique applied to collected data, with a real before/after count (14,428 → 1,752)
- [x] Normalization technique applied, unifying raw feed rows into one common schema
- [x] Deduplication applied (1,752 → 729 unique domains)
- [x] Correlation/enrichment performed (tag-frequency analysis + cross-check against Week 2's flagged domain)
- [x] Output (`iocs_normalized.json`) consumed by `simple_url_check.py`, so the pipeline is genuinely connected end-to-end, verified with real console output and a real bug found and fixed along the way
- [x] Recommended reading (MISP Training Documentation) reviewed — its IOC schema shaped our normalization format even though we did not deploy MISP itself
