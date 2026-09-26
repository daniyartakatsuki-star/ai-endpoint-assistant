# Project Overview
## Local AI-Powered Cybersecurity Assistant for Personal Endpoints

**Topic:** Monitoring suspicious local system processes and detecting phishing URLs in real time for non-technical users.

This document explains what was produced for Weeks 1–3 of the assignment and how the pieces fit together. The detailed work for each week lives in its own folder/file, as required.

---

## What Was Produced

| Week | Folder / File | What it covers |
|---|---|---|
| 1 | `week-01-cti-fundamentals/week1-work.md` | Glossary of CTI terms scoped to our project, classification of threats relevant to personal endpoints, and how the ENISA Threat Landscape reading shaped our MVP scope (phishing URLs + suspicious processes). |
| 2 | `week-02-data-collection/week2-work.md` + `images/` | A real dataset (UCI Phishing Websites, 11,055 rows) explored and correlated to rank real threat indicators, OSINT tool validation on safe baselines (VirusTotal, Shodan, Maltego), a real-world investigation of a currently flagged phishing domain, a data-source mapping, and findings answering three research questions — all backed by 8 real screenshots as evidence. |
| 3 | `week-03-data-processing/week3-work.md` + `filter_normalize_iocs.py` + `simple_url_check.py` | A live IOC feed (URLhaus) pulled directly via Python (in place of a full MISP deployment), then filtered (14,428 → 1,752 by status), normalized into a common schema, deduplicated (→ 729 unique domains), and correlated (tag frequency + a cross-check against Week 2's flagged domain) — with the output consumed directly by `simple_url_check.py`, so the pipeline is genuinely connected end-to-end. |

Each week's file ends with a **Deliverables Checklist** matching the exact tasks listed in the syllabus table (Section 3.3), so the practice teacher can quickly verify coverage.

## Why This Scope

Personal-endpoint users face a narrower, higher-frequency threat set than enterprises — mainly phishing links and unwanted/malicious local processes — so we deliberately scoped the MVP around those two detection surfaces rather than trying to cover the full enterprise CTI threat landscape. Each week's reading was used to justify a concrete design decision:

- **Week 1 (ENISA):** confirmed phishing + malware are the top threats to individuals → chose them as the two MVP pillars.
- **Week 2 (Bazzell):** shaped the OSINT methodology — validate tools on safe baselines before trusting them on a real target, and never rely on a single source; this was directly confirmed by a real case where VirusTotal and domain age both said "safe" while a community abuse feed said otherwise.
- **Week 3 (MISP Training Documentation):** informed the IOC schema (type, value, source, confidence, tags) our filtering/normalization pipeline uses, even though we substituted a full MISP deployment with a simpler, equally real direct feed pull — see `week3-work.md §3.1` for why.

## AI Usage Disclosure

We used Claude (Anthropic) as an AI assistant during this project, as permitted by the assignment. Scope of use:

- **Ours:** the project idea (local AI-powered cybersecurity assistant for personal endpoints), the CTI research and threat-classification decisions, the dataset selection and correlation analysis, the real OSINT investigation and its findings, the decision to substitute a full MISP deployment with a direct feed pull, and the core logic and research behind `filter_normalize_iocs.py` and `simple_url_check.py`.
- **Claude's role:** sorting and documenting that work into structured weekly deliverables (checklists, the data-source mapping, this overview), and helping refine and document the filtering/normalization and URL-checking logic.

No AI-generated content replaced our own research or decision-making — Claude was used as a documentation and formatting aid.
