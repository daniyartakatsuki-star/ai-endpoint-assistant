# Project Overview
## Local AI-Powered Cybersecurity Assistant for Personal Endpoints

**Topic:** Monitoring suspicious local system processes and detecting phishing URLs in real time for non-technical users.

This document explains what was produced for Weeks 1–3 of the assignment and how the pieces fit together. The detailed work for each week lives in its own folder/file, as required.

---

## What Was Produced

| Week | Folder / File | What it covers |
|---|---|---|
| 1 | `week-01-cti-fundamentals/week1-work.md` | Glossary of CTI terms scoped to our project, classification of threats relevant to personal endpoints, and how the ENISA Threat Landscape reading shaped our MVP scope (phishing URLs + suspicious processes). |
| 2 | `week-02-data-collection/week2-work.md` + `virustotal_check.py` | Open-source vs. closed-source data sources for our project, an OSINT exercise (VirusTotal via a real runnable script, Shodan and Maltego via manual lookups with screenshot evidence), and a data-source mapping diagram showing how data flows from the endpoint into our pipeline. |
| 3 | `week-03-data-processing/week3-work.md` + `misp_export.py` + `simple_url_check.py` | MISP deployed via Docker with a real feed imported, `misp_export.py` pulling those IOCs out via the MISP API into `iocs.json`, and `simple_url_check.py` consuming that data to score a URL as safe/suspicious/phishing — a working, connected pipeline rather than separate claims. |

Each week's file ends with a **Deliverables Checklist** matching the exact tasks listed in the syllabus table (Section 3.3), so the practice teacher can quickly verify coverage.

## Why This Scope

Personal-endpoint users face a narrower, higher-frequency threat set than enterprises — mainly phishing links and unwanted/malicious local processes — so we deliberately scoped the MVP around those two detection surfaces rather than trying to cover the full enterprise CTI threat landscape. Each week's reading was used to justify a concrete design decision:

- **Week 1 (ENISA):** confirmed phishing + malware are the top threats to individuals → chose them as the two MVP pillars.
- **Week 2 (Bazzell / OSINT Framework):** shaped the data-source mapping so third-party enrichment (VirusTotal, Shodan) is optional and rate-limited, preserving user privacy by default.
- **Week 3 (MISP docs):** informed the normalization schema so locally collected telemetry can be filtered/scored the same way professional IOC data is, without requiring the end user to run MISP themselves.

## AI Usage Disclosure

We used Claude (Anthropic) as an AI assistant during this project, as permitted by the assignment. Scope of use:

- **Ours:** the project idea (local AI-powered cybersecurity assistant for personal endpoints), the CTI research and threat-classification decisions, the OSINT/data-collection approach, the MISP workflow, and the core logic and research behind `simple_url_check.py`.
- **Claude's role:** sorting and documenting that work into structured weekly deliverables (glossary tables, checklists, the data-source mapping diagram, and this overview), and helping refine and document the `simple_url_check.py` heuristic logic.

No AI-generated content replaced our own research or decision-making — Claude was used as a documentation and formatting aid.
