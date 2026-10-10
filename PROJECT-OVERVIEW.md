# Project Overview
## Local AI-Powered Cybersecurity Assistant for Personal Endpoints

**Topic:** Monitoring suspicious local system processes and detecting phishing URLs in real time for non-technical users.

This document explains what was produced for Weeks 1–5 of the assignment and how the pieces fit together. The detailed work for each week lives in its own folder/file, as required.

---

## What Was Produced

| Week | Folder / File | What it covers |
|---|---|---|
| 1 | `week-01-cti-fundamentals/week1-work.md` | Glossary of CTI terms scoped to our project, classification of threats relevant to personal endpoints, and how the ENISA Threat Landscape reading shaped our MVP scope (phishing URLs + suspicious processes). |
| 2 | `week-02-data-collection/week2-work.md` + `images/` | A real dataset (UCI Phishing Websites, 11,055 rows) explored and correlated to rank real threat indicators, OSINT tool validation on safe baselines (VirusTotal, Shodan, Maltego), a real-world investigation of a currently flagged phishing domain, a data-source mapping, and findings answering three research questions — all backed by 8 real screenshots as evidence. |
| 3 | `week-03-data-processing/week3-work.md` + `filter_normalize_iocs.py` + `simple_url_check.py` | A live IOC feed (URLhaus) pulled directly via Python (in place of a full MISP deployment), then filtered (14,428 → 1,752 by status), normalized into a common schema, deduplicated (→ 729 unique domains), and correlated (tag frequency + a cross-check against Week 2's flagged domain) — with the output consumed directly by `simple_url_check.py`, so the pipeline is genuinely connected end-to-end. |
| 4 | `week-04-kill-chain/week4-work.md` + `images/` | The Mirai IoT botnet / 2016 Dyn DDoS attack analyzed stage-by-stage through the Lockheed Martin Kill Chain, each stage mapped to a MITRE ATT&CK technique, with a diagram — the attack was chosen because it matched the dominant threat tags (`mirai`/`Mozi`) found in Week 3's own live feed data, not picked arbitrarily. |
| 5 | `week-05-threat-hunting/week5-work.md` + `powershell_rule.py` + `images/` (10 screenshots) | Splunk Enterprise deployed locally with Sysmon as the telemetry source (8,580 real events ingested), a hypothesis-driven hunt for suspicious PowerShell activity (T1059.001) run as three real SPL queries against that data, a genuine false-positive pattern discovered (legitimate VS Code updates share attacker-favored flags), and the finding converted into a detection rule (`powershell_rule.py`) validated 10/10 against real hunt data plus synthetic edge cases. |

Each week's file ends with a **Deliverables Checklist** matching the exact tasks listed in the syllabus table (Section 3.3), so the practice teacher can quickly verify coverage.

## Why This Scope

Personal-endpoint users face a narrower, higher-frequency threat set than enterprises — mainly phishing links and unwanted/malicious local processes — so we deliberately scoped the MVP around those two detection surfaces rather than trying to cover the full enterprise CTI threat landscape. Each week's reading was used to justify a concrete design decision:

- **Week 1 (ENISA):** confirmed phishing + malware are the top threats to individuals → chose them as the two MVP pillars.
- **Week 2 (Bazzell):** shaped the OSINT methodology — validate tools on safe baselines before trusting them on a real target, and never rely on a single source; this was directly confirmed by a real case where VirusTotal and domain age both said "safe" while a community abuse feed said otherwise.
- **Week 3 (MISP Training Documentation):** informed the IOC schema (type, value, source, confidence, tags) our filtering/normalization pipeline uses, even though we substituted a full MISP deployment with a simpler, equally real direct feed pull — see `week3-work.md §3.1` for why.
- **Week 4 (Lockheed Martin Intelligence-Driven Defense):** its "break any single link" principle explains why the assistant prioritizes catching attacker behavior at the earliest observable stage (a suspicious URL before it's clicked) rather than only reacting after the fact.
- **Week 5 (Microsoft Threat Hunting Guide, Smith's Practical Threat Hunting):** both stress that a hunt's value comes from feeding the finding back into automated detection — which is why the real false positive uncovered in the Splunk hunt (VS Code's update flags overlapping attacker tradecraft) was carried directly into `powershell_rule.py`'s logic (a hidden window alone is deliberately not flagged) rather than left as a one-off observation.

## AI Usage Disclosure

We used Claude (Anthropic) as an AI assistant during this project, as permitted by the assignment. Scope of use:

- **Ours:** the project idea (local AI-powered cybersecurity assistant for personal endpoints), the CTI research and threat-classification decisions, the dataset selection and correlation analysis, the real OSINT investigation and its findings, the decision to substitute a full MISP deployment with a direct feed pull, the Kill Chain/ATT&CK attack analysis, the Splunk/Sysmon lab deployment and threat-hunting hypothesis, and the core logic and research behind `filter_normalize_iocs.py`, `simple_url_check.py`, and `powershell_rule.py`.
- **Claude's role:** sorting and documenting that work into structured weekly deliverables (checklists, the data-source mapping, diagrams, this overview), and helping refine and document the filtering/normalization, URL-checking, and threat-hunting logic.

No AI-generated content replaced our own research or decision-making — Claude was used as a documentation and formatting aid.
