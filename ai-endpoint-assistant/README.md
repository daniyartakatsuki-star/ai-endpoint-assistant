# Local AI-Powered Cybersecurity Assistant for Personal Endpoints

Monitoring suspicious local system processes and detecting phishing URLs in real time for non-technical users.

## Overview

See [`PROJECT-OVERVIEW.md`](./PROJECT-OVERVIEW.md) for the full write-up of what was researched and produced, and why the project was scoped the way it was.

## Repository Structure

```
ai-endpoint-assistant/
├── README.md
├── PROJECT-OVERVIEW.md
├── week-01-cti-fundamentals/
│   └── week1-work.md
├── week-02-data-collection/
│   ├── week2-work.md
│   ├── virustotal_check.py
│   ├── virustotal_result.json     
│   ├── shodan_screenshot.png      
│   └── maltego_graph.png        
├── week-03-data-processing/
│   ├── week3-work.md
│   ├── misp_export.py
│   ├── iocs.json      
│   └── simple_url_check.py
└── .gitignore
```

## Progress Log

- **Week 1:** CTI glossary and threat classification completed. See [`week-01-cti-fundamentals/week1-work.md`](./week-01-cti-fundamentals/week1-work.md).
- **Week 2:** OSINT data collection completed (VirusTotal via a real script, Shodan/Maltego via manual lookups) and data-source mapping done. See [`week-02-data-collection/week2-work.md`](./week-02-data-collection/week2-work.md).
- **Week 3:** MISP deployed and a feed imported, IOCs exported via `misp_export.py`, and consumed by `simple_url_check.py` for real-time URL scoring. See [`week-03-data-processing/week3-work.md`](./week-03-data-processing/week3-work.md).

## AI Usage Disclosure

We used Claude (Anthropic) as an AI assistant during this project. The project idea, research, and core logic (including `simple_url_check.py`) are our own; Claude was used to sort and document the weekly work and to help refine and document the URL-checking logic.
