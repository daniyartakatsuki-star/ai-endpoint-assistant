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
│   └── images/
│       ├── feature-correlation-chart.png
│       ├── maltego-graph.png
│       ├── shodan-cyberreliant-general.png
│       ├── shodan-cyberreliant-ports.png
│       ├── shodan-ip-185.15.58.224.jpg
│       ├── virustotal-eicar-hash.jpg
│       ├── virustotal-timestampasa-domain.png
│       └── virustotal-url-testsafebrowsing.jpg
├── week-03-data-processing/
│   ├── week3-work.md
│   ├── filter_normalize_iocs.py
│   ├── iocs_normalized.json
│   └── simple_url_check.py
└── .gitignore
```

## Progress Log

- **Week 1:** CTI glossary and threat classification completed. See [`week-01-cti-fundamentals/week1-work.md`](./week-01-cti-fundamentals/week1-work.md).
- **Week 2:** Real dataset (UCI Phishing Websites) explored and correlated, OSINT tools (VirusTotal/Shodan/Maltego) validated and applied to a real flagged domain, data-source mapping produced. See [`week-02-data-collection/week2-work.md`](./week-02-data-collection/week2-work.md).
- **Week 3:** Live IOC feed (URLhaus) filtered, normalized, and deduplicated (14,428 → 729 domains) via `filter_normalize_iocs.py`, consumed by `simple_url_check.py` for real-time URL scoring. See [`week-03-data-processing/week3-work.md`](./week-03-data-processing/week3-work.md).

## AI Usage Disclosure

We used Claude (Anthropic) as an AI assistant during this project. The project idea, research, dataset analysis, OSINT investigation, and core logic (including `filter_normalize_iocs.py` and `simple_url_check.py`) are our own; Claude was used to sort and document the weekly work and to help refine and document the filtering/normalization and URL-checking logic.
