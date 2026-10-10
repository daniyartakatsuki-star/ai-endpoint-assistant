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
├── week-04-kill-chain/
│   ├── week4-work.md
│   └── images/
│       └── kill-chain-mirai-diagram.png
├── week-05-threat-hunting/
│   ├── week5-work.md
│   ├── powershell_rule.py
│   └── images/
│       ├── 01-splunk-home.png
│       ├── 02-sysmon-installed.png
│       ├── 03-sysmon-eventviewer.png
│       ├── 04-index-created.png
│       ├── 05-data-arriving.png
│       ├── 06-raw-sysmon-event.png
│       ├── 07-test-commands.png
│       ├── 08-query1-encoded-powershell.png
│       ├── 09-query2-parent.png
│       └── 10-query3-rare.png
└── .gitignore
```

## Progress Log

- **Week 1:** CTI glossary and threat classification completed. See [`week-01-cti-fundamentals/week1-work.md`](./week-01-cti-fundamentals/week1-work.md).
- **Week 2:** Real dataset (UCI Phishing Websites) explored and correlated, OSINT tools (VirusTotal/Shodan/Maltego) validated and applied to a real flagged domain, data-source mapping produced. See [`week-02-data-collection/week2-work.md`](./week-02-data-collection/week2-work.md).
- **Week 3:** Live IOC feed (URLhaus) filtered, normalized, and deduplicated (14,428 → 729 domains) via `filter_normalize_iocs.py`, consumed by `simple_url_check.py` for real-time URL scoring. See [`week-03-data-processing/week3-work.md`](./week-03-data-processing/week3-work.md).
- **Week 4:** Mirai botnet / 2016 Dyn DDoS attack analyzed through the Lockheed Martin Kill Chain, each stage mapped to a MITRE ATT&CK technique — attack chosen because it matched the dominant threat tags from Week 3's own data. See [`week-04-kill-chain/week4-work.md`](./week-04-kill-chain/week4-work.md).
- **Week 5:** Splunk + Sysmon deployed locally (8,580 real events ingested), hypothesis-driven hunt for suspicious PowerShell activity run as three real SPL queries, with a genuine false-positive finding (VS Code updates) feeding into a detection rule (`powershell_rule.py`, validated 10/10 on real + synthetic cases). See [`week-05-threat-hunting/week5-work.md`](./week-05-threat-hunting/week5-work.md).

## AI Usage Disclosure

We used Claude (Anthropic) as an AI assistant during this project. The project idea, research, dataset analysis, OSINT investigation, attack analysis, Splunk/Sysmon lab setup, and core logic (including `filter_normalize_iocs.py`, `simple_url_check.py`, and `powershell_rule.py`) are our own; Claude was used to sort and document the weekly work and to help refine and document the filtering/normalization, URL-checking, and threat-hunting logic.
