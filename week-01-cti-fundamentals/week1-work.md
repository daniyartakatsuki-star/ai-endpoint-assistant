# Week 1 — Cyber Threat Intelligence Fundamentals
### Applied to: Local AI-Powered Cybersecurity Assistant for Personal Endpoints

## 1.1 Glossary of Key CTI Terms (scoped to our project)

| Term | Definition (in the context of an endpoint assistant) |
|---|---|
| **IOC (Indicator of Compromise)** | An observable artifact — a malicious URL, file hash, IP, or process name — that suggests a system may be compromised. |
| **IOA (Indicator of Attack)** | A behavioral pattern (e.g., a script spawning `powershell.exe` with an encoded command) that suggests an attack is *in progress*, not just that one happened. |
| **TTP (Tactics, Techniques, Procedures)** | The "how" behind an attacker's actions; we map detected behavior to MITRE ATT&CK TTPs. |
| **Phishing URL** | A link crafted to impersonate a legitimate site to steal credentials or deliver malware; our tool's primary detection target on the browsing side. |
| **Threat Feed** | A continuously updated list of known-bad indicators (URLs, hashes, IPs) published by a provider (e.g., URLhaus, PhishTank, OpenPhish). |
| **OSINT (Open-Source Intelligence)** | Publicly available data used to enrich or verify a suspicious indicator (WHOIS, VirusTotal reputation, Shodan exposure). |
| **False Positive (FP)** | A benign process/URL wrongly flagged as malicious — critical to minimize for non-technical users, who will otherwise distrust or disable the tool. |
| **Heuristic Detection** | Rule-of-thumb / statistical detection (e.g., suspicious URL entropy, lookalike domains) used when no exact IOC match exists — needed for *zero-day* phishing links. |
| **Sysmon / EDR Telemetry** | OS-level logging of process creation, network connections, and file activity — the raw data our local monitor consumes. |
| **Enrichment** | Adding context to a raw indicator (e.g., attaching VirusTotal detection ratio to a URL) before presenting a verdict to the user. |

## 1.2 Threat Classification for Personal Endpoints

| Threat Type | Source | Relevance to Our Tool |
|---|---|---|
| Phishing / credential-harvesting URLs | Email links, SMS (smishing), malicious ads | Core detection target — real-time URL scanning module |
| Malicious/unwanted local processes | Trojans, info-stealers, cryptominers, unsigned autostart entries | Core detection target — process monitor module |
| Living-off-the-land binaries (LOLBins) | Abuse of legitimate tools (`mshta.exe`, `certutil.exe`) | Behavioral detection layer (harder for non-technical users to judge, so the assistant explains the risk in plain language) |
| Ransomware precursors | Rapid mass file renaming/encryption processes | Stretch goal — anomaly detection on file-system activity |
| Malicious browser extensions | Third-party extension stores | Secondary detection surface |
| Supply-chain/updater abuse | Compromised legitimate software updaters | Out of scope for MVP; noted as a limitation |

## 1.3 Week 1 Deliverables Checklist

- [x] Glossary of key CTI terms
- [x] Classification of threat types and their sources
- [x] Recommended reading (ENISA Threat Landscape Report) reviewed — used to confirm phishing and malware as the top threats to individuals, supporting our MVP scope
