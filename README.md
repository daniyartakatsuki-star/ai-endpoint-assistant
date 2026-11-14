# Local AI-Powered Cybersecurity Assistant for Personal Endpoints

This Astana IT University project investigates two questions a personal computer user might ask: “Why should I be cautious about this link?” and “What did this program do on my computer?” The repository contains a Python URL checker, a PowerShell detection rule, and ten weeks of threat-intelligence research and endpoint experiments. The two prototypes run independently. Their current decisions come from feed matches and explicit rules.

## Try the prototypes

Run these commands from the repository root with Python 3. Both examples use the standard library and work offline with the committed data.

```sh
(cd week-03-data-processing && python3 simple_url_check.py)
python3 week-05-threat-hunting/powershell_rule.py
```

The URL checker reads its JSON file from the working directory. Running it inside the Week 3 folder loads the 729-domain snapshot and prints example verdicts. The PowerShell rule runs ten cases and prints the reasons for each decision. A legitimate VS Code update is one of the controls.

## Weekly reports

| Week | Report | What to look for |
|---|---|---|
| 1 | [Threat intelligence fundamentals](week-01-cti-fundamentals/week1-work.md) | Why the project focuses on suspicious links and local processes |
| 2 | [Data collection](week-02-data-collection/week2-work.md) | Phishing dataset analysis and cross-checks using OSINT tools |
| 3 | [Indicator processing](week-03-data-processing/week3-work.md) | URLhaus records transformed into the domain list used by the checker |
| 4 | [Cyber Kill Chain](week-04-kill-chain/week4-work.md) | Mirai case study prompted by tags in the feed |
| 5 | [Threat hunting](week-05-threat-hunting/week5-work.md) | Sysmon process records, Splunk searches and a tested PowerShell rule |
| 6–7 | [ATT&CK mapping and MITRE CAR](week-06-07-attack-car/week6-7-work.md) | PowerShell procedures mapped to ATT&CK and a tuned Splunk alert |
| 8 | [Adversary emulation plan](week-08-adversary-emulation/week8-work.md) | CALDERA ability files, an Atomic Red Team plan and detection coverage |
| 9 | [Windows archive investigation](week-09-atomic-red-team/week9-work.md) | A verified 157-byte CAB and the limits of file-event visibility |
| 10 | [APT41 case study](week-10-apt41/week10-work.md) | A Navigator layer comparing lab evidence with three published procedures |

The [project overview](PROJECT-OVERVIEW.md) explains how the experiments connect, what the group verified and which conclusions the evidence supports.

## AI usage

Earlier project documentation credits Claude (Anthropic) with assistance in organizing reports and developing scripts and emulation materials. The group used ChatGPT (OpenAI) for the Week 9 lab guide, troubleshooting and evidence analysis, and for the Week 10 mapping and documentation. Each of those reports ends with a description of the group's work and the assistance it received.
