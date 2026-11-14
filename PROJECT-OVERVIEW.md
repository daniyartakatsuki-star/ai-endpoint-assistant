# Project overview

**Local AI-Powered Cybersecurity Assistant for Personal Endpoints** is a ten-week investigation into how a personal computer can explain suspicious links and processes to a non-technical user. The group built two small prototypes and used controlled experiments to test what a warning could reasonably say. A recurring question was how much evidence a single signal provides: a domain match, a PowerShell flag and an archive command each tell a different part of the story.

## From threat intelligence to a URL verdict · Weeks 1–4

The group selected phishing links and suspicious local processes as the two detection priorities. It examined 11,055 observations in the UCI Phishing Websites dataset and compared findings from VirusTotal, Shodan and Maltego. Conflicting findings for a domain illustrated why a URL verdict should explain which indicator contributed to it. [Week 1 scope](week-01-cti-fundamentals/week1-work.md) · [Week 2 collection and evidence](week-02-data-collection/week2-work.md)

For a working prototype, the Week 3 pipeline filtered 14,428 URLhaus records to 1,752 records by status and deduplicated them into 729 domains. The URL checker reads this snapshot, checks for a domain match, and scores features such as unusual length and repeated hyphens. URLhaus supplies malware-distribution indicators; a match signals known malicious hosting but cannot establish that a particular page steals credentials. The Mirai-related tags in the feed also motivated the Week 4 study of the 2016 Dyn attack. [Normalization script](week-03-data-processing/filter_normalize_iocs.py) · [URL checker](week-03-data-processing/simple_url_check.py) · [Mirai case study](week-04-kill-chain/week4-work.md)

## From a PowerShell hunt to an alert · Weeks 5–7

Sysmon supplied Windows process-creation records and Splunk made them searchable. A legitimate VS Code update shared command-line flags with the simulated suspicious activity. The group adjusted its rule so a hidden window alone would not trigger a warning. The implementation also considers encoded commands, execution keywords and the program that launched PowerShell. Its ten checks cover both deliberate test cases and benign examples. [Week 5 hunt](week-05-threat-hunting/week5-work.md) · [Rule and test cases](week-05-threat-hunting/powershell_rule.py)

Week 6 mapped the tested procedures to ATT&CK. Week 7 adapted MITRE CAR-2014-04-003, *PowerShell Execution*, to the lab's Sysmon fields. The broad search returned 92 PowerShell starts. The tuned search returned 12 events, all associated with deliberate test commands in that dataset. The group saved the search as a scheduled Splunk alert. Those counts describe this lab sample; they do not estimate detection accuracy on other endpoints. [Combined Week 6–7 report](week-06-07-attack-car/week6-7-work.md) · [Navigator layer](week-06-07-attack-car/attack-navigator-layer.json)

## Testing an operation outside the PowerShell rule · Weeks 8–9

Week 8 expressed a Lumma-inspired endpoint scenario as CALDERA YAML abilities and an Atomic Red Team plan. The coverage script compared the plan with the existing rule. One collection ability packaged decoy browser and wallet files into a ZIP with PowerShell. Week 9 isolated that archiving step and changed the utility to Windows Cabinet Maker. This gave the group a concrete question: can the assistant identify the archive writer when the child process is a native Windows executable? [Week 8 plan and coverage](week-08-adversary-emulation/week8-work.md) · [Decoy collection ability](week-08-adversary-emulation/emulation-plan/abilities/a4-browser-collection.yml)

The group executed Atomic Red Team T1560.001 test 11 on Windows 11 Enterprise Evaluation VM `win`. Sysmon64 15.22 and Winlogbeat 9.5.6 supplied events to Elasticsearch and Kibana 9.5.6 on Ubuntu 26.04.1 LTS VM `askhat`. Two executions answered different questions:

| Run | Question | Finding |
|---|---|---|
| `W9-20261111-113436` | What did the archive contain? | Makecab exited successfully. Windows reported a 157-byte CAB, and `expand.exe -D` listed `browser-decoy.txt`. |
| `W9-20261111-120716` | What did the SIEM capture? | Sysmon Event ID 1, record 5436, showed `cmd.exe` launching `makecab.exe` with both paths. Searches in Kibana and the local Windows log returned no matching Event ID 11 for the CAB. |

For the second run, an assistant could accurately say, “Command Prompt started Cabinet Maker and supplied browser-decoy.txt as input and browser-decoy.cab as the destination.” Confirming a completed write for that run would require more evidence. The experiment demonstrated a manual Elastic investigation; the earlier automatic alert belonged to the PowerShell work in Splunk. [Week 9 screenshots and method](week-09-atomic-red-team/week9-work.md) · [Selected fields from record 5436](week-09-atomic-red-team/record-5436.json)

## Comparing the evidence with APT41 · Week 10

APT41 provided a documented example of the same archiving utility. The group mapped three published procedures in ATT&CK Navigator and used color to distinguish the one reproduced locally. The comparison identifies a shared behavior. The group was the known operator of the lab endpoint.

| Technique | Evidence and relevance to the assistant |
|---|---|
| T1560.001 · Archive via Utility | Green. Makecab archiving appears in both the published case and the controlled Windows experiment. |
| T1049 · System Network Connections Discovery | Blue. Published APT41 use of `netstat` illustrates why a process warning needs the parent and surrounding activity. |
| T1102.001 · Dead Drop Resolver | Blue. Published APT41 use of legitimate web services illustrates why a domain's reputation alone cannot establish how its content was used. |

The repository's demonstrated components are the URL scorer, the PowerShell rule, the saved lab evidence and the ATT&CK layers. A unified assistant that continuously collects events and generates explanations remains a project goal. [Week 10 analysis and sources](week-10-apt41/week10-work.md) · [Exported Navigator layer](week-10-apt41/apt41-endpoint-evidence.json)
