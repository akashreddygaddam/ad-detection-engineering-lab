# Active Directory Threat Detection Engineering Lab

**Author:** `akashreddygaddam`  
**Status:** Portfolio lab — synthetic telemetry and detection content  
**Focus:** Blue Team · SOC Analysis · Detection Engineering · MITRE ATT&CK

> **Transparency note:** This repository is a reproducible, documentation-led lab scaffold. The included events are synthetic examples; they were not collected from a live Active Directory domain, and no attacks were executed against real systems. Replace the sample evidence with results from your own isolated lab before describing the work as hands-on validation.

## Overview

This project demonstrates how a defender can reason about common Active Directory attack patterns, map them to telemetry, write detections, and document an investigation. It focuses on:

- Kerberoasting — MITRE ATT&CK `T1558.003`
- DCSync — `T1003.006`
- Suspicious PowerShell execution — `T1059.001`
- Remote service / lateral movement indicators — `T1021` (context-dependent)

The repository includes sample Windows Security event records, Sigma-style detection rules, a Python validator for the sample dataset, an investigation playbook, and a detection coverage matrix.

## Repository layout

```text
.
├── README.md
├── docs/
│   ├── architecture.md
│   ├── investigation-playbook.md
│   └── detection-matrix.md
├── detections/
│   ├── sigma/
│   │   ├── kerberoasting_ticket_volume.yml
│   │   ├── dcsync_directory_replication.yml
│   │   └── suspicious_powershell_encoded_command.yml
│   └── README.md
├── data/
│   └── sample_events.jsonl
├── src/
│   └── analyze_events.py
├── tests/
│   └── test_analyze_events.py
├── requirements.txt
└── LICENSE
```

## Quick start

Requires Python 3.10+; no third-party packages are required.

```bash
git clone https://github.com/akashreddygaddam/ad-detection-engineering-lab.git
cd ad-detection-engineering-lab
python src/analyze_events.py data/sample_events.jsonl
python -m unittest discover -s tests -v
```

Expected output includes alerts for the synthetic DCSync-like event, suspicious PowerShell, and Kerberos service-ticket activity. Threshold-based detections are illustrative and must be tuned to the environment.

## Detection logic

| Use case | Primary telemetry | ATT&CK | Investigation focus |
|---|---|---|---|
| Kerberoasting signal | Security Event ID 4769 | T1558.003 | Unusual volume of service-ticket requests, encryption type, requesting account, target SPNs |
| DCSync signal | Security Event ID 4662 | T1003.006 | Replication control-access rights, subject identity, source host, approved DCs |
| Encoded PowerShell | Sysmon Event ID 1 / process command line | T1059.001 | Parent process, user, command-line content, script block logs, host context |
| Remote service activity | Security 4624 / 7045 / Sysmon 1 | T1021 (context-dependent) | Logon type, source host, service creation, admin context, change window |

## Validation

The Python analyzer uses deliberately small, transparent heuristics against the included JSONL examples. It is not a SIEM and does not replace Sigma execution, event normalization, baselining, or analyst review.

```bash
python src/analyze_events.py data/sample_events.jsonl
python -m unittest discover -s tests -v
```

## Safe lab design

Use an isolated virtual network with disposable Windows Server and Windows client VMs. Do not run attack simulations against production or third-party systems. Keep snapshots, use test identities, and ensure the lab has no route to sensitive networks.

See [architecture](docs/architecture.md) and [investigation playbook](docs/investigation-playbook.md).

## Attribution and scope

This is an independently authored learning scaffold inspired by common Active Directory defense and detection-engineering practices. It is not a copy of another repository. If you adapt material, diagrams, code, or text from another project, preserve its license and provide clear attribution.

## Author

GitHub: [@akashreddygaddam](https://github.com/akashreddygaddam)

Add your own lab screenshots, sanitized event exports, detection test results, and lessons learned here after you perform the validation. Do not claim detections were tested against a live environment until you have done so.
