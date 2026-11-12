# Active Directory Detection Lab – Architecture

## 1. Overview

This document describes the architecture of the Active Directory Detection Engineering Lab.

The project focuses on monitoring Windows environments, identifying suspicious Active Directory activities, analyzing security events, and developing detection mechanisms.

The architecture follows a defensive security monitoring workflow.

## 2. Architecture Diagram

```text
              ACTIVE DIRECTORY ENVIRONMENT
                         |
             +-----------+-----------+
             |                       |
       Windows Server          Windows Client
       Domain Controller       Endpoint System
             |                       |
             +-----------+-----------+
                         |
                  Windows Telemetry
                         |
             +-----------+-----------+
             |                       |
       Security Logs              Sysmon
             |                       |
             +-----------+-----------+
                         |
                  Event Collection
                         |
                Detection Engineering
                         |
             +-----------+-----------+
             |                       |
          Sigma Rules          Python Engine
             |                       |
             +-----------+-----------+
                         |
                   Security Alerts
                         |
                  SOC Investigation
                         |
                  Incident Response
```

## 3. Architecture Components

### Active Directory

Active Directory provides centralized authentication, authorization, and identity management.

### Windows Security Logs

Windows Security logs provide information about authentication, account activity, directory access, and other security-related events.

### Sysmon

Sysmon provides detailed endpoint telemetry, including process creation and command-line information.

### Sigma Detection Rules

Sigma provides a standardized format for describing security detection logic.

### Python Detection Engine

The Python analyzer processes JSONL event data and identifies selected suspicious indicators.

### SOC Investigation

Security analysts investigate generated alerts, correlate related events, identify false positives, and determine appropriate response actions.

## 4. Monitored Security Events

| Event ID | Description | Investigation Purpose |
|---|---|---|
| 4769 | Kerberos service ticket request | Kerberoasting indicators |
| 4662 | Directory object access | DCSync indicators |
| 4624 | Successful logon | Authentication investigation |
| 7045 | Service installation | Service creation investigation |
| Sysmon 1 | Process creation | Suspicious process activity |
| PowerShell 4104 | Script block logging | PowerShell investigation |

## 5. Detection Workflow

The detection workflow consists of:

1. Collect relevant Windows event data.
2. Parse and normalize event information.
3. Apply detection rules.
4. Generate potential security alerts.
5. Investigate suspicious activity.
6. Correlate related events.
7. Document findings.
8. Recommend appropriate remediation.

## 6. Security Considerations

The lab should operate within an isolated virtual network.

Recommended practices:

- Use dedicated test accounts.
- Avoid production credentials.
- Keep experimental systems isolated.
- Use virtual machine snapshots.
- Protect collected security logs.
- Never expose sensitive organizational information.

## 7. Current Implementation Status

The repository currently contains:

- Python event analysis code.
- Synthetic Windows event samples.
- Sigma-style detection examples.
- Architecture documentation.

A fully deployed Active Directory environment, live telemetry collection pipeline, and SIEM integration are future implementation goals unless separately configured and validated.

## 8. Future Improvements

- Deploy a Windows Server domain controller.
- Integrate Windows Event Forwarding.
- Configure Sysmon telemetry collection.
- Integrate Splunk or another SIEM.
- Improve detection correlation.
- Develop automated investigation workflows.

---

**Author:** Akash Reddy

**Project:** Active Directory Detection Engineering Lab
