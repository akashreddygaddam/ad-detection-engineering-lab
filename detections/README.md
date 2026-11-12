# Sigma Detection Rules

## 1. Overview

This directory contains Sigma-style detection rules developed for identifying suspicious activities within Windows Active Directory environments.

The rules focus on common enterprise security threats and provide a starting point for security monitoring and investigation.

## 2. Detection Rules

| Rule | Detection Scenario | MITRE ATT&CK |
|---|---|---|
| kerberoasting.yml | Kerberos service-ticket activity | T1558.003 |
| dcsync.yml | Directory replication activity | T1003.006 |
| suspicious-powershell.yml | Encoded PowerShell execution | T1059.001 |

## 3. Kerberoasting Detection

**File:** `sigma/kerberoasting.yml`

**Event ID:** 4769

Identifies Kerberos service-ticket events for further investigation.

Investigation considerations:
- Service-ticket request volume.
- Requesting user accounts.
- Service principal names.
- Encryption types.
- Source computer.

## 4. DCSync Detection

**File:** `sigma/dcsync.yml`

**Event ID:** 4662

Identifies directory object access events for investigation.

Investigation considerations:
- Replication-related permissions.
- Requesting account.
- Source computer.
- Authorized domain controllers.
- Directory access patterns.

## 5. Suspicious PowerShell Detection

**File:** `sigma/suspicious-powershell.yml`

**Event Source:** Sysmon Process Creation

Identifies PowerShell processes containing encoded-command indicators.

Investigation considerations:
- Command-line arguments.
- Parent process.
- Executing user.
- Endpoint activity.
- Related PowerShell script-block logs.

## 6. Detection Engineering Workflow

The detection development process follows:

1. Identify suspicious behavior.
2. Identify relevant Windows telemetry.
3. Develop Sigma detection logic.
4. Map detections to MITRE ATT&CK.
5. Review false-positive possibilities.
6. Test against representative event data.
7. Improve detection accuracy.

## 7. Validation

The current rules are experimental examples.

They require additional field-level filtering, testing, and environment-specific tuning before operational deployment.

The Python analyzer and Sigma rules are separate demonstration components; the Python analyzer does not execute Sigma YAML rules.

## 8. Future Improvements

- Add more Active Directory detection rules.
- Improve event correlation.
- Reduce false positives.
- Validate rules using real Windows telemetry.
- Integrate with Splunk or another SIEM.
- Develop automated detection dashboards.

---

**Author:** Akash Reddy

**Project:** Active Directory Detection Engineering Lab
