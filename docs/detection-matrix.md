# Active Directory Detection Matrix

## 1. Overview

This document describes the security detection scenarios covered by the Active Directory Detection Engineering Lab.

The detection matrix maps suspicious behaviors to Windows event telemetry, MITRE ATT&CK techniques, detection rules, and investigation requirements.

## 2. Detection Coverage

| ID | Attack Scenario | MITRE ATT&CK | Windows Event | Detection Priority |
|---|---|---|---|---|
| DET-001 | Kerberoasting | T1558.003 | 4769 | High |
| DET-002 | DCSync | T1003.006 | 4662 | Critical |
| DET-003 | Suspicious PowerShell | T1059.001 | Sysmon 1 / 4104 | High |
| DET-004 | Lateral Movement | T1021 | 4624 / 7045 | High |

## 3. Detection Details

### DET-001: Kerberoasting

**MITRE ATT&CK:** T1558.003

**Event ID:** 4769

**Objective:** Identify unusual Kerberos service-ticket request patterns.

Investigation indicators:

- Unusual ticket-request volume.
- Unexpected requesting accounts.
- Unusual service principal names.
- Unexpected source systems.

False-positive considerations:

- Legitimate service accounts.
- Application authentication.
- Administrative operations.

### DET-002: DCSync

**MITRE ATT&CK:** T1003.006

**Event ID:** 4662

**Objective:** Identify suspicious directory replication activity.

Investigation indicators:

- Unexpected replication permissions.
- Unusual requesting accounts.
- Unauthorized source systems.
- Suspicious directory access.

False-positive considerations:

- Domain controller replication.
- Approved identity-management tools.
- Authorized backup systems.

### DET-003: Suspicious PowerShell

**MITRE ATT&CK:** T1059.001

**Event ID:** Sysmon 1 / PowerShell 4104

**Objective:** Identify potentially suspicious PowerShell execution.

Investigation indicators:

- Encoded command-line arguments.
- Unusual parent processes.
- Unexpected script execution.
- Suspicious command sequences.

False-positive considerations:

- Administrative automation.
- Software deployment.
- Authorized PowerShell scripts.

### DET-004: Lateral Movement

**MITRE ATT&CK:** T1021

**Event ID:** 4624 / 7045

**Objective:** Identify suspicious remote access and service creation activity.

Investigation indicators:

- Unexpected remote logons.
- Unusual privileged accounts.
- Suspicious service installation.
- Unusual access between endpoints.

False-positive considerations:

- Remote administration.
- Software deployment.
- System maintenance.

## 4. Detection Validation Status

| Detection | Current Status |
|---|---|
| Kerberoasting | Synthetic example |
| DCSync | Synthetic example |
| PowerShell | Synthetic example |
| Lateral Movement | Investigation guidance |

The detection examples have not yet been validated against a live Active Directory environment.

## 5. Detection Improvement Strategy

Future detection improvements include:

- Event correlation.
- Account and host baselining.
- Time-based detection thresholds.
- False-positive reduction.
- SIEM integration.
- Automated alert generation.

## 6. References

- MITRE ATT&CK: https://attack.mitre.org/
- Sigma: https://sigmahq.io/
- Microsoft Security Auditing: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/

---

**Author:** Akash Reddy

**Project:** Active Directory Detection Engineering Lab
