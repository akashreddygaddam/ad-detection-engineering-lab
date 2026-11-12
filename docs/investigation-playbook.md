# Active Directory Security Investigation Playbook

## 1. Overview

This playbook describes the investigation process for suspicious activities detected within an Active Directory environment.

The objective is to provide a structured approach for SOC analysts to identify suspicious behavior, correlate security events, investigate potential threats, and recommend appropriate incident response actions.

## 2. Investigation Workflow

The investigation process follows these stages:

1. Alert identification.
2. Event verification.
3. Account investigation.
4. Endpoint investigation.
5. Event correlation.
6. Threat assessment.
7. Incident documentation.
8. Response and remediation.

## 3. Scenario 1: Kerberoasting Investigation

**MITRE ATT&CK:** T1558.003

**Primary Event ID:** 4769

### Investigation Steps

- Identify the account requesting Kerberos service tickets.
- Review the requesting computer and source IP.
- Examine the requested service principal names.
- Identify unusual ticket-request patterns.
- Compare activity against normal account behavior.
- Investigate related authentication events.

### Important Questions

- Is the requesting account expected to access these services?
- Is the request volume unusual?
- Is the source computer authorized?
- Are there additional suspicious authentication events?

### Recommended Response

Escalate suspicious activity for identity-security investigation. Review affected service accounts and follow approved credential-protection procedures.

## 4. Scenario 2: DCSync Investigation

**MITRE ATT&CK:** T1003.006

**Primary Event ID:** 4662

### Investigation Steps

- Identify the account performing directory access.
- Review replication-related access rights.
- Identify the source system.
- Verify whether the account is authorized.
- Review related privileged logons.
- Correlate other directory access events.

### Important Questions

- Is the account authorized for directory replication?
- Did the request originate from an approved domain controller?
- Are unexpected replication permissions present?
- Is there evidence of privilege misuse?

### Recommended Response

Escalate unexplained directory replication activity as a high-priority identity-security incident.

## 5. Scenario 3: Suspicious PowerShell Investigation

**MITRE ATT&CK:** T1059.001

**Primary Events:** Sysmon 1 and PowerShell 4104

### Investigation Steps

- Review the PowerShell command line.
- Identify the user and endpoint.
- Examine the parent process.
- Review script-block logging.
- Investigate related process creation events.
- Examine network and file activity.

### Important Questions

- Was the command encoded or obfuscated?
- Was PowerShell launched by an unusual process?
- Is the user authorized to execute the script?
- Is there evidence of suspicious follow-on activity?

### Recommended Response

Preserve relevant endpoint telemetry and escalate suspicious execution for further investigation.

## 6. Scenario 4: Lateral Movement Investigation

**MITRE ATT&CK:** T1021

**Primary Events:** 4624 and 7045

### Investigation Steps

- Identify source and destination systems.
- Review the account used for remote access.
- Examine logon type and timestamps.
- Review newly installed services.
- Correlate process creation events.
- Compare activity with approved administrative operations.

### Important Questions

- Is the remote connection expected?
- Is the account authorized?
- Is the installed service legitimate?
- Are multiple systems involved?

### Recommended Response

Investigate unauthorized remote access and follow the organization's containment and incident-response procedures.

## 7. Investigation Documentation

For every investigation, record:

| Field | Description |
|---|---|
| Alert ID | Detection identifier |
| Timestamp | Time of suspicious activity |
| Username | Account involved |
| Hostname | Affected computer |
| Event ID | Relevant Windows event |
| Source IP | Origin of activity |
| Findings | Investigation observations |
| Severity | Assessed incident severity |
| Status | Open, investigating, or closed |

## 8. Conclusion

A structured investigation process helps security analysts understand suspicious activities, reduce false positives, and respond effectively to potential Active Directory threats.

---

**Author:** Akash Reddy

**Project:** Active Directory Detection Engineering Lab
