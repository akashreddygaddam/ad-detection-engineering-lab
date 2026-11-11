# Investigation Playbook

## 1. Kerberoasting signal

**Trigger:** A user account requests an unusual number of service tickets (Event ID 4769), especially for multiple SPNs or with unexpected encryption characteristics.

**Triage**
1. Identify the requesting account, client address, target SPNs, and time window.
2. Compare request volume with the account's historical baseline.
3. Confirm whether the source host and activity align with an approved administrative or application workflow.
4. Review adjacent authentication events and endpoint process telemetry.
5. Escalate if activity is anomalous and unexplained; preserve relevant logs.

**False-positive considerations:** Service discovery, application pools, scheduled jobs, and legitimate service-account management can create ticket activity.

## 2. DCSync signal

**Trigger:** Directory replication rights are exercised by a principal or host that is not an approved domain controller or authorized identity-management system.

**Triage**
1. Review Event ID 4662 and the subject SID/account.
2. Inspect access mask and replication-related control-access rights.
3. Validate the source host against the approved domain-controller inventory.
4. Correlate with logons (4624), process creation (4688/Sysmon 1), and recent privilege changes.
5. Treat unexplained replication activity as high priority; follow the organization's incident response process.

**False-positive considerations:** Backup, identity synchronization, and directory recovery products may legitimately use replication permissions. Maintain an explicit allowlist and review it regularly.

## 3. Suspicious PowerShell

**Trigger:** PowerShell launched with encoded or obfuscated command-line arguments, especially from an unusual parent process or user context.

**Triage**
1. Capture full command line, parent process, user, host, and timestamp.
2. Review PowerShell script-block logs if enabled.
3. Determine whether the command is approved automation or interactive administration.
4. Correlate with network, file, and authentication events.
5. Preserve evidence and contain only according to authorized response procedures.

## Evidence template

For each real lab test, record: test ID, date/time (UTC), lab topology, telemetry source, event IDs, query/rule version, expected result, actual result, false-positive notes, screenshots (sanitized), and cleanup confirmation.
