# Detection Coverage Matrix

| Scenario | ATT&CK ID | Data source | Included artifact | Validation status |
|---|---|---|---|---|
| Kerberos service-ticket volume anomaly | T1558.003 | Windows Security 4769 | Sigma-style rule + synthetic event | Synthetic parser test only |
| Directory replication rights anomaly | T1003.006 | Windows Security 4662 | Sigma-style rule + synthetic event | Synthetic parser test only |
| Encoded PowerShell command line | T1059.001 | Sysmon 1 / process creation | Sigma-style rule + synthetic event | Synthetic parser test only |
| Remote service / lateral movement | T1021 | 4624, 7045, Sysmon 1 | Playbook guidance | Not implemented in parser |

## Next validation steps

- Deploy the proposed topology in an isolated hypervisor network.
- Configure Windows audit policy and Sysmon.
- Generate benign baseline events first.
- Conduct only authorized, non-destructive simulations in the lab.
- Tune thresholds and allowlists using observed baseline data.
- Validate Sigma rules with the target SIEM's supported backend.
- Replace synthetic status labels with measured results and attach sanitized evidence.
