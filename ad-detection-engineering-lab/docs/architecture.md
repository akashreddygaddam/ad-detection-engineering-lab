# Lab Architecture

## Logical design

```text
              Isolated virtual network (no production route)
   ┌──────────────────────┐       ┌────────────────────────┐
   │ Windows Server       │       │ Windows client         │
   │ Domain Controller   │──────▶│ Domain-joined endpoint │
   │ DNS / AD DS          │       │ Sysmon + audit policy  │
   └──────────────────────┘       └────────────────────────┘
              │                              │
              └──────────────┬───────────────┘
                             ▼
                   ┌──────────────────┐
                   │ SIEM / Collector │
                   │ Wazuh or other   │
                   └──────────────────┘
```

This is a proposed topology, not a claim that the author has deployed it. The synthetic events in `../data/sample_events.jsonl` are standalone examples.

## Suggested telemetry

- Windows Security auditing: 4769, 4662, 4624, 4688 (depending on audit policy).
- Sysmon: Event ID 1 process creation; configure and validate an appropriate Sysmon configuration.
- PowerShell logging: module and script-block logging where appropriate.
- Centralize timestamps and preserve host, user, source IP, and event fields.

## Safety controls

1. Use host-only or internal virtual networking.
2. Use disposable test accounts and snapshots.
3. Keep domain controller credentials out of source control.
4. Do not expose LDAP, SMB, RDP, or WinRM to the public internet.
5. Export only sanitized evidence; remove usernames, internal domains, and IPs before publishing.
