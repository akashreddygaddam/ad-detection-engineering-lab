#!/usr/bin/env python3
"""Small, dependency-free analyzer for the repository's synthetic JSONL events."""
import json
import sys
from pathlib import Path

def analyze(event):
    alerts = []
    eid = event.get("event_id")
    if eid == 4769:
        alerts.append(("REVIEW", "Kerberos service-ticket request (baseline volume and SPN context)"))
    if eid == 4662 and event.get("access_mask") == "0x100":
        alerts.append(("HIGH", "Directory object control-access-like event; verify replication GUID and principal"))
    if eid == 1 and "powershell" in event.get("image", "").lower():
        cmd = event.get("command_line", "").lower()
        if "-enc" in cmd or "-encodedcommand" in cmd:
            alerts.append(("MEDIUM", "PowerShell encoded-command indicator"))
    return alerts

def main(path):
    count = 0
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            count += 1
            for severity, message in analyze(event):
                print(f"[{severity}] line={line_no} host={event.get('host', 'unknown')} user={event.get('user', 'unknown')}: {message}")
    print(f"Processed {count} event(s). All bundled events are synthetic examples.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {Path(sys.argv[0]).name} <events.jsonl>")
    main(sys.argv[1])
