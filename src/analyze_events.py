import json
import argparse
from pathlib import Path


def load_events(file_path):

    events = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            if line.strip():

                events.append(json.loads(line))

    return events


def detect_kerberoasting(event):

    if event.get("EventID") == 4769:

        request_count = int(event.get("RequestCount", 0))

        if request_count >= 20:

            return (
                f"Possible Kerberoasting activity detected! "
                f"Account: {event.get('TargetUserName')}"
            )

    return None


def detect_dcsync(event):

    if event.get("EventID") == 4662:

        properties = str(event.get("Properties", "")).lower()

        if "replication" in properties:

            return (
                f"Possible DCSync activity detected! "
                f"Account: {event.get('SubjectUserName')}"
            )

    return None


def detect_suspicious_powershell(event):

    if event.get("EventID") == 1:

        image = str(event.get("Image", "")).lower()

        command = str(event.get("CommandLine", "")).lower()

        if "powershell.exe" in image or "pwsh.exe" in image:

            if "-enc " in command or "-encodedcommand " in command:

                return (
                    f"Suspicious PowerShell activity detected! "
                    f"Host: {event.get('Computer')}"
                )

    return None


def analyze_events(events):

    detections = []

    for event in events:

        checks = [
            detect_kerberoasting,
            detect_dcsync,
            detect_suspicious_powershell
        ]

        for check in checks:

            result = check(event)

            if result:

                detections.append(result)

    return detections


def main():

    parser = argparse.ArgumentParser(
        description="Active Directory Detection Engineering Lab"
    )

    parser.add_argument(
        "input",
        help="Path to JSONL event file"
    )

    args = parser.parse_args()

    events = load_events(Path(args.input))

    print("\n======================================")
    print(" ACTIVE DIRECTORY DETECTION ENGINE")
    print("======================================")

    print(f"\nTotal Events Analyzed: {len(events)}")

    detections = analyze_events(events)

    print("\nDetection Results")
    print("--------------------------------------")

    if detections:

        for detection in detections:

            print("[ALERT]", detection)

    else:

        print("No suspicious activity detected.")

    print("\nAnalysis Completed.")


if __name__ == "__main__":

    main()
