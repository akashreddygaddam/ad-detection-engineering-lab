import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from analyze_events import analyze_events, load_events


class TestDetectionEngine(unittest.TestCase):

    def test_sample_events_generate_alerts(self):
        events = load_events(ROOT / "data" / "sample_events.jsonl")
        results = analyze_events(events)

        self.assertEqual(len(results), 3)

    def test_kerberoasting_detection(self):
        event = [{
            "EventID": 4769,
            "TargetUserName": "svc_backup",
            "RequestCount": 38
        }]

        results = analyze_events(event)

        self.assertTrue(any("Kerberoasting" in r for r in results))

    def test_dcsync_detection(self):
        event = [{
            "EventID": 4662,
            "SubjectUserName": "user_ops",
            "Properties": "Replication-Get-Changes"
        }]

        results = analyze_events(event)

        self.assertTrue(any("DCSync" in r for r in results))

    def test_powershell_detection(self):
        event = [{
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand TEST",
            "Computer": "WS-TEST01"
        }]

        results = analyze_events(event)

        self.assertTrue(any("PowerShell" in r for r in results))

    def test_normal_event_no_alert(self):
        event = [{
            "EventID": 4769,
            "TargetUserName": "normal_user",
            "RequestCount": 1
        }]

        results = analyze_events(event)

        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
